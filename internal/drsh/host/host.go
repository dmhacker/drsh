package host

import (
	"context"
	"fmt"
	"sync"
	"time"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"
)

type outgoingMessage struct {
	recipient      string
	sessionMessage *drshproto.SessionMessage
	publicMessage  *drshproto.PublicMessage
	killFlag       bool
}

// RedisHost is a wrapper around Redis that only uses Redis as a message broker.
// It tries to hide the full functionality of Redis by only exposing functions
// related to sending and receiving drsh messages.
type RedisHost struct {
	Hostname                string                        // The name of this host (e.g. what channel this host is listening on)
	Logger                  *zap.SugaredLogger            // The logger attached to this host
	Encryption              drshutil.EncryptionModule     // Responsible for performing key exchange, symmetric encryption, etc.
	IncomingPublicMessages  chan drshproto.PublicMessage  // If not in a session, then any incoming messages can be read through this channel
	IncomingSessionMessages chan drshproto.SessionMessage // If in a session, then any incoming messages can be read through this channel
	outgoingMessages        chan outgoingMessage          // Any messages sent through this channel are sent to other Redis hosts
	rclient                 *redis.Client                 // The Redis client attached to this host
	rpubsub                 *redis.PubSub                 // The Redis channel the client is listening on
	readyMtx                sync.Mutex                    // Used to signal that this host is correctly sending & receiving Redis messages
	readyFlag               bool                          // Used to signal that this host is correctly sending & receiving Redis messages
	readyCnd                *sync.Cond                    // Used to signal that this host is correctly sending & receiving Redis messages
	childFlag               bool                          // Is true if this host is a child of another host (borrowing resources)
	openFlag                drshutil.AtomicBoolean        // Is true if this host is still connected to Redis
	sessionFlag             drshutil.AtomicBoolean        // Is true if the host is currently involved in an encrypted session
}

var ctx = context.Background()

// NewRedisHost creates a new Redis host. The host will connect as `hostname` to the Redis
// node at `uri` and will subscribe to the channel "drsh:`hostname`". Although
// the host is connected, it is not actively processing messages at this point.
func NewRedisHost(hostname string, uri string, logger *zap.SugaredLogger) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	host := RedisHost{
		Hostname:                hostname,
		Logger:                  logger,
		Encryption:              drshutil.NewEncryptionModule(),
		IncomingPublicMessages:  make(chan drshproto.PublicMessage, 10),
		IncomingSessionMessages: make(chan drshproto.SessionMessage, 10),
		outgoingMessages:        make(chan outgoingMessage, 10),
		rclient:                 redis.NewClient(opt),
		readyFlag:               false,
		childFlag:               false,
		openFlag:                drshutil.NewAtomicBoolean(true),
		sessionFlag:             drshutil.NewAtomicBoolean(false),
	}
	host.readyCnd = sync.NewCond(&host.readyMtx)
	err = host.rclient.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if host.IsListening(host.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	host.rpubsub = host.rclient.Subscribe(ctx, "drsh:"+host.Hostname)
	return &host, nil
}

// NewChildRedisHost is a niche method that is used by a server session to create a host
// using the parent server's existing connection. This host shares the parent's connection
// resources, but doesn't own them. This is mainly used by the server for spawning new sessions.
func NewInheritedRedisHost(hostname string, parent *RedisHost) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	child := RedisHost{
		Hostname:                hostname,
		Logger:                  parent.Logger,
		Encryption:              drshutil.NewEncryptionModule(),
		IncomingPublicMessages:  make(chan drshproto.PublicMessage, 10),
		IncomingSessionMessages: make(chan drshproto.SessionMessage, 10),
		outgoingMessages:        make(chan outgoingMessage, 10),
		rclient:                 parent.rclient,
		readyFlag:               false,
		childFlag:               false,
		openFlag:                drshutil.NewAtomicBoolean(true),
		sessionFlag:             drshutil.NewAtomicBoolean(false),
	}
	child.readyCnd = sync.NewCond(&child.readyMtx)
	err := child.rclient.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if child.IsListening(child.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	child.rpubsub = child.rclient.Subscribe(ctx, "drsh:"+child.Hostname)
	return &child, nil
}

// Returns whether or not the host is listening on the network.
// The host is considered open from creation until Close() is called on it.
func (host *RedisHost) IsOpen() bool {
	return host.openFlag.Get()
}

// Returns whether or not the host is involved in a session.
func (host *RedisHost) IsSession() bool {
	return host.sessionFlag.Get()
}

// Sets the status of host as potentially being involved in a session.
func (host *RedisHost) SetSession(session bool) {
	host.sessionFlag.Set(session)
}

// Returns whether or not a host with this name is listening on the network.
// A listening host means that the host is subscribed to its channel. It is a necessary
// but not sufficient condition for host communication, as the other host must be
// responsive too.
func (host *RedisHost) IsListening(hostname string) bool {
	channels, err := host.rclient.PubSubChannels(ctx, "drsh:"+hostname).Result()
	return err == nil && len(channels) > 0
}

// A thread-safe way to send public messages to another host on the network.
// If the host is in session mode, then it should only be communicating in a secure manner
// via encrypted session messages, so public messages cannot be sent in parallel.
func (host *RedisHost) SendPublicMessage(recipient string, msg drshproto.PublicMessage) {
	// If this is triggered, then the protocol has failed in some way
	if host.IsSession() {
		host.Logger.Panicf("Cannot send a public message in session mode: %v", msg)
		return
	}
	host.outgoingMessages <- outgoingMessage{
		recipient:      recipient,
		publicMessage:  &msg,
		sessionMessage: nil,
		killFlag:       false,
	}
}

// If the host is in session mode, then the host can send encrypted session messages
// to users in the session. Session mode is a requirement, because it implies that
// a mutual encryption key has been established via a handshake.
func (host *RedisHost) SendSessionMessage(recipient string, msg drshproto.SessionMessage) {
	// If this is triggered, then the protocol has failed in some way
	if !host.IsSession() {
		host.Logger.Panicf("Cannot send a session message in public mode: %v", msg)
		return
	}
	host.outgoingMessages <- outgoingMessage{
		recipient:      recipient,
		publicMessage:  nil,
		sessionMessage: &msg,
		killFlag:       false,
	}
}

func (host *RedisHost) startMessageSender() {
	for omsg := range host.outgoingMessages {
		var payload []byte
		var err error
		if omsg.killFlag {
			break
		} else if omsg.sessionMessage != nil {
			payload, err = proto.Marshal(omsg.sessionMessage)
			if err != nil {
				host.Logger.Warnf("Failed to marshal message: %s", err)
				continue
			}
			// Session messages have an extra layer of encryption after marshalling
			payload, err = host.Encryption.Encrypt(payload)
			if err != nil {
				host.Logger.Warnf("Failed to marshal message: %s", err)
				continue
			}
		} else if omsg.publicMessage != nil {
			payload, err = proto.Marshal(omsg.publicMessage)
			if err != nil {
				host.Logger.Warnf("Failed to marshal message: %s", err)
				continue
			}
		}
		err = host.rclient.Publish(ctx, "drsh:"+omsg.recipient, payload).Err()
		if err != nil {
			// If the host is closed, this is likely a normal shutdown event
			if host.IsOpen() {
				host.Logger.Warnf("Failed to publish message: %s", err)
				continue
			} else {
				break
			}
		}
	}
}

func (host *RedisHost) startMessageReceiver() {
	for {
		rmsg, err := host.rpubsub.ReceiveMessage(ctx)
		if err != nil {
			// If the host is closed, this is likely a normal shutdown event
			if host.IsOpen() {
				host.Logger.Warnf("Failed to receive message: %s", err)
				continue
			} else {
				break
			}
		}
		payload := []byte(rmsg.Payload)
		// If the host in session mode, assume all incoming messages are encrypted session messages.
		// Otherwise, assume all incoming messages are unencrypted public messages.
		if host.IsSession() {
			payload, err = host.Encryption.Decrypt(payload)
			if err != nil {
				host.Logger.Warnf("Failed to decrypt message: %s", err)
				continue
			}
			msg := drshproto.SessionMessage{}
			err = proto.Unmarshal(payload, &msg)
			if err != nil {
				host.Logger.Warnf("Failed to unmarshal message: %s", err)
				continue
			}
			if msg.GetType() == drshproto.SessionMessage_READY && msg.GetSender() == host.Hostname {
				host.readyMtx.Lock()
				host.readyFlag = true
				host.readyCnd.Signal()
				host.readyMtx.Unlock()
				continue
			}
			host.IncomingSessionMessages <- msg
		} else {
			msg := drshproto.PublicMessage{}
			err = proto.Unmarshal(payload, &msg)
			if err != nil {
				host.Logger.Warnf("Failed to unmarshal message: %s", err)
				continue
			}
			if msg.GetType() == drshproto.PublicMessage_READY && msg.GetSender() == host.Hostname {
				host.readyMtx.Lock()
				host.readyFlag = true
				host.readyCnd.Signal()
				host.readyMtx.Unlock()
				continue
			}
			host.IncomingPublicMessages <- msg
		}
	}
}

func (host *RedisHost) waitUntilReady() {
	// The ready check works by spawning a goroutine to send READY packets
	// through Redis back to itself. As soon as one of these packets is
	// fully processed, this indicates that the pipeline is functional
	go (func() {
		for {
			host.readyMtx.Lock()
			ready := host.readyFlag
			host.readyMtx.Unlock()
			if ready {
				break
			}
			if host.IsSession() {
				host.SendSessionMessage(host.Hostname, drshproto.SessionMessage{
					Type:   drshproto.SessionMessage_READY,
					Sender: host.Hostname,
				})
			} else {
				host.SendPublicMessage(host.Hostname, drshproto.PublicMessage{
					Type:   drshproto.PublicMessage_READY,
					Sender: host.Hostname,
				})
			}
			time.Sleep(500 * time.Millisecond)
		}
	})()
	host.readyMtx.Lock()
	defer host.readyMtx.Unlock()
	for !host.readyFlag {
		host.readyCnd.Wait()
	}
}

// Starts the host. Upon completion of this function, the host
// can both send and receive messages through its Redis node. It is actively
// listening for incoming messages from counterparties and sending outgoing
// messages from its own queue.
func (host *RedisHost) Start() {
	go host.startMessageSender()
	go host.startMessageReceiver()
	host.waitUntilReady()
}

// Closes the host. The connection to Redis is dropped and the
// host can no longer send messages. If the host was created using NewInheritedRedisHost
// (e.g. a server spawns a session), then the underlying connection is left intact.
func (host *RedisHost) Close() {
	// Indicate that we are closed
	host.openFlag.Set(false)
	// Kills the message sender
	host.outgoingMessages <- outgoingMessage{
		killFlag: true,
	}
	// Kills the message receiver
	host.rpubsub.Close()
	// Disposes of the Redis connection
	if !host.childFlag {
		host.rclient.Close()
	}
}
