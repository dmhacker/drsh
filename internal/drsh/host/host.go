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

// A wrapper around Redis that only uses Redis as a message broker.
// It tries to hide the full functionality of Redis by only exposing functions
// related to sending and receiving drsh messages.
type RedisHost struct {
	Hostname         string                    // The name of this host (e.g. what channel this host is listening on)
	Logger           *zap.SugaredLogger        // The logger attached to this host
	Encryption       drshutil.EncryptionModule // Responsible for performing key exchange, symmetric encryption, etc.
	incomingMessages chan drshproto.Message    // Any incoming messages can be read through this channel
	outgoingMessages chan outgoingMessage      // Any messages sent through this channel are sent to other Redis hosts
	rclient          *redis.Client             // The Redis client attached to this host
	rpubsub          *redis.PubSub             // The Redis channel the client is listening on
	readyMtx         sync.Mutex                // Used to signal that this host is correctly sending & receiving Redis messages
	readyFlag        bool                      // Used to signal that this host is correctly sending & receiving Redis messages
	readyCnd         *sync.Cond                // Used to signal that this host is correctly sending & receiving Redis messages
	childFlag        bool                      // Is true if this host is a child of another host (borrowing resources)
	openFlag         drshutil.AtomicBoolean    // Is true if this host is still connected to Redis
	sessionFlag      drshutil.AtomicBoolean    // Is true if the host is currently involved in an encrypted session
}

var ctx = context.Background()

// Creates a new Redis host. The host will connect as `hostname` to the Redis
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
		Hostname:         hostname,
		Logger:           logger,
		Encryption:       drshutil.NewEncryptionModule(),
		incomingMessages: make(chan drshproto.Message, 10),
		outgoingMessages: make(chan outgoingMessage, 10),
		rclient:          redis.NewClient(opt),
		readyFlag:        false,
		childFlag:        false,
		openFlag:         drshutil.NewAtomicBoolean(true),
		sessionFlag:      drshutil.NewAtomicBoolean(false),
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

// A niche method that is used by a server session to create a host
// using the parent server's existing connection. This host shares the parent's connection
// resources, but doesn't own them. This is mainly used by the server for spawning new sessions.
func NewChildRedisHost(hostname string, parent *RedisHost) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	child := RedisHost{
		Hostname:         hostname,
		Logger:           parent.Logger,
		Encryption:       drshutil.NewEncryptionModule(),
		incomingMessages: make(chan drshproto.Message, 10),
		outgoingMessages: make(chan outgoingMessage, 10),
		rclient:          parent.rclient,
		readyFlag:        false,
		childFlag:        true,
		openFlag:         drshutil.NewAtomicBoolean(true),
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

// Returns whether or not a host with this name is listening on the network.
// A listening host means that the host is subscribed to its channel. It is a necessary
// but not sufficient condition for host communication, as the other host must be
// responsive too.
func (host *RedisHost) IsListening(hostname string) bool {
	channels, err := host.rclient.PubSubChannels(ctx, "drsh:"+hostname).Result()
	return err == nil && len(channels) > 0
}

// A thread-safe way to send public messages to another host on the network.
func (host *RedisHost) SendPublicMessage(recipient string, msg drshproto.PublicMessage) {
	host.outgoingMessages <- outgoingMessage{
		recipient:      recipient,
		publicMessage:  &msg,
		sessionMessage: nil,
		killFlag:       false,
	}
}

// A thread-safe way to send session messages to another host on the network.
// The session messages will be encrypted with a mutually derived key.
func (host *RedisHost) SendSessionMessage(recipient string, msg drshproto.SessionMessage) {
	host.outgoingMessages <- outgoingMessage{
		recipient:      recipient,
		publicMessage:  nil,
		sessionMessage: &msg,
		killFlag:       false,
	}
}

// Attempts to extract the public component of the message if it exists.
func (host *RedisHost) GetPublicMessage(mmsg drshproto.Message) *drshproto.PublicMessage {
	switch mmsg.Wrapper.(type) {
	case *drshproto.Message_PublicMessage:
		return mmsg.GetPublicMessage()
	}
	return nil
}

// Attempts to extract the session component of the message if it exists.
func (host *RedisHost) GetSessionMessage(mmsg drshproto.Message) (*drshproto.SessionMessage, error) {
	switch mmsg.Wrapper.(type) {
	case *drshproto.Message_EncryptedSessionMessage:
		emsg := mmsg.GetEncryptedSessionMessage()
		payload, err := host.Encryption.Decrypt(emsg)
		if err != nil {
			return nil, err
		}
		msg := drshproto.SessionMessage{}
		err = proto.Unmarshal(payload, &msg)
		if err != nil {
			return nil, err
		}
		return &msg, nil
	}
	return nil, nil
}

func (host *RedisHost) startMessageSender() {
	for omsg := range host.outgoingMessages {
		if omsg.killFlag {
			break
		}
		var wmsg drshproto.Message
		if omsg.publicMessage != nil {
			wmsg.Wrapper = &drshproto.Message_PublicMessage{omsg.publicMessage}
		} else if omsg.sessionMessage != nil {
			payload, err := proto.Marshal(omsg.sessionMessage)
			if err != nil {
				host.Logger.Warnf("Error sending message: %s", err)
				continue
			}
			// Session messages have an extra layer of encryption after marshalling
			emsg, err := host.Encryption.Encrypt(payload)
			if err != nil {
				host.Logger.Warnf("Error sending message: %s", err)
				continue
			}
			wmsg.Wrapper = &drshproto.Message_EncryptedSessionMessage{emsg}
		}
		payload, err := proto.Marshal(&wmsg)
		if err != nil {
			host.Logger.Warnf("Error sending message: %s", err)
			continue
		}
		err = host.rclient.Publish(ctx, "drsh:"+omsg.recipient, payload).Err()
		if err != nil {
			if host.IsOpen() {
				host.Logger.Warnf("Error sending message: %s", err)
				continue
			} else {
				// If the host is closed, this is likely a normal shutdown event
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
		wmsg := drshproto.Message{}
		err = proto.Unmarshal(payload, &wmsg)
		if err != nil {
			host.Logger.Warnf("Failed to unmarshal message: %s", err)
			continue
		}
		pmsg := host.GetPublicMessage(wmsg)
		if pmsg != nil && pmsg.GetType() == drshproto.PublicMessage_READY && pmsg.GetSender() == host.Hostname {
			host.readyMtx.Lock()
			host.readyFlag = true
			host.readyCnd.Signal()
			host.readyMtx.Unlock()
			continue
		}
		// TODO: Session message extraction must currently be handled by the reader of the incoming channel.
		// In particular, for clients, session setup may not be finished before new session messages are received.
		// If session message extraction were performed here, it could introduce race conditions.
		// A more permanent fix would be to split pipelines but delay messages in the session pipeline if
		// session setup has not concluded yet.
		host.incomingMessages <- wmsg
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
			host.SendPublicMessage(host.Hostname, drshproto.PublicMessage{
				Type:   drshproto.PublicMessage_READY,
				Sender: host.Hostname,
			})
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
	// Closes all channels
	close(host.outgoingMessages)
	close(host.incomingMessages)
}
