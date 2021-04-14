package host

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type outgoingMessage struct {
	Recipient     string
	Message       drshproto.Message
	ShouldEncrypt bool
	ShouldKill    bool
}

// RedisHost is a wrapper around Redis that only uses Redis as a message broker.
// It tries to hide the full functionality of Redis by only exposing functions
// related to sending and receiving drsh messages.
type RedisHost struct {
	Hostname     string
	Rdb          *redis.Client
	Rps          *redis.PubSub
	Inherited    bool
	Outgoing     chan outgoingMessage
	Logger       *zap.SugaredLogger
	Handler      func(drshproto.Message)
	ReadyMtx     sync.Mutex
	ReadyFlag    bool
	ReadyCnd     *sync.Cond
	KXMtx        sync.Mutex
	KXGroup      *dhkx.DHGroup
	KXPrivateKey *dhkx.DHKey
	KXCipher     cipher.AEAD
	KXEnabled    bool
	OpenMtx      sync.Mutex
	OpenState    bool
}

var ctx = context.Background()

// NewRedisHost creates a new Redis host. The host will connect as `hostname` to the Redis
// node at `uri` and will subscribe to the channel "drsh:`hostname`". Although
// the host is connected, it is not actively processing messages at this point.
func NewRedisHost(hostname string, uri string, logger *zap.SugaredLogger, handler func(drshproto.Message)) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	host := RedisHost{
		Hostname:  hostname,
		Rdb:       redis.NewClient(opt),
		Inherited: false,
		Outgoing:  make(chan outgoingMessage, 10),
		Logger:    logger,
		Handler:   handler,
		ReadyFlag: false,
		KXEnabled: false,
		OpenState: true,
	}
	host.ReadyCnd = sync.NewCond(&host.ReadyMtx)
	err = host.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if host.IsListening(host.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	host.Rps = host.Rdb.Subscribe(ctx, "drsh:"+host.Hostname)
	return &host, nil
}

// NewInheritedRedisHost is a niche method that is used by a server session to create a host
// using the parent server's existing connection. Do not use otherwise.
func NewInheritedRedisHost(hostname string, rdb *redis.Client, logger *zap.SugaredLogger, handler func(drshproto.Message)) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	host := RedisHost{
		Hostname:  hostname,
		Rdb:       rdb,
		Inherited: true,
		Outgoing:  make(chan outgoingMessage, 10),
		Logger:    logger,
		Handler:   handler,
		ReadyFlag: false,
		KXEnabled: false,
		OpenState: true,
	}
	host.ReadyCnd = sync.NewCond(&host.ReadyMtx)
	err := host.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if host.IsListening(host.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	host.Rps = host.Rdb.Subscribe(ctx, "drsh:"+host.Hostname)
	return &host, nil
}

// IsOpen returns whether or not the host is listening on the network.
// The host is considered open from creation until Close() is called on it.
func (host *RedisHost) IsOpen() bool {
	host.OpenMtx.Lock()
	defer host.OpenMtx.Unlock()
	return host.OpenState
}

// IsListening returns whether or not a host with this name is listening on the network.
// A listening host means that the host is subscribed to its channel. It is a necessary
// but not sufficient condition for host communication, as the other host must be
// responsive too.
func (host *RedisHost) IsListening(hostname string) bool {
	channels, err := host.Rdb.PubSubChannels(ctx, "drsh:"+hostname).Result()
	return err == nil && len(channels) > 0
}

// IsEncryptionEnabled should return true if encryption has been enabled, preferrably after
// key exchange has been performed.
func (host *RedisHost) IsEncryptionEnabled() bool {
	host.KXMtx.Lock()
	defer host.KXMtx.Unlock()
	return host.KXEnabled
}

// SetEncryptionEnabled is set by the key exchange protocol upon completion.
func (host *RedisHost) SetEncryptionEnabled(enabled bool) {
	host.KXMtx.Lock()
	defer host.KXMtx.Unlock()
	host.KXEnabled = enabled
}

// PrepareKeyExchange creates the host's keypair needed for key exchange.
func (host *RedisHost) PrepareKeyExchange() error {
	grp, err := dhkx.GetGroup(0)
	if err != nil {
		return err
	}
	priv, err := grp.GeneratePrivateKey(nil)
	if err != nil {
		return err
	}
	host.KXGroup = grp
	host.KXPrivateKey = priv
	return nil
}

// CompleteKeyExchange marks the completion of the key exchange protocol.
// When the key exchange handshake is performed, the other host's public
// key is mixed with the keypair generated via PrepareKeyExchange. This
// creates a shared secret, passed through a KDF and given to a cipher.
func (host *RedisHost) CompleteKeyExchange(key []byte) error {
	pub := dhkx.NewPublicKey(key)
	secret, err := host.KXGroup.ComputeKey(pub, host.KXPrivateKey)
	if err != nil {
		return err
	}
	deriv := hkdf.New(sha256.New, secret.Bytes(), nil, nil)
	skey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(deriv, skey); err != nil {
		return err
	}
	host.KXCipher, err = chacha20poly1305.New(skey)
	if err != nil {
		return err
	}
	return nil
}

// FreePrivateKeys removes references to the keypair, allowing for it to
// be garbage collected.
func (host *RedisHost) FreePrivateKeys() {
	host.KXGroup = nil
	host.KXPrivateKey = nil
}

// SendMessage sends a message to a specific host on the network.
// Encryption is handled by the host if key exchange has been performed.
// It should be completely thread-safe.
func (host *RedisHost) SendMessage(recipient string, msg drshproto.Message) {
	host.Outgoing <- outgoingMessage{
		Recipient:     recipient,
		Message:       msg,
		ShouldEncrypt: host.IsEncryptionEnabled(),
		ShouldKill:    false,
	}
}

func (host *RedisHost) encryptMessage(data []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := host.KXCipher.Seal(nil, nonce, data, nil)
	emsg := drshproto.EncryptedMessage{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}
	encrypted, err := proto.Marshal(&emsg)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (host *RedisHost) decryptMessage(data []byte) ([]byte, error) {
	emsg := drshproto.EncryptedMessage{}
	err := proto.Unmarshal([]byte(data), &emsg)
	if err != nil {
		return nil, err
	}
	plaintext, err := host.KXCipher.Open(nil, emsg.Nonce, emsg.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (host *RedisHost) startMessageSender() {
	for omsg := range host.Outgoing {
		if omsg.ShouldKill {
			break
		}
		raw, err := proto.Marshal(&omsg.Message)
		if err != nil {
			host.Logger.Warnf("Failed to marshal message: %s", err)
			continue
		}
		encrypted := raw
		if omsg.ShouldEncrypt {
			encrypted, err = host.encryptMessage(raw)
			if err != nil {
				host.Logger.Warnf("Failed to encrypt message: %s", err)
				continue
			}
		}
		err = host.Rdb.Publish(ctx, "drsh:"+omsg.Recipient, encrypted).Err()
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
		rmsg, err := host.Rps.ReceiveMessage(ctx)
		if err != nil {
			// If the host is closed, this is likely a normal shutdown event
			if host.IsOpen() {
				host.Logger.Warnf("Failed to receive message: %s", err)
				continue
			} else {
				break
			}
		}
		raw := []byte(rmsg.Payload)
		if host.IsEncryptionEnabled() {
			raw, err = host.decryptMessage(raw)
			if err != nil {
				host.Logger.Warnf("Failed to decrypt message: %s", err)
				continue
			}
		}
		msg := drshproto.Message{}
		err = proto.Unmarshal(raw, &msg)
		if err != nil {
			host.Logger.Warnf("Failed to unmarshal message: %s", err)
			continue
		}
		sender := msg.GetSender()
		if msg.GetType() == drshproto.Message_READY && sender == host.Hostname {
			host.ReadyMtx.Lock()
			host.ReadyFlag = true
			host.ReadyCnd.Signal()
			host.ReadyMtx.Unlock()
			continue
		}
		host.Handler(msg)
	}
}

func (host *RedisHost) waitUntilReady() {
	// The ready check works by spawning a goroutine to send READY packets
	// through Redis back to itself. As soon as one of these packets is
	// fully processed, this indicates that the pipeline is functional
	go (func() {
		for {
			host.ReadyMtx.Lock()
			ready := host.ReadyFlag
			host.ReadyMtx.Unlock()
			if ready {
				break
			}
			host.SendMessage(host.Hostname, drshproto.Message{
				Type:   drshproto.Message_READY,
				Sender: host.Hostname,
			})
			time.Sleep(500 * time.Millisecond)
		}
	})()
	host.ReadyMtx.Lock()
	defer host.ReadyMtx.Unlock()
	for !host.ReadyFlag {
		host.ReadyCnd.Wait()
	}
}

// Start starts the host. Upon completion of this function, the host
// can both send and receive messages through its Redis node. It is actively
// listening for incoming messages from counterparties and sending outgoing
// messages from its own queue.
func (host *RedisHost) Start() {
	go host.startMessageSender()
	go host.startMessageReceiver()
	host.waitUntilReady()
}

// Close closes the host. The connection to Redis is dropped and the
// host can no longer send messages. If the host was created using NewInheritedRedisHost
// (e.g. a server spawns a session), then the underlying connection is left intact.
func (host *RedisHost) Close() {
	// Indicate that we are closed
	host.OpenMtx.Lock()
	host.OpenState = false
	host.OpenMtx.Unlock()
	// Kills the packet handler
	host.Outgoing <- outgoingMessage{
		ShouldKill: true,
	}
	// Kills the packet receiver
	host.Rps.Close()
	// Disposes of the Redis connection
	if !host.Inherited {
		host.Rdb.Close()
	}
}
