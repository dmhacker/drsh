package drshhost

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/drshproto"
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

func InheritRedisHost(hostname string, rdb *redis.Client, logger *zap.SugaredLogger, handler func(drshproto.Message)) (*RedisHost, error) {
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

func (host *RedisHost) IsOpen() bool {
	host.OpenMtx.Lock()
	defer host.OpenMtx.Unlock()
	return host.OpenState
}

func (host *RedisHost) IsListening(hostname string) bool {
	channels, err := host.Rdb.PubSubChannels(ctx, "drsh:"+hostname).Result()
	return err == nil && len(channels) > 0
}

func (host *RedisHost) IsEncryptionEnabled() bool {
	host.KXMtx.Lock()
	defer host.KXMtx.Unlock()
	return host.KXEnabled
}

func (host *RedisHost) SetEncryptionEnabled(enabled bool) {
	host.KXMtx.Lock()
	defer host.KXMtx.Unlock()
	host.KXEnabled = enabled
}

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

func (host *RedisHost) FreePrivateKeys() {
	host.KXGroup = nil
	host.KXPrivateKey = nil
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

func (host *RedisHost) SendMessage(recipient string, msg drshproto.Message) {
	host.Outgoing <- outgoingMessage{
		Recipient:     recipient,
		Message:       msg,
		ShouldEncrypt: host.IsEncryptionEnabled(),
		ShouldKill:    false,
	}
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

func (host *RedisHost) Start() {
	go host.startMessageSender()
	go host.startMessageReceiver()
	host.waitUntilReady()
}

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
