package drshhost

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/drshcomms"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
)

type OutgoingPacket struct {
	Recipient     string
	Packet        drshcomms.Packet
	ShouldEncrypt bool
	ShouldKill    bool
}

type RedisHost struct {
	Hostname     string
	Rdb          *redis.Client
	Rps          *redis.PubSub
	Inherited    bool
	Outgoing     chan OutgoingPacket
	Logger       *zap.SugaredLogger
	Handler      func(drshcomms.Packet)
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

func NewRedisHost(hostname string, uri string, logger *zap.SugaredLogger, handler func(drshcomms.Packet)) (*RedisHost, error) {
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
		Outgoing:  make(chan OutgoingPacket, 10),
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

func InheritRedisHost(hostname string, rdb *redis.Client, logger *zap.SugaredLogger, handler func(drshcomms.Packet)) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	host := RedisHost{
		Hostname:  hostname,
		Rdb:       rdb,
		Inherited: true,
		Outgoing:  make(chan OutgoingPacket, 10),
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

func (host *RedisHost) SendPacket(recipient string, pckt drshcomms.Packet) {
	host.Outgoing <- OutgoingPacket{
		Recipient:     recipient,
		Packet:        pckt,
		ShouldEncrypt: host.IsEncryptionEnabled(),
		ShouldKill:    false,
	}
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
	skey, err := host.KXGroup.ComputeKey(pub, host.KXPrivateKey)
	if err != nil {
		return err
	}
	// TODO: Are there issues with only using the first 32 bytes?
	host.KXCipher, err = chacha20poly1305.New(skey.Bytes()[:chacha20poly1305.KeySize])
	if err != nil {
		return err
	}
	return nil
}

func (host *RedisHost) FreePrivateKeys() {
	host.KXGroup = nil
	host.KXPrivateKey = nil
}

func (host *RedisHost) EncryptPacket(data []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := host.KXCipher.Seal(nil, nonce, data, nil)
	epckt := drshcomms.EncryptedPacket{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}
	encrypted, err := proto.Marshal(&epckt)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func (host *RedisHost) DecryptPacket(data []byte) ([]byte, error) {
	epckt := drshcomms.EncryptedPacket{}
	err := proto.Unmarshal([]byte(data), &epckt)
	if err != nil {
		return nil, err
	}
	plaintext, err := host.KXCipher.Open(nil, epckt.Nonce, epckt.Ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (host *RedisHost) WaitUntilReady() {
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
			host.SendPacket(host.Hostname, drshcomms.Packet{
				Type:   drshcomms.Packet_READY,
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

func (host *RedisHost) StartPacketSender() {
	for opckt := range host.Outgoing {
		if opckt.ShouldKill {
			break
		}
		raw, err := proto.Marshal(&opckt.Packet)
		if err != nil {
			host.Logger.Warnf("Failed to marshal packet: %s", err)
			continue
		}
		encrypted := raw
		if opckt.ShouldEncrypt {
			encrypted, err = host.EncryptPacket(raw)
			if err != nil {
				host.Logger.Warnf("Failed to encrypt packet: %s", err)
				continue
			}
		}
		err = host.Rdb.Publish(ctx, "drsh:"+opckt.Recipient, encrypted).Err()
		if err != nil {
			// If the host is closed, this is likely a normal shutdown event
			if host.IsOpen() {
				host.Logger.Warnf("Failed to publish packet: %s", err)
				continue
			} else {
				break
			}
		}
	}
}

func (host *RedisHost) StartPacketReceiver() {
	for {
		msg, err := host.Rps.ReceiveMessage(ctx)
		if err != nil {
			// If the host is closed, this is likely a normal shutdown event
			if host.IsOpen() {
				host.Logger.Warnf("Failed to receive packet: %s", err)
				continue
			} else {
				break
			}
		}
		raw := []byte(msg.Payload)
		if host.IsEncryptionEnabled() {
			raw, err = host.DecryptPacket(raw)
			if err != nil {
				host.Logger.Warnf("Failed to decrypt packet: %s", err)
				continue
			}
		}
		pckt := drshcomms.Packet{}
		err = proto.Unmarshal(raw, &pckt)
		if err != nil {
			host.Logger.Warnf("Failed to unmarshal packet: %s", err)
			continue
		}
		sender := pckt.GetSender()
		if pckt.GetType() == drshcomms.Packet_READY && sender == host.Hostname {
			host.ReadyMtx.Lock()
			host.ReadyFlag = true
			host.ReadyCnd.Signal()
			host.ReadyMtx.Unlock()
			continue
		}
		host.Handler(pckt)
	}
}

func (host *RedisHost) Start() {
	go host.StartPacketSender()
	go host.StartPacketReceiver()
	host.WaitUntilReady()
}

func (host *RedisHost) Close() {
	// Indicate that we are closed
	host.OpenMtx.Lock()
	host.OpenState = false
	host.OpenMtx.Unlock()
	// Kills the packet handler
	host.Outgoing <- OutgoingPacket{
		ShouldKill: true,
	}
	// Kills the packet receiver
	host.Rps.Close()
	// Disposes of the Redis connection
	if !host.Inherited {
		host.Rdb.Close()
	}
}
