package host

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/comms"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
)

type DirectedPacket struct {
	Category     string
	Recipient    string
	Packet       comms.Packet
	NeedsEncrypt bool
}

type RedisHost struct {
	Hostname     string
	Category     string
	Rdb          *redis.Client
	Rps          *redis.PubSub
	Outgoing     chan DirectedPacket
	Logger       *zap.SugaredLogger
	Handler      func(DirectedPacket)
	ReadyMtx     sync.Mutex
	ReadyFlag    bool
	ReadyCnd     *sync.Cond
	KXMtx        sync.Mutex
	KXGroup      *dhkx.DHGroup
	KXPrivateKey *dhkx.DHKey
	KXCipher     cipher.AEAD
	KXEnabled    bool
}

var ctx = context.Background()

func NewRedisHost(category string, hostname string, uri string, logger *zap.SugaredLogger, handler func(DirectedPacket)) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	host := RedisHost{
		Hostname:  hostname,
		Category:  category,
		Rdb:       redis.NewClient(opt),
		Outgoing:  make(chan DirectedPacket, 10),
		Logger:    logger,
		Handler:   handler,
		ReadyFlag: false,
		KXEnabled: false,
	}
	host.ReadyCnd = sync.NewCond(&host.ReadyMtx)
	err = host.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if host.IsListening(host.Category, host.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	host.Rps = host.Rdb.Subscribe(ctx, "drsh:"+host.Category+":"+host.Hostname)
	return &host, nil
}

func InheritRedisHost(category string, hostname string, rdb *redis.Client, logger *zap.SugaredLogger, handler func(DirectedPacket)) (*RedisHost, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	host := RedisHost{
		Hostname:  hostname,
		Category:  category,
		Rdb:       rdb,
		Outgoing:  make(chan DirectedPacket, 10),
		Logger:    logger,
		Handler:   handler,
		ReadyFlag: false,
		KXEnabled: false,
	}
	host.ReadyCnd = sync.NewCond(&host.ReadyMtx)
	err := host.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	if host.IsListening(host.Category, host.Hostname) {
		return nil, fmt.Errorf("hostname is in use already on this network")
	}
	host.Rps = host.Rdb.Subscribe(ctx, "drsh:"+host.Category+":"+host.Hostname)
	return &host, nil
}

func (host *RedisHost) IsListening(category string, hostname string) bool {
	channels, err := host.Rdb.PubSubChannels(ctx, "drsh:"+category+":"+hostname).Result()
	return err == nil && len(channels) > 0
}

func (host *RedisHost) SendPacket(dirpckt DirectedPacket) {
	dirpckt.NeedsEncrypt = host.IsEncryptionEnabled()
	host.Outgoing <- dirpckt
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
	epckt := comms.EncryptedPacket{
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
	epckt := comms.EncryptedPacket{}
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
			host.SendPacket(DirectedPacket{
				Category:  host.Category,
				Recipient: host.Hostname,
				Packet: comms.Packet{
					Type:   comms.Packet_READY,
					Sender: host.Hostname,
				},
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
	for dirpckt := range host.Outgoing {
		channel := "drsh:" + dirpckt.Category + ":" + dirpckt.Recipient
		raw, err := proto.Marshal(&dirpckt.Packet)
		if err != nil {
			host.Logger.Errorf("Failed to marshal packet: %s", err)
			continue
		}
		encrypted := raw
		if dirpckt.NeedsEncrypt {
			encrypted, err = host.EncryptPacket(raw)
			if err != nil {
				host.Logger.Errorf("Failed to encrypt packet: %s", err)
				continue
			}
		}
		err = host.Rdb.Publish(ctx, channel, encrypted).Err()
		if err != nil {
			host.Logger.Errorf("Failed to publish packet: %s", err)
			continue
		}
	}
}

func (host *RedisHost) StartPacketReceiver() {
	for {
		msg, err := host.Rps.ReceiveMessage(ctx)
		if err != nil {
			host.Logger.Errorf("Failed to receive packet: %s", err)
			continue
		}
		raw := []byte(msg.Payload)
		if host.IsEncryptionEnabled() {
			raw, err = host.DecryptPacket(raw)
			if err != nil {
				host.Logger.Errorf("Failed to decrypt packet: %s", err)
				continue
			}
		}
		components := strings.Split(msg.Channel, ":")
		if len(components) != 2 && components[0] != "drsh" {
			host.Logger.Errorf("Failed to validate channel: %s", msg.Channel)
			continue
		}
		dirpckt := DirectedPacket{
			Category:  components[1],
			Recipient: components[2],
			Packet:    comms.Packet{},
		}
		err = proto.Unmarshal(raw, &dirpckt.Packet)
		if err != nil {
			host.Logger.Errorf("Failed to unmarshal packet: %s", err)
			continue
		}
		sender := dirpckt.Packet.GetSender()
		if dirpckt.Packet.GetType() == comms.Packet_READY && sender == host.Hostname {
			host.ReadyMtx.Lock()
			host.ReadyFlag = true
			host.ReadyCnd.Signal()
			host.ReadyMtx.Unlock()
			continue
		}
		host.Handler(dirpckt)
	}
}

func (host *RedisHost) Start() {
	go host.StartPacketSender()
	go host.StartPacketReceiver()
	host.WaitUntilReady()
}

func (host *RedisHost) Close() {
	host.Rps.Close()
	host.Rdb.Close()
}