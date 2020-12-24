package proxy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"
)

type CategoryPacket struct {
	Category string
	Packet   *packet.Packet
}

type RedisProxy struct {
	Name      string
	Category  string
	Rdb       *redis.Client
	Incoming  chan *packet.Packet
	Outgoing  chan CategoryPacket
	Logger    *zap.SugaredLogger
	Handler   func(*packet.Packet)
	ReadyMtx  sync.Mutex
	ReadyFlag bool
	ReadyCnd  *sync.Cond
}

var ctx = context.Background()

func NewRedisProxy(name string, category string, uri string, logger *zap.SugaredLogger, handler func(*packet.Packet)) (*RedisProxy, error) {
	if name == "" {
		return nil, fmt.Errorf("Name cannot be empty")
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	prx := RedisProxy{
		Name:      name,
		Category:  category,
		Rdb:       redis.NewClient(opt),
		Incoming:  make(chan *packet.Packet),
		Outgoing:  make(chan CategoryPacket),
		Logger:    logger,
		Handler:   handler,
		ReadyMtx:  sync.Mutex{},
		ReadyFlag: false,
	}
	prx.ReadyCnd = sync.NewCond(&prx.ReadyMtx)
	err = prx.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	check, err := prx.Rdb.PubSubChannels(ctx, "drsh:"+prx.Category+":"+prx.Name).Result()
	if err != nil {
		return nil, err
	}
	if len(check) > 0 {
		return nil, fmt.Errorf("Another server is already using that name.")
	}
	return &prx, nil
}

func (prx *RedisProxy) CandidateServers() []string {
	channels, err := prx.Rdb.PubSubChannels(ctx, "drsh:server:*").Result()
	if err != nil {
		prx.Logger.Errorf("Could not obtain Redis channels: %s", err)
	}
	servers := make([]string, 0, len(channels))
	for _, channel := range channels {
		server := strings.Join(strings.Split(channel, ":")[2:], ":")
		servers = append(servers, server)
	}
	return servers
}

func (prx *RedisProxy) WaitUntilReady() {
	// The ready check works by spawning a goroutine to send READY packets
	// through Redis back to itself. As soon as one of these packets is
	// fully processed, this indicates that the pipeline is functional
	go (func() {
		for {
			prx.ReadyMtx.Lock()
			ready := prx.ReadyFlag
			prx.ReadyMtx.Unlock()
			if ready {
				break
			}
			pckt := packet.Packet{
				Type:      packet.Packet_READY,
				Sender:    prx.Name,
				Recipient: prx.Name,
			}
			prx.SendPacket(prx.Category, &pckt)
			time.Sleep(500 * time.Millisecond)
		}
	})()
	prx.ReadyMtx.Lock()
	defer prx.ReadyMtx.Unlock()
	for !prx.ReadyFlag {
		prx.ReadyCnd.Wait()
	}
}

func (prx *RedisProxy) StartPacketHandler() {
	// Any incoming packets over the channel have preliminary
	// checks performed on them and then are handled by type
	for pckt := range prx.Incoming {
		recipient := pckt.GetRecipient()
		if recipient != prx.Name {
			// Silently ignore any packets not intended for us
			continue
		}
		sender := pckt.GetSender()
		if pckt.GetType() == packet.Packet_READY && sender == prx.Name {
			prx.ReadyMtx.Lock()
			prx.ReadyFlag = true
			prx.ReadyCnd.Signal()
			prx.ReadyMtx.Unlock()
			continue
		}
		prx.Handler(pckt)
	}
}

func (prx *RedisProxy) StartPacketSender() {
	// Any outgoing packets are immediately serialized and then
	// sent through Redis
	for out := range prx.Outgoing {
		channel := "drsh:"
		channel += out.Category + ":"
		channel += out.Packet.GetRecipient()
		serial, err := proto.Marshal(out.Packet)
		if err != nil {
			prx.Logger.Errorf("Could not marshal packet: %s", err)
			continue
		}
		err = prx.Rdb.Publish(ctx, channel, serial).Err()
		if err != nil {
			prx.Logger.Errorf("Unable to publish packet: %s", err)
			continue
		}
	}
}

func (prx *RedisProxy) StartPacketReceiver() {
	pubsub := prx.Rdb.Subscribe(ctx, "drsh:"+prx.Category+":"+prx.Name)
	defer pubsub.Close()
	for {
		msg, err := pubsub.ReceiveMessage(ctx)
		if err != nil {
			prx.Logger.Errorf("Unable to receive packet: %s", err)
			continue
		}
		pckt := packet.Packet{}
		proto.Unmarshal([]byte(msg.Payload), &pckt)
		prx.Incoming <- &pckt
	}
}

func (prx *RedisProxy) SendPacket(category string, pckt *packet.Packet) {
	prx.Outgoing <- CategoryPacket{
		Category: category,
		Packet:   pckt,
	}
}

func (prx *RedisProxy) Start() {
	go prx.StartPacketSender()
	go prx.StartPacketHandler()
	go prx.StartPacketReceiver()
	prx.WaitUntilReady()
}

func (prx *RedisProxy) Close() {
	prx.Rdb.Close()
}
