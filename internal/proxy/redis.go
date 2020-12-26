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

type DirectedPacket struct {
	Category  string
	Recipient string
	Packet    *packet.Packet
}

type RedisProxy struct {
	Name      string
	Category  string
	Rdb       *redis.Client
	Rps       *redis.PubSub
	Incoming  chan DirectedPacket
	Outgoing  chan DirectedPacket
	Logger    *zap.SugaredLogger
	Handler   func(DirectedPacket)
	ReadyMtx  sync.Mutex
	ReadyFlag bool
	ReadyCnd  *sync.Cond
}

var ctx = context.Background()

func NewRedisProxy(name string, category string, uri string, logger *zap.SugaredLogger, handler func(DirectedPacket)) (*RedisProxy, error) {
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
		Incoming:  make(chan DirectedPacket),
		Outgoing:  make(chan DirectedPacket),
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
	prx.Rps = prx.Rdb.Subscribe(ctx, "drsh:"+prx.Category+":"+prx.Name)
	return &prx, nil
}

func (prx *RedisProxy) ConnectedNodes(category string) []string {
	channels, err := prx.Rdb.PubSubChannels(ctx, "drsh:"+category+":*").Result()
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
				Type:   packet.Packet_READY,
				Sender: prx.Name,
			}
			prx.SendPacket(DirectedPacket{
				Category:  prx.Category,
				Recipient: prx.Name,
				Packet:    &pckt,
			})
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
	for dp := range prx.Incoming {
		pckt := dp.Packet
		sender := pckt.GetSender()
		if pckt.GetType() == packet.Packet_READY && sender == prx.Name {
			prx.ReadyMtx.Lock()
			prx.ReadyFlag = true
			prx.ReadyCnd.Signal()
			prx.ReadyMtx.Unlock()
			continue
		}
		prx.Handler(dp)
	}
}

func (prx *RedisProxy) StartPacketSender() {
	// Any outgoing packets are immediately serialized and then
	// sent through Redis
	for out := range prx.Outgoing {
		channel := "drsh:"
		channel += out.Category + ":"
		channel += out.Recipient
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
	for {
		msg, err := prx.Rps.ReceiveMessage(ctx)
		if err != nil {
			prx.Logger.Errorf("Unable to receive packet: %s", err)
			continue
		}
		pckt := packet.Packet{}
		proto.Unmarshal([]byte(msg.Payload), &pckt)
		components := strings.Split(msg.Channel, ":")
		if len(components) != 2 && components[0] != "drsh" {
			prx.Logger.Errorf("Packet's channel is invalid: %s", msg.Channel)
			continue
		}
		prx.Incoming <- DirectedPacket{
			Category:  components[1],
			Recipient: components[2],
			Packet:    &pckt,
		}
	}
}

func (prx *RedisProxy) SendPacket(dirpckt DirectedPacket) {
	prx.Outgoing <- dirpckt
}

func (prx *RedisProxy) Start() {
	go prx.StartPacketSender()
	go prx.StartPacketHandler()
	go prx.StartPacketReceiver()
	prx.WaitUntilReady()
}

func (prx *RedisProxy) Close() {
	prx.Rps.Close()
	prx.Rdb.Close()
}
