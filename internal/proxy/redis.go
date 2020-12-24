package proxy

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CategoryPacket struct {
	Category string
	Packet   *packet.Packet
}

type RedisProxy struct {
	Id        uuid.UUID
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

func NewRedisProxy(category string, uri string, logger *zap.SugaredLogger, handler func(*packet.Packet)) (*RedisProxy, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	prx := RedisProxy{
		Id:        id,
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
	return &prx, nil
}

func (prx *RedisProxy) CandidateServers() []uuid.UUID {
	channels, err := prx.Rdb.PubSubChannels(ctx, "drsh:server:*").Result()
	if err != nil {
		prx.Logger.Errorf("Could not obtain Redis channels: %s", err)
	}
	servers := make([]uuid.UUID, 0, len(channels))
	for _, channel := range channels {
		server, err := uuid.Parse(strings.Split(channel, ":")[2])
		if err != nil {
			continue
		}
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
				Sender:    prx.Id[:],
				Recipient: prx.Id[:],
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
		recipient, err := uuid.FromBytes(pckt.GetRecipient())
		if err != nil {
			prx.Logger.Errorf("Could not interpret incoming recipient ID: %s", err)
			continue
		}
		if recipient != prx.Id {
			// Silently ignore any packets not intended for us
			continue
		}
		sender, err := uuid.FromBytes(pckt.GetSender())
		if err != nil {
			prx.Logger.Errorf("Could not interpret incoming sender ID: %s", err)
			continue
		}
		if pckt.GetType() == packet.Packet_READY && sender == prx.Id {
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
		recipient, err := uuid.FromBytes(out.Packet.GetRecipient())
		if err != nil {
			prx.Logger.Errorf("Could not interpret outgoing recipient ID: %s", err)
			continue
		}
		channel := "drsh:"
		channel += out.Category + ":"
		channel += recipient.String()
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
	pubsub := prx.Rdb.Subscribe(ctx, "drsh:"+prx.Category+":"+prx.Id.String())
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
