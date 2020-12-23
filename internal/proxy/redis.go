package proxy

import (
	"context"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type RedisProxy struct {
	Id       uuid.UUID
	Category string
	Rdb      *redis.Client
	Incoming chan *packet.Packet
	Outgoing chan *packet.Packet
	Logger   *zap.SugaredLogger
	Handler  func(*packet.Packet)
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
		Id:       id,
		Category: category,
		Rdb:      redis.NewClient(opt),
		Incoming: make(chan *packet.Packet),
		Outgoing: make(chan *packet.Packet),
		Logger:   logger,
		Handler:  handler,
	}
	err = prx.Rdb.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}
	return &prx, nil
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
		_, err = uuid.FromBytes(pckt.GetSender())
		if err != nil {
			prx.Logger.Errorf("Could not interpret incoming sender ID: %s", err)
			continue
		}
		prx.Handler(pckt)
	}
}

func (prx *RedisProxy) StartPacketSender() {
	// Any outgoing packets are immediately serialized and then
	// sent through Redis
	for pckt := range prx.Outgoing {
		recipient, err := uuid.FromBytes(pckt.GetRecipient())
		if err != nil {
			prx.Logger.Errorf("Could not interpret outgoing recipient ID: %s", err)
			continue
		}
		channel := "drsh:"
        // Infer from outgoing packet type what the proxy category is
        switch pckt.GetType() {
        case packet.Packet_SERVER_PING:
            channel += "client:"
        case packet.Packet_SERVER_HANDSHAKE:
            channel += "client:"
        case packet.Packet_SERVER_OUTPUT:
            channel += "client:"
        case packet.Packet_SERVER_EXIT:
            channel += "client:"
        default:
            channel += "server:"
        }
        channel += recipient.String()
		serial, err := proto.Marshal(pckt)
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

func (prx *RedisProxy) SendPacket(pckt *packet.Packet) {
	prx.Outgoing <- pckt
}

func (prx *RedisProxy) Start() {
	go prx.StartPacketSender()
	go prx.StartPacketHandler()
	go prx.StartPacketReceiver()
}

func (prx *RedisProxy) Close() {
	prx.Rdb.Close()
}
