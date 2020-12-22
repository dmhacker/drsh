package server

import (
	"context"
	"log"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
)

type SimpleMessage struct {

}

type Server struct {
	Name     string
	Id       uuid.UUID
	Sessions map[uuid.UUID]Session
	Rdb      *redis.Client
	Incoming chan *packet.Packet
    Outgoing chan *packet.Packet
}

var ctx = context.Background()

func NewServer(name string, url string) (*Server, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return &Server{
		Name:     name,
		Id:       id,
		Sessions: make(map[uuid.UUID]Session),
		Rdb:      redis.NewClient(opt),
	}, nil
}

func (serv *Server) StartReceiver() {
	for pckt := range serv.Incoming {
		recipient, err := uuid.FromBytes(pckt.GetRecipient())
		if err != nil {
			log.Printf("Could not interpret incoming recipient ID: %s", err)
            continue
		}
        if recipient != serv.Id {
            // Silently ignore any packets not intended for us
            continue
        }
		sender, err := uuid.FromBytes(pckt.GetSender())
		if err != nil {
			log.Printf("Could not interpret incoming sender ID: %s", err)
            continue
		}
		switch pt := pckt.GetType(); pt {
		case packet.Packet_CLIENT_PING:
            // TODO: Handle ping
		case packet.Packet_CLIENT_HANDSHAKE:
            // TODO: Handle handshake
		case packet.Packet_CLIENT_HEARTBEAT:
            // TODO: Handle heartbeat
		case packet.Packet_CLIENT_INPUT:
            // TODO: Handle input
		case packet.Packet_CLIENT_PTY:
            // TODO: Handle tty resize
		default:
			log.Printf("Received invalid packet from %s.\n", sender.String())
		}
	}
}

func (serv* Server) StartSender() {
    for pckt := range serv.Outgoing {
        recipient, err := uuid.FromBytes(pckt.GetRecipient())
        if err != nil {
			log.Printf("Could not interpret outgoing recipient ID: %s", err)
            continue
		}
        channel := "drsh:" + recipient.String()
        serial, err := proto.Marshal(pckt)
        if err != nil {
			log.Printf("Could not marshal packet: %s", err)
            continue
        }
        err = serv.Rdb.Publish(ctx, channel, serial).Err()
        if err != nil {
			log.Printf("Unable to publish packet: %s", err)
            continue
        }
    }
}

func (serv *Server) Start() error {
	go serv.StartReceiver()
	go serv.StartSender()
	// Main thread is responsible for listening to messages and passing them off to handlers
	pubsub := serv.Rdb.Subscribe(ctx, "drsh:"+serv.Id.String())
	for {
		msg, err := pubsub.ReceiveMessage(ctx)
		if err != nil {
			return err
		}
		pckt := packet.Packet{}
		proto.Unmarshal([]byte(msg.Payload), &pckt)
		serv.Incoming <- &pckt 
	}
}

func (serv *Server) Close() {
	serv.Rdb.Close()
}
