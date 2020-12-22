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
	Sessions map[uuid.UUID]*Session
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
		Sessions: make(map[uuid.UUID]*Session),
		Rdb:      redis.NewClient(opt),
	}, nil
}

func (serv *Server) HandlePing(sender uuid.UUID, seqNum uint32) {
	resp := packet.Packet{}
	resp.Sender = serv.Id[:]
	resp.Recipient = sender[:]
	resp.AckSeqNum = seqNum
	resp.Success = true
	resp.Name = serv.Name
	serv.Outgoing <- &resp
}

func (serv *Server) HandleHandshake(sender uuid.UUID, seqNum uint32, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	resp := packet.Packet{}
	resp.Sender = serv.Id[:]
	resp.Recipient = sender[:]
	resp.AckSeqNum = seqNum
	if _, ok := serv.Sessions[sender]; ok {
		resp.Success = false
		resp.Error = "You are already connected to this server"
	} else {
		session, err := NewSession(rows, cols, xpixels, ypixels)
		if err != nil {
			resp.Success = false
			resp.Error = "An error occurred: " + err.Error()
		} else {
			resp.Success = true
			serv.Sessions[sender] = session
		}
	}
	serv.Outgoing <- &resp
}

func (serv *Server) HandleHeartbeat(sender uuid.UUID, seqNum uint32, pckt *packet.Packet) {
	// TODO: Implement heartbeat
}

func (serv *Server) HandleInput(sender uuid.UUID, payload []byte) {
	serv.Sessions[sender].Send(payload)
}

func (serv *Server) HandlePty(sender uuid.UUID, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	serv.Sessions[sender].Resize(rows, cols, xpixels, ypixels)
}

func (serv *Server) StartHandler() {
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
			serv.HandlePing(sender, pckt.GetSeqNum())
		case packet.Packet_CLIENT_HANDSHAKE:
			serv.HandleHandshake(sender, pckt.GetSeqNum(), pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels())
		case packet.Packet_CLIENT_HEARTBEAT:
			// TODO: Handle heartbeat
		case packet.Packet_CLIENT_INPUT:
			serv.HandleInput(sender, pckt.GetPayload())
		case packet.Packet_CLIENT_PTY:
			serv.HandlePty(sender, pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels())
		default:
			log.Printf("Received invalid packet from %s.\n", sender.String())
		}
	}
}

func (serv *Server) StartSender() {
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
	go serv.StartHandler()
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
