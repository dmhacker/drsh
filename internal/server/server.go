package server

import (
	"context"
	"log"
	"sync"
	"time"

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
	Sessions sync.Map
	Rdb      *redis.Client
	Incoming chan *packet.Packet
	Outgoing chan *packet.Packet
}

var ctx = context.Background()

func NewServer(name string, uri string) (*Server, error) {
	opt, err := redis.ParseURL(uri)
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
		Sessions: sync.Map{},
		Rdb:      redis.NewClient(opt),
		Incoming: make(chan *packet.Packet),
		Outgoing: make(chan *packet.Packet),
	}, nil
}

func (serv *Server) GetSession(sender uuid.UUID) *Session {
	val, ok := serv.Sessions.Load(sender)
	if ok {
		return val.(*Session)
	} else {
		return nil
	}
}

func (serv *Server) PutSession(sender uuid.UUID, session *Session) {
	serv.Sessions.Store(sender, session)
}

func (serv *Server) DeleteSession(sender uuid.UUID) {
	serv.Sessions.Delete(sender)
}

func (serv *Server) HandlePing(sender uuid.UUID) {
	// Send an identical response packet back, only including the server name
	resp := packet.Packet{}
	resp.Type = packet.Packet_SERVER_PING
	resp.Sender = serv.Id[:]
	resp.Recipient = sender[:]
	resp.Success = true
	resp.ServerName = serv.Name
	serv.Outgoing <- &resp
}

func (serv *Server) HandleHandshake(sender uuid.UUID, hasSession bool, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	// Always send back a handshake response but vary success
	// based on whether or not user has a session
	resp := packet.Packet{}
	resp.Type = packet.Packet_SERVER_HANDSHAKE
	resp.Sender = serv.Id[:]
	resp.Recipient = sender[:]
	if hasSession {
		resp.Success = false
		resp.Error = "You are already connected to this server"
	} else {
		session, err := NewSession(rows, cols, xpixels, ypixels)
		if err != nil {
			resp.Success = false
			resp.Error = "An error occurred: " + err.Error()
		} else {
			resp.Success = true
			serv.PutSession(sender, session)
			log.Printf("Client %s has connected.", sender.String())
		}
	}
	serv.Outgoing <- &resp

	// Spawn goroutine to start capturing stdout from this session
	// and convert it into outgoing packets
	if resp.Success {
		go (func() {
			buf := make([]byte, 1024)
			for {
				session := serv.GetSession(sender)
				if session != nil {
					cnt, err := session.Receive(buf)
					if err != nil {
						serv.HandleExit(sender, err)
					}
					out := packet.Packet{}
					out.Type = packet.Packet_SERVER_OUTPUT
					out.Sender = serv.Id[:]
					out.Recipient = sender[:]
					out.Payload = buf[:cnt]
					out.Success = true
					serv.Outgoing <- &out
				} else {
					// If the session was already cleaned up, we
					// can just end the goroutine gracefully
					break
				}
			}
		})()
	}
}

func (serv *Server) HandleInput(sender uuid.UUID, payload []byte) {
    // Any input goes directly to the session; no response packet necessary
    // If the input fails to be written to the session, terminate the client
	session := serv.GetSession(sender)
	if session != nil {
		written, err := session.Send(payload)
		if err != nil || written != len(payload) {
			serv.HandleExit(sender, err)
		}
	}
}

func (serv *Server) HandlePty(sender uuid.UUID, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
    // Again, the resize event goes directly to the session
	session := serv.GetSession(sender)
	if session != nil {
		session.Resize(rows, cols, xpixels, ypixels)
	}
}

func (serv *Server) HandleExit(sender uuid.UUID, err error) {
    // Clean up any session state between the server and the client
	serv.DeleteSession(sender)
    // Send an acknowledgement back to the client to indicate that we have 
    // closed the session on the server's end
	resp := packet.Packet{}
	resp.Type = packet.Packet_SERVER_EXIT
	resp.Sender = serv.Id[:]
	resp.Recipient = sender[:]
	if err != nil {
		resp.Success = false
		resp.Error = "An error occurred: " + err.Error()
	} else {
		resp.Success = true
	}
	log.Printf("Client %s has disconnected.", sender.String())
	serv.Outgoing <- &resp
}

func (serv *Server) StartTimeoutHandler() {
    // Runs every 30 seconds and performs a sweep through the sessions to
    // make sure none are expired (last packet received >10 minutes ago)
    log.Println("Timeout handler is online")
	expiryCheck := func(k interface{}, v interface{}) bool {
		sender, _ := k.(uuid.UUID)
		session, _ := k.(*Session)
		if session.IsExpired() {
			serv.HandleExit(sender, nil)
		}
		return true
	}
	for {
		serv.Sessions.Range(expiryCheck)
		time.Sleep(30 * time.Second)
	}
}

func (serv *Server) StartPacketHandler() {
    // Any incoming packets over the channel have preliminary
    // checks performed on them and then are handled by type
    log.Println("Packet handler is online")
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
		session := serv.GetSession(sender)
		if session != nil {
			session.RefreshExpiry()
		}
		switch pt := pckt.GetType(); pt {
		case packet.Packet_CLIENT_PING:
			serv.HandlePing(sender)
		case packet.Packet_CLIENT_HANDSHAKE:
			serv.HandleHandshake(sender, session != nil, pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels())
		case packet.Packet_CLIENT_INPUT:
			serv.HandleInput(sender, pckt.GetPayload())
		case packet.Packet_CLIENT_PTY:
			serv.HandlePty(sender, pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels())
		case packet.Packet_CLIENT_EXIT:
			serv.HandleExit(sender, nil)
		default:
			log.Printf("Received invalid packet from %s.\n", sender.String())
		}
	}
}

func (serv *Server) StartPacketSender() {
    // Any outgoing packets are immediately serialized and then
    // sent through Redis
    log.Println("Packet sender is online")
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
	go serv.StartPacketSender()
	go serv.StartPacketHandler()
	go serv.StartTimeoutHandler()
	// Main thread is responsible for parsing messages and passing them off to the packet handler
    log.Println("Packet receiver is online")
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
