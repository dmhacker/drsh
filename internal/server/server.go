package server

import (
	"context"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Server struct {
	Name     string
	Sessions sync.Map
	Proxy    *proxy.RedisProxy
	Logger   *zap.SugaredLogger
}

var ctx = context.Background()

func NewServer(name string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Name:     name,
		Sessions: sync.Map{},
		Logger:   logger,
	}
	prx, err := proxy.NewRedisProxy("server", uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Proxy = prx
	return &serv, nil
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
	resp.Sender = serv.Proxy.Id[:]
	resp.Recipient = sender[:]
	resp.Success = true
	resp.ServerName = serv.Name
	serv.Proxy.SendPacket(&resp)
	serv.Logger.Infof("Client %s has pinged.", sender.String())
}

func (serv *Server) HandleHandshake(sender uuid.UUID, hasSession bool, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	// Always send back a handshake response but vary success
	// based on whether or not user has a session
	resp := packet.Packet{}
	resp.Type = packet.Packet_SERVER_HANDSHAKE
	resp.Sender = serv.Proxy.Id[:]
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
			serv.Logger.Infof("Client %s has connected.", sender.String())
		}
	}
	serv.Proxy.SendPacket(&resp)

	// Spawn goroutine to start capturing stdout from this session
	// and convert it into outgoing packets
	if resp.Success {
		go (func() {
			for {
				session := serv.GetSession(sender)
				if session != nil {
					buf := make([]byte, 1024)
					cnt, err := session.Receive(buf)
					if err != nil {
						serv.HandleExit(sender, err, true)
					}
					out := packet.Packet{}
					out.Type = packet.Packet_SERVER_OUTPUT
					out.Sender = serv.Proxy.Id[:]
					out.Recipient = sender[:]
					out.Payload = buf[:cnt]
					out.Success = true
					serv.Proxy.SendPacket(&out)
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
			serv.HandleExit(sender, err, true)
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

func (serv *Server) HandleExit(sender uuid.UUID, err error, ack bool) {
	// Clean up any session state between the server and the client
	serv.DeleteSession(sender)
	// Send an acknowledgement back to the client to indicate that we have
	// closed the session on the server's end
	if ack {
		resp := packet.Packet{}
		resp.Type = packet.Packet_SERVER_EXIT
		resp.Sender = serv.Proxy.Id[:]
		resp.Recipient = sender[:]
		if err != nil {
			resp.Success = false
			resp.Error = "An error occurred: " + err.Error()
		} else {
			resp.Success = true
		}
		serv.Proxy.SendPacket(&resp)
	}
	serv.Logger.Infof("Client %s has disconnected.", sender.String())
}

func (serv *Server) HandlePacket(pckt *packet.Packet) {
	sender, _ := uuid.FromBytes(pckt.GetSender())
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
		serv.HandleExit(sender, nil, false)
	default:
		serv.Logger.Errorf("Received invalid packet from %s.", sender.String())
	}
}

func (serv *Server) StartTimeoutHandler() {
	// Runs every 30 seconds and performs a sweep through the sessions to
	// make sure none are expired (last packet received >10 minutes ago)
	expiryCheck := func(k interface{}, v interface{}) bool {
		sender, _ := k.(uuid.UUID)
		session, _ := v.(*Session)
		if session.IsExpired() {
			serv.HandleExit(sender, nil, true)
		}
		return true
	}
	for {
		serv.Sessions.Range(expiryCheck)
		time.Sleep(30 * time.Second)
	}
}

func (serv *Server) Start() {
	go serv.StartTimeoutHandler()
	serv.Proxy.Start()
	<-make(chan int)
}

func (serv *Server) Close() {
	serv.Proxy.Close()
}
