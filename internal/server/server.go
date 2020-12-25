package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/dmhacker/drsh/internal/packet"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/golang/protobuf/ptypes"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
)

type Server struct {
	Properties ServerProperties
	Sessions   sync.Map
	Proxy      *proxy.RedisProxy
	Logger     *zap.SugaredLogger
}

var ctx = context.Background()

func NewServer(name string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Properties: ServerProperties{
			StartedAt: time.Now(),
		},
		Sessions: sync.Map{},
		Logger:   logger,
	}
	prx, err := proxy.NewRedisProxy(name, "server", uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Proxy = prx
	return &serv, nil
}

func (serv *Server) GetSession(sender string) *Session {
	val, ok := serv.Sessions.Load(sender)
	if ok {
		return val.(*Session)
	} else {
		return nil
	}
}

func (serv *Server) PutSession(sender string, session *Session) {
	serv.Sessions.Store(sender, session)
}

func (serv *Server) DeleteSession(sender string) {
	serv.Sessions.Delete(sender)
}

func (serv *Server) HandlePing(sender string) {
	// Send an identical response packet back with public server information
	resp := packet.Packet{
		Type:       packet.Packet_SERVER_PING,
		Sender:     serv.Proxy.Name,
		Recipient:  sender,
		PingUptime: ptypes.DurationProto(serv.Properties.Uptime()),
	}
	serv.Proxy.SendPacket("client", &resp)
	serv.Logger.Infof("'%s' has pinged.", sender)
}

func (serv *Server) HandleHandshake(sender string, hasSession bool, rows uint32, cols uint32, xpixels uint32, ypixels uint32, key []byte) {
	if hasSession {
		serv.Logger.Errorw("'%s' is already connected.", sender)
		return
	}
	session, err := NewSession(rows, cols, xpixels, ypixels)
	if err != nil {
		serv.Logger.Errorw("Could not allocate session: %s", err)
		return
	}
	pkey := dhkx.NewPublicKey(key)
	skey, err := session.Group.ComputeKey(pkey, session.PrivateKey)
	if err != nil {
		serv.Logger.Errorw("Received invalid key from client: %s", err)
		return
	}
	// TODO: Are there issues with only using the first 32 bytes?
	session.Cipher, err = chacha20poly1305.New(skey.Bytes()[:chacha20poly1305.KeySize])
	if err != nil {
		serv.Logger.Errorw("Unable to create cipher: %s", err)
		return
	}
	serv.PutSession(sender, session)
	resp := packet.Packet{
		Type:      packet.Packet_SERVER_HANDSHAKE,
		Sender:    serv.Proxy.Name,
		Recipient: sender,
		Key:       session.PrivateKey.Bytes(),
	}
	serv.Proxy.SendPacket("client", &resp)
	serv.Logger.Infof("'%s' has connected.", sender)
	// Spawn goroutine to start capturing stdout from this session
	go (func() {
		for {
			session := serv.GetSession(sender)
			if session != nil {
				buf := make([]byte, 2048)
				cnt, err := session.Receive(buf)
				if err != nil {
					serv.HandleExit(sender, err, true)
					break
				}
				nonce := make([]byte, chacha20poly1305.NonceSize)
				_, err = rand.Read(nonce)
				if err != nil {
					serv.HandleExit(sender, err, true)
					break
				}
				ciphertext := session.Cipher.Seal(nil, nonce, buf[:cnt], nil)
				out := packet.Packet{
					Type:      packet.Packet_SERVER_OUTPUT,
					Sender:    serv.Proxy.Name,
					Recipient: sender,
					Payload:   ciphertext,
					Nonce:     nonce,
				}
				serv.Proxy.SendPacket("client", &out)
			} else {
				// If the session was already cleaned up, we
				// can just end the goroutine gracefully
				break
			}
		}
	})()
}

func (serv *Server) HandleOutput(sender string, payload []byte, nonce []byte) {
	// Any input goes directly to the session; no response packet necessary
	// If the input fails to be written to the session, terminate the client
	session := serv.GetSession(sender)
	if session != nil {
		plaintext, err := session.Cipher.Open(nil, nonce, payload, nil)
		if err != nil {
			serv.HandleExit(sender, err, true)
		}
		_, err = session.Send(plaintext)
		if err != nil {
			serv.HandleExit(sender, err, true)
		}
	}
}

func (serv *Server) HandlePty(sender string, rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	// Again, the resize event goes directly to the session
	session := serv.GetSession(sender)
	if session != nil {
		session.Resize(rows, cols, xpixels, ypixels)
	}
}

func (serv *Server) HandleExit(sender string, err error, ack bool) {
	// Clean up any session state between the server and the client
	serv.DeleteSession(sender)
	// Send an acknowledgement back to the client to indicate that we have
	// closed the session on the server's end
	if ack {
		resp := packet.Packet{
			Type:      packet.Packet_SERVER_EXIT,
			Sender:    serv.Proxy.Name,
			Recipient: sender,
		}
		serv.Proxy.SendPacket("client", &resp)
	}
	if err != nil {
		serv.Logger.Infof("'%s' has disconnected: %s.", sender, err.Error())
	} else {
		serv.Logger.Infof("'%s' has disconnected.", sender)
	}
}

func (serv *Server) HandlePacket(pckt *packet.Packet) {
	sender := pckt.GetSender()
	session := serv.GetSession(sender)
	if session != nil {
		session.RefreshExpiry()
	}
	switch pckt.GetType() {
	case packet.Packet_CLIENT_PING:
		serv.HandlePing(sender)
	case packet.Packet_CLIENT_HANDSHAKE:
		serv.HandleHandshake(sender, session != nil, pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels(), pckt.GetKey())
	case packet.Packet_CLIENT_OUTPUT:
		serv.HandleOutput(sender, pckt.GetPayload(), pckt.GetNonce())
	case packet.Packet_CLIENT_PTY_WINCH:
		serv.HandlePty(sender, pckt.GetPtyRows(), pckt.GetPtyCols(), pckt.GetPtyXpixels(), pckt.GetPtyYpixels())
	case packet.Packet_CLIENT_EXIT:
		serv.HandleExit(sender, nil, false)
	default:
		serv.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (serv *Server) StartTimeoutHandler() {
	// Runs every 30 seconds and performs a sweep through the sessions to
	// make sure none are expired (last packet received >10 minutes ago)
	expiryCheck := func(k interface{}, v interface{}) bool {
		sender, _ := k.(string)
		session, _ := v.(*Session)
		if session.IsExpired() {
			serv.HandleExit(sender, fmt.Errorf("client timed out"), true)
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
