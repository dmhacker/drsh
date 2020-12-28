package server

import (
	"context"

	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/dmhacker/drsh/internal/util"
	"go.uber.org/zap"
)

type Server struct {
	Proxy  *proxy.RedisProxy
	Logger *zap.SugaredLogger
}

var ctx = context.Background()

func NewServer(hostname string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Logger: logger,
	}
	prx, err := proxy.NewRedisProxy("server", hostname, uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Proxy = prx
	return &serv, nil
}

func (serv *Server) HandlePing(sender string) {
	// Send an identical response packet back with public information
	serv.Proxy.SendPacket(proxy.DirectedPacket{
		Category:  "client",
		Recipient: sender,
		Packet: comms.Packet{
			Type:   comms.Packet_SERVER_PING,
			Sender: serv.Proxy.Hostname,
		},
	})
}

func (serv *Server) HandleHandshake(sender string, key []byte, packedDims uint64) {
	session, err := NewSessionFromHandshake(serv, sender, key)
	if err != nil {
		serv.Logger.Errorf("Failed to setup session with '%s': %s", sender, err)
		serv.Proxy.SendPacket(proxy.DirectedPacket{
			Category:  "client",
			Recipient: sender,
			Packet: comms.Packet{
				Type:             comms.Packet_SERVER_HANDSHAKE,
				Sender:           serv.Proxy.Hostname,
				HandshakeSuccess: false,
			},
		})
		return
	}
	serv.Proxy.SendPacket(proxy.DirectedPacket{
		Category:  "client",
		Recipient: sender,
		Packet: comms.Packet{
			Type:             comms.Packet_SERVER_HANDSHAKE,
			Sender:           serv.Proxy.Hostname,
			HandshakeKey:     session.PrivateKey.Bytes(),
			HandshakeSession: session.Proxy.Hostname,
			HandshakeSuccess: true,
		},
	})
	serv.Logger.Infof("'%s' has joined session %s.", sender, session.Proxy.Hostname)
	dims := util.Unpack64(packedDims)
	session.HandlePty(dims[0], dims[1], dims[2], dims[3])
	go session.Start()
}

func (serv *Server) HandlePacket(dirpckt proxy.DirectedPacket) {
	sender := dirpckt.Packet.GetSender()
	switch dirpckt.Packet.GetType() {
	case comms.Packet_CLIENT_PING:
		serv.HandlePing(sender)
	case comms.Packet_CLIENT_HANDSHAKE:
		serv.HandleHandshake(sender, dirpckt.Packet.GetHandshakeKey(), dirpckt.Packet.GetPtyDimensions())
	default:
		serv.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (serv *Server) Start() {
	serv.Proxy.Start()
	<-make(chan int)
}

func (serv *Server) Close() {
	serv.Proxy.Close()
}
