package server

import (
	"context"

	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/host"
	"github.com/dmhacker/drsh/internal/util"
	"go.uber.org/zap"
)

type Server struct {
	Host   *host.RedisHost
	Logger *zap.SugaredLogger
}

var ctx = context.Background()

func NewServer(hostname string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Logger: logger,
	}
	hst, err := host.NewRedisHost("server", hostname, uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Host = hst
	return &serv, nil
}

func (serv *Server) HandlePing(sender string) {
	// Send an identical response packet back with public information
	serv.Host.SendPacket(host.DirectedPacket{
		Category:  "client",
		Recipient: sender,
		Packet: comms.Packet{
			Type:   comms.Packet_SERVER_PING,
			Sender: serv.Host.Hostname,
		},
	})
}

func (serv *Server) HandleHandshake(sender string, key []byte, packedDims uint64) {
	resp := host.DirectedPacket{
		Category:  "client",
		Recipient: sender,
		Packet: comms.Packet{
			Type:   comms.Packet_SERVER_HANDSHAKE,
			Sender: serv.Host.Hostname,
		},
	}
	session, err := NewSessionFromHandshake(serv, sender, key)
	if err != nil {
		resp.Packet.HandshakeSuccess = false
		serv.Host.SendPacket(resp)
		serv.Logger.Errorf("Failed to setup session with '%s': %s", sender, err)
	} else {
		resp.Packet.HandshakeSuccess = true
		resp.Packet.HandshakeKey = session.Host.KXPrivateKey.Bytes()
		resp.Packet.HandshakeSession = session.Host.Hostname
		serv.Host.SendPacket(resp)
		serv.Logger.Infof("'%s' has joined session %s.", sender, session.Host.Hostname)
		dims := util.Unpack64(packedDims)
		session.HandlePty(dims[0], dims[1], dims[2], dims[3])
		session.Host.FreePrivateKeys()
		session.Host.SetEncryptionEnabled(true)
		go session.Start()
	}
}

func (serv *Server) HandlePacket(dirpckt host.DirectedPacket) {
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
	serv.Host.Start()
	<-make(chan int)
}

func (serv *Server) Close() {
	serv.Host.Close()
}
