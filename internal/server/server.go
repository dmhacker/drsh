package server

import (
	"context"

	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/host"
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
	hst, err := host.NewRedisHost("se-"+hostname, uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Host = hst
	return &serv, nil
}

func (serv *Server) HandlePing(sender string) {
	serv.Host.SendPacket(sender, comms.Packet{
		Type:   comms.Packet_SERVER_PING,
		Sender: serv.Host.Hostname,
	})
}

func (serv *Server) HandleHandshake(sender string, key []byte, username string) {
	resp := comms.Packet{
		Type:   comms.Packet_SERVER_HANDSHAKE,
		Sender: serv.Host.Hostname,
	}
	session, err := NewSessionFromHandshake(serv, sender, key, username)
	if err != nil {
		serv.Logger.Warnf("Failed to setup session with '%s': %s", sender, err)
		resp.HandshakeSuccess = false
		serv.Host.SendPacket(sender, resp)
	} else {
		serv.Logger.Infof("'%s' has joined session %s.", sender, session.Host.Hostname)
		resp.HandshakeSuccess = true
		resp.HandshakeKey = session.Host.KXPrivateKey.Bytes()
		resp.HandshakeSession = session.Host.Hostname
		serv.Host.SendPacket(sender, resp)
		session.Host.FreePrivateKeys()
		session.Host.SetEncryptionEnabled(true)
		session.Start()
	}
}

func (serv *Server) HandlePacket(pckt comms.Packet) {
	switch pckt.GetType() {
	case comms.Packet_CLIENT_PING:
		serv.HandlePing(pckt.GetSender())
	case comms.Packet_CLIENT_HANDSHAKE:
		serv.HandleHandshake(pckt.GetSender(), pckt.GetHandshakeKey(), pckt.GetHandshakeUser())
	default:
		serv.Logger.Warnf("Received invalid packet from '%s'.", pckt.GetSender())
	}
}

func (serv *Server) Start() {
	serv.Host.Start()
}

func (serv *Server) Close() {
	serv.Host.Close()
}
