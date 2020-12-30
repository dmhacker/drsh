package drshserver

import (
	"context"
	"strings"

	"github.com/dmhacker/drsh/internal/drshcomms"
	"github.com/dmhacker/drsh/internal/drshhost"
	"github.com/dmhacker/drsh/internal/drshutil"
	"go.uber.org/zap"
)

type Server struct {
	Host   *drshhost.RedisHost
	Logger *zap.SugaredLogger
}

var ctx = context.Background()

func NewServer(hostname string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Logger: logger,
	}
	hst, err := drshhost.NewRedisHost("se-"+hostname, uri, logger, serv.HandlePacket)
	if err != nil {
		return nil, err
	}
	serv.Host = hst
	return &serv, nil
}

func (serv *Server) HandlePing(sender string) {
	serv.Host.SendPacket(sender, drshcomms.Packet{
		Type:   drshcomms.Packet_SERVER_PING,
		Sender: serv.Host.Hostname,
	})
}

func (serv *Server) HandleHandshake(sender string, key []byte, username string) {
	resp := drshcomms.Packet{
		Type:   drshcomms.Packet_SERVER_HANDSHAKE,
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
		resp.HandshakeMotd = drshutil.Motd() + "Logged in successfully to " + strings.TrimPrefix(serv.Host.Hostname, "se-") + ".\n"
		serv.Host.SendPacket(sender, resp)
		session.Host.FreePrivateKeys()
		session.Host.SetEncryptionEnabled(true)
		session.Start()
	}
}

func (serv *Server) HandlePacket(pckt drshcomms.Packet) {
	switch pckt.GetType() {
	case drshcomms.Packet_CLIENT_PING:
		serv.HandlePing(pckt.GetSender())
	case drshcomms.Packet_CLIENT_HANDSHAKE:
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
