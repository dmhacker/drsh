package drshserver

import (
	"context"
	"strings"

	"github.com/dmhacker/drsh/internal/drshhost"
	"github.com/dmhacker/drsh/internal/drshproto"
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
	hst, err := drshhost.NewRedisHost("se-"+hostname, uri, logger, serv.handleMessage)
	if err != nil {
		return nil, err
	}
	serv.Host = hst
	return &serv, nil
}

func (serv *Server) handlePing(sender string) {
	serv.Host.SendMessage(sender, drshproto.Message{
		Type:   drshproto.Message_PING_RESPONSE,
		Sender: serv.Host.Hostname,
	})
}

func (serv *Server) handleHandshake(sender string, key []byte, username string) {
	resp := drshproto.Message{
		Type:   drshproto.Message_HANDSHAKE_RESPONSE,
		Sender: serv.Host.Hostname,
	}
	session, err := NewSessionFromHandshake(serv, sender, key, username)
	if err != nil {
		serv.Logger.Warnf("Failed to setup session with '%s': %s", sender, err)
		resp.HandshakeSuccess = false
		serv.Host.SendMessage(sender, resp)
	} else {
		serv.Logger.Infof("'%s' has joined session %s.", sender, session.Host.Hostname)
		resp.HandshakeSuccess = true
		resp.HandshakeKey = session.Host.KXPrivateKey.Bytes()
		resp.HandshakeSession = session.Host.Hostname
		resp.HandshakeMotd = drshutil.Motd() + "Logged in successfully to " + strings.TrimPrefix(serv.Host.Hostname, "se-") + " via drsh.\n"
		serv.Host.SendMessage(sender, resp)
		session.Host.FreePrivateKeys()
		session.Host.SetEncryptionEnabled(true)
		session.Start()
	}
}

func (serv *Server) handleMessage(msg drshproto.Message) {
	switch msg.GetType() {
	case drshproto.Message_PING_REQUEST:
		serv.handlePing(msg.GetSender())
	case drshproto.Message_HANDSHAKE_REQUEST:
		serv.handleHandshake(msg.GetSender(), msg.GetHandshakeKey(), msg.GetHandshakeUser())
	default:
		serv.Logger.Warnf("Received invalid packet from '%s'.", msg.GetSender())
	}
}

func (serv *Server) Start() {
	serv.Host.Start()
}

func (serv *Server) Close() {
	serv.Host.Close()
}
