package host

import (
	"strings"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
	"go.uber.org/zap"
)

// Server represents a host on the network that accepts connections & pings from any clients
// that wish to communicate with it. On a successful handshake with a client, a server will
// spawn a separate "session" through which all communication is encrypted. Because the session
// handles most of the connection legwork, the actual server class is fairly light.
type Server struct {
	Host   *RedisHost
	Logger *zap.SugaredLogger
}

// NewServer creates a new server and its underlying connection to Redis. It is not actively
// receiving and sending packets at this point; that is only enabled upon start.
func NewServer(hostname string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{
		Logger: logger,
	}
	hst, err := NewRedisHost("se-"+hostname, uri, logger, serv.handleMessage)
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

func (serv *Server) handleHandshake(sender string, key []byte, username string, mode drshproto.Message_SessionMode, filename string) {
	resp := drshproto.Message{
		Type:   drshproto.Message_HANDSHAKE_RESPONSE,
		Sender: serv.Host.Hostname,
	}
	session, err := NewSessionFromHandshake(serv, sender, key, username, mode, filename)
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
		serv.handleHandshake(msg.GetSender(), msg.GetHandshakeKey(), msg.GetHandshakeUser(), msg.GetHandshakeMode(), msg.GetHandshakeFilename())
	default:
		serv.Logger.Warnf("Received invalid packet from '%s'.", msg.GetSender())
	}
}

// Start is a non-blocking function that enables server packet processing.
func (serv *Server) Start() {
	serv.Host.Start()
}

// Close is called to destroy the server's Redis connection and perform cleanup.
func (serv *Server) Close() {
	serv.Host.Close()
}