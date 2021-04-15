package host

import (
	"strings"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
	"go.uber.org/zap"
)

// Represents a host on the network that accepts connections & pings from any clients
// that wish to communicate with it. On a successful handshake with a client, a server will
// spawn a separate "session" through which all communication is encrypted. Because the session
// handles most of the connection legwork, the actual server class is fairly light.
type Server struct {
	Host *RedisHost
}

// NewServer creates a new server and its underlying connection to Redis. It is not actively
// receiving, sending, or processing messages at this point; that is only enabled upon start.
func NewServer(hostname string, uri string, logger *zap.SugaredLogger) (*Server, error) {
	serv := Server{}
	hst, err := NewRedisHost("se-"+hostname, uri, logger)
	if err != nil {
		return nil, err
	}
	serv.Host = hst
	return &serv, nil
}

func (serv *Server) handlePing(sender string) {
	serv.Host.SendPublicMessage(sender, drshproto.PublicMessage{
		Type:   drshproto.PublicMessage_PING_RESPONSE,
		Sender: serv.Host.Hostname,
	})
}

func (serv *Server) handleSession(sender string, keyPart []byte, mode drshproto.SessionMode, username string, filename string) {
	resp := drshproto.PublicMessage{
		Type:   drshproto.PublicMessage_SESSION_RESPONSE,
		Sender: serv.Host.Hostname,
	}
	session, err := NewSession(serv, sender, keyPart, mode, username, filename)
	if err != nil {
		serv.Host.Logger.Warnf("Failed to setup session with '%s': %s", sender, err)
		resp.SessionCreated = false
		resp.SessionError = err.Error()
		serv.Host.SendPublicMessage(sender, resp)
	} else {
		serv.Host.Logger.Infof("'%s' has joined session %s.", sender, session.Host.Hostname)
		resp.SessionCreated = true
		resp.SessionKeyPart = session.Host.Encryption.PrivateKey.Bytes()
		resp.SessionId = session.Host.Hostname
		resp.SessionMotd = drshutil.Motd() + "Logged in successfully to " + strings.TrimPrefix(serv.Host.Hostname, "se-") + " via drsh.\n"
		serv.Host.SendPublicMessage(sender, resp)
		session.Host.Encryption.FreePrivateKeys()
		session.Start()
	}
}

func (serv *Server) startMessageHandler() {
	for imsg := range serv.Host.incomingMessages {
		msg := serv.Host.GetPublicMessage(imsg)
		if msg == nil {
			serv.Host.Logger.Warnf("Server %s only accepts public messages.", serv.Host.Hostname)
			continue
		}
		switch msg.GetType() {
		case drshproto.PublicMessage_PING_REQUEST:
			serv.handlePing(msg.GetSender())
		case drshproto.PublicMessage_SESSION_REQUEST:
			serv.handleSession(msg.GetSender(), msg.GetSessionKeyPart(), msg.GetSessionMode(), msg.GetSessionUser(), msg.GetSessionFilename())
		default:
			serv.Host.Logger.Warnf("Received invalid message from '%s'.", msg.GetSender())
		}
	}
}

// Non-blocking function that enables server message processing.
func (serv *Server) Start() {
	serv.Host.Start()
	go serv.startMessageHandler()
}

// Destroys the server's Redis connection and perform cleanup.
func (serv *Server) Close() {
	serv.Host.Close()
}
