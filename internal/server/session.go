package server

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/astromechza/etcpwdparse"
	"github.com/creack/pty"
	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/host"
	"github.com/dmhacker/drsh/internal/util"
	"go.uber.org/zap"
)

type Session struct {
	Host                *host.RedisHost
	Pty                 *os.File
	LastPacketMutex     sync.Mutex
	LastPacketTimestamp time.Time
	Logger              *zap.SugaredLogger
	Client              string
	Resized             bool
	Finished            chan bool
}

func NewSessionFromHandshake(serv *Server, clnt string, key []byte) (*Session, error) {
	// Set up interactive pseudoterminal
	// TODO: Client will decide which user is run in the future
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, err
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		return nil, err
	}
	entry, _ := cache.LookupUserByUid(uid)
	shell := entry.Shell()
	cmd := exec.Command(shell)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	// Initialize session
	session := Session{
		Client:              clnt,
		Pty:                 ptmx,
		LastPacketTimestamp: time.Now(),
		Logger:              serv.Logger,
		Resized:             false,
	}

	// Set up session properties & Redis connection
	name, err := util.RandomName()
	if err != nil {
		return nil, err
	}
	session.Host, err = host.InheritRedisHost("server-session", name, serv.Host.Rdb, serv.Logger, session.HandlePacket)
	if err != nil {
		return nil, err
	}

	// Set up shared key through key exchange
	err = session.Host.PrepareKeyExchange()
	if err != nil {
		return nil, err
	}
	err = session.Host.CompleteKeyExchange(key)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (session *Session) RefreshExpiry() {
	session.LastPacketMutex.Lock()
	defer session.LastPacketMutex.Unlock()
	session.LastPacketTimestamp = time.Now()
}

func (session *Session) IsExpired() bool {
	session.LastPacketMutex.Lock()
	defer session.LastPacketMutex.Unlock()
	return time.Now().Sub(session.LastPacketTimestamp).Minutes() >= 10
}

func (session *Session) HandleOutput(payload []byte) {
	_, err := session.Pty.Write(payload)
	if err != nil {
		session.HandleExit(err, true)
	}
}

func (session *Session) HandlePty(rows uint16, cols uint16, xpixels uint16, ypixels uint16) {
	pty.Setsize(session.Pty, &pty.Winsize{
		Rows: rows,
		Cols: cols,
		X:    xpixels,
		Y:    ypixels,
	})
	if !session.Resized {
		go session.StartOutputHandler()
	}
	session.Resized = true
}

func (session *Session) HandleExit(err error, ack bool) {
	// Send an acknowledgement back to the client to indicate that we have
	// closed the session on the server's end
	if ack {
		session.Host.SendPacket(host.DirectedPacket{
			Category:  "client",
			Recipient: session.Client,
			Packet: comms.Packet{
				Type:   comms.Packet_SERVER_EXIT,
				Sender: session.Host.Hostname,
			},
		})
	}
	if err != nil {
		session.Logger.Infof("'%s' has left session %s: %s.", session.Client, session.Host.Hostname, err.Error())
	} else {
		session.Logger.Infof("'%s' has left session %s.", session.Client, session.Host.Hostname)
	}
	session.Finished <- true
}

func (session *Session) HandlePacket(dirpckt host.DirectedPacket) {
	sender := dirpckt.Packet.GetSender()
	if sender != session.Client {
		session.Logger.Errorf("Invalid participant in session '%s'.", sender)
		return
	}
	session.RefreshExpiry()
	switch dirpckt.Packet.GetType() {
	case comms.Packet_CLIENT_OUTPUT:
		session.HandleOutput(dirpckt.Packet.GetPayload())
	case comms.Packet_CLIENT_PTY_WINCH:
		dims := util.Unpack64(dirpckt.Packet.GetPtyDimensions())
		session.HandlePty(dims[0], dims[1], dims[2], dims[3])
	case comms.Packet_CLIENT_EXIT:
		session.HandleExit(nil, false)
	default:
		session.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (session *Session) StartOutputHandler() {
	for {
		buf := make([]byte, 4096)
		cnt, err := session.Pty.Read(buf)
		if err != nil {
			session.HandleExit(err, true)
			break
		}
		session.Host.SendPacket(host.DirectedPacket{
			Category:  "client",
			Recipient: session.Client,
			Packet: comms.Packet{
				Type:    comms.Packet_SERVER_OUTPUT,
				Sender:  session.Host.Hostname,
				Payload: buf[:cnt],
			},
		})
		// This delay is chosen such that output from the pty is able to
		// buffer, resulting larger packets, more efficient usage of the link,
		// and more responsiveness for interactive applications like top.
		// Too large of a delay would create the perception of lag.
		time.Sleep(10 * time.Millisecond)
	}
}

func (session *Session) StartTimeoutHandler() {
	for {
		if session.IsExpired() {
			session.HandleExit(fmt.Errorf("client timed out"), true)
		}
		time.Sleep(30 * time.Second)
	}
}

func (session *Session) Start() {
	go session.StartTimeoutHandler()
	session.Host.Start()
	<-session.Finished
}

func (session *Session) Close() {
	session.Host.Rps.Close()
	session.Pty.Close()
}
