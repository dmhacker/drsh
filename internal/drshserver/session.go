package drshserver

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
	"github.com/dmhacker/drsh/internal/drshcomms"
	"github.com/dmhacker/drsh/internal/drshhost"
	"github.com/dmhacker/drsh/internal/drshutil"
	"go.uber.org/zap"
)

type Session struct {
	Host                *drshhost.RedisHost
	Pty                 *os.File
	Logger              *zap.SugaredLogger
	Client              string
	Resized             bool
	LastPacketMutex     sync.Mutex
	LastPacketTimestamp time.Time
}

func GetShellCommand(username string) (*exec.Cmd, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	uid64, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	uid := int(uid64)
	if uid == 0 {
		return nil, fmt.Errorf("logins as root are prohibited")
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		return nil, err
	}
	entry, _ := cache.LookupUserByUid(int(uid))
	shell := entry.Shell()
	// There are issues with setuid, setreuid in Golang ...
	return exec.Command("sudo", "-u", username, shell, "-l"), nil
}

func NewSessionFromHandshake(serv *Server, clnt string, key []byte, username string) (*Session, error) {
	// Initialize pseudoterminal
	cmd, err := GetShellCommand(username)
	if err != nil {
		return nil, err
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	// Initialize session
	session := Session{
		Client:              clnt,
		Pty:                 ptmx,
		Logger:              serv.Logger,
		Resized:             false,
		LastPacketTimestamp: time.Now(),
	}

	// Set up session properties & Redis connection
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	session.Host, err = drshhost.InheritRedisHost("ss-"+name, serv.Host.Rdb, serv.Logger, session.HandlePacket)
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
	return time.Now().Sub(session.LastPacketTimestamp).Minutes() >= 5
}

func (session *Session) HandleOutput(payload []byte) {
	_, err := session.Pty.Write(payload)
	if err != nil {
		session.HandleExit(err, true)
	}
}

func (session *Session) HandleHeartbeat() {
	session.Host.SendPacket(session.Client, drshcomms.Packet{
		Type:   drshcomms.Packet_SERVER_HEARTBEAT,
		Sender: session.Host.Hostname,
	})
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
	if err != nil {
		session.Logger.Infof("'%s' has left session %s: %s.", session.Client, session.Host.Hostname, err.Error())
	} else {
		session.Logger.Infof("'%s' has left session %s.", session.Client, session.Host.Hostname)
	}
	if ack {
		session.Host.SendPacket(session.Client, drshcomms.Packet{
			Type:   drshcomms.Packet_SERVER_EXIT,
			Sender: session.Host.Hostname,
		})
	}
	session.Close()
}

func (session *Session) HandlePacket(pckt drshcomms.Packet) {
	if pckt.GetSender() != session.Client {
		session.Logger.Warnf("Invalid participant '%s' in session %s.", pckt.GetSender(), session.Host.Hostname)
		return
	}
	session.RefreshExpiry()
	switch pckt.GetType() {
	case drshcomms.Packet_CLIENT_HEARTBEAT:
		session.HandleHeartbeat()
	case drshcomms.Packet_CLIENT_OUTPUT:
		session.HandleOutput(pckt.GetPayload())
	case drshcomms.Packet_CLIENT_PTY_WINCH:
		dims := drshutil.Unpack64(pckt.GetPtyDimensions())
		session.HandlePty(dims[0], dims[1], dims[2], dims[3])
	case drshcomms.Packet_CLIENT_EXIT:
		session.HandleExit(nil, false)
	default:
		session.Logger.Warnf("Received invalid packet from '%s'.", pckt.GetSender())
	}
}

func (session *Session) StartOutputHandler() {
	for {
		if !session.Host.IsOpen() {
			break
		}
		buf := make([]byte, 4096)
		cnt, err := session.Pty.Read(buf)
		if err != nil {
			session.HandleExit(err, true)
			break
		}
		session.Host.SendPacket(session.Client, drshcomms.Packet{
			Type:    drshcomms.Packet_SERVER_OUTPUT,
			Sender:  session.Host.Hostname,
			Payload: buf[:cnt],
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
		if !session.Host.IsOpen() {
			break
		}
		if session.IsExpired() {
			session.HandleExit(fmt.Errorf("client timed out"), true)
		}
		time.Sleep(30 * time.Second)
	}
}

func (session *Session) Start() {
	go session.StartTimeoutHandler()
	session.Host.Start()
}

func (session *Session) Close() {
	session.Pty.Close()
	session.Host.Close()
}
