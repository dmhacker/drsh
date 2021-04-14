package host

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/astromechza/etcpwdparse"
	"github.com/creack/pty"
	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
	"go.uber.org/zap"
)

// Session represents the server's view of the connection between it and the client.
// Every session between a server and a client is considered unique. The session piggybacks
// off of the server's own Redis connection so that not as much TCP state has to be maintained.
// In many ways, a session is analogous to an encrypted tunnel in SSH, as the session can only
// be created after a successful key exchange occurring in a handshake. Every session also
// maintains its own pseudoterminal that is controlled by the client.
type Session struct {
	Mode                 drshproto.Message_SessionMode
	Host                 *RedisHost
	Pty                  *os.File
	Logger               *zap.SugaredLogger
	ClientHostname       string
	Resized              bool
	LastMessageMutex     sync.Mutex
	LastMessageTimestamp time.Time
	TransferFile         *os.File
}

func userShell(username string) (*exec.Cmd, error) {
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

// NewSessionFromHandshake creates a session given that the server has received a handshake
// request packet with necessary information like a client's public key and target username.
// It sets up the Redis host, subscribes to the proper channel, assigns a name to the session,
// sets up encryption, and initializes the client's interactive pseudoterminal.
func NewSessionFromHandshake(serv *Server, clnt string, key []byte, username string, mode drshproto.Message_SessionMode, filename string) (*Session, error) {
	// Initialize pseudoterminal
	cmd, err := userShell(username)
	if err != nil {
		return nil, err
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	// Adjust remote filename to be relative to current user's home directory
	// filepath.Abs is relative to the working directory, so the WD needs to be temporarily set
	// to the home directory if the server is run from a subdirectory
	savedWd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	usr, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	err = os.Chdir(usr.HomeDir)
	if err != nil {
		return nil, err
	}
	adjustedFilename, err := filepath.Abs(filename)
	if err != nil {
		os.Chdir(savedWd)
		return nil, err
	}
	os.Chdir(savedWd)

	// Open file for uploading, downloading depending on mode
	var transferFile *os.File
	if mode == drshproto.Message_MODE_FILE_UPLOAD {
		transferFile, err = os.Create(adjustedFilename)
		if err != nil {
			return nil, err
		}
	} else if mode == drshproto.Message_MODE_FILE_DOWNLOAD {
		transferFile, err = os.Open(adjustedFilename)
		if err != nil {
			return nil, err
		}
	} else if mode == drshproto.Message_MODE_TERMINAL {
		transferFile = nil
	} else {
		return nil, fmt.Errorf("invalid session mode")
	}

	// Initialize session
	session := Session{
		Mode:                 mode,
		ClientHostname:       clnt,
		Pty:                  ptmx,
		Logger:               serv.Logger,
		Resized:              false,
		LastMessageTimestamp: time.Now(),
		TransferFile:         transferFile,
	}

	// Set up session properties & Redis connection
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	session.Host, err = NewInheritedRedisHost("ss-"+name, serv.Host.Rdb, serv.Logger, session.handleMessage)
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

func (session *Session) refreshExpiry() {
	session.LastMessageMutex.Lock()
	defer session.LastMessageMutex.Unlock()
	session.LastMessageTimestamp = time.Now()
}

func (session *Session) isExpired() bool {
	session.LastMessageMutex.Lock()
	defer session.LastMessageMutex.Unlock()
	return time.Now().Sub(session.LastMessageTimestamp).Minutes() >= 5
}

func (session *Session) handleHeartbeat() {
	session.Host.SendMessage(session.ClientHostname, drshproto.Message{
		Type:   drshproto.Message_HEARTBEAT_RESPONSE,
		Sender: session.Host.Hostname,
	})
}

func (session *Session) handlePtyInput(payload []byte) {
	if session.Mode != drshproto.Message_MODE_TERMINAL {
		return
	}
	_, err := session.Pty.Write(payload)
	if err != nil {
		session.handleExit(err, true)
	}
}

func (session *Session) handlePtyWinch(rows uint16, cols uint16, xpixels uint16, ypixels uint16) {
	if session.Mode != drshproto.Message_MODE_TERMINAL {
		return
	}
	pty.Setsize(session.Pty, &pty.Winsize{
		Rows: rows,
		Cols: cols,
		X:    xpixels,
		Y:    ypixels,
	})
	// The session only begins broadcasting output after it has received initial terminal dimensions from the client.
	// This has to be done so the output sent between the handshake and initial winch does not appear mangled.
	if !session.Resized {
		go session.startPtyOutputHandler()
	}
	session.Resized = true
}

func (session *Session) handleFileUpload(payload []byte) {
	if session.Mode == drshproto.Message_MODE_FILE_UPLOAD && session.TransferFile != nil {
		_, err := session.TransferFile.Write(payload)
		if err != nil {
			session.handleExit(err, true)
		}
	}
}

func (session *Session) handleFileUploadFinish() {
	if session.Mode == drshproto.Message_MODE_FILE_UPLOAD && session.TransferFile != nil {
		session.handleExit(nil, true)
	}
}

func (session *Session) handleExit(err error, ack bool) {
	if err != nil {
		session.Logger.Infof("'%s' has left session %s: %s.", session.ClientHostname, session.Host.Hostname, err.Error())
	} else {
		session.Logger.Infof("'%s' has left session %s.", session.ClientHostname, session.Host.Hostname)
	}
	if ack {
		session.Host.SendMessage(session.ClientHostname, drshproto.Message{
			Type:   drshproto.Message_EXIT,
			Sender: session.Host.Hostname,
		})
	}
	session.Close()
}

func (session *Session) handleMessage(msg drshproto.Message) {
	if msg.GetSender() != session.ClientHostname {
		session.Logger.Warnf("Invalid participant '%s' in session %s.", msg.GetSender(), session.Host.Hostname)
		return
	}
	session.refreshExpiry()
	switch msg.GetType() {
	case drshproto.Message_HEARTBEAT_REQUEST:
		session.handleHeartbeat()
	case drshproto.Message_PTY_INPUT:
		session.handlePtyInput(msg.GetPtyPayload())
	case drshproto.Message_PTY_WINCH:
		dims := drshutil.Unpack64(msg.GetPtyDimensions())
		session.handlePtyWinch(dims[0], dims[1], dims[2], dims[3])
	case drshproto.Message_FILE_UPLOAD:
		session.handleFileUpload(msg.GetFilePayload())
	case drshproto.Message_FILE_UPLOAD_FINISH:
		session.handleFileUploadFinish()
	case drshproto.Message_EXIT:
		session.handleExit(nil, false)
	default:
		session.Logger.Warnf("Received invalid packet from '%s'.", msg.GetSender())
	}
}

func (session *Session) startPtyOutputHandler() {
	for {
		if !session.Host.IsOpen() {
			break
		}
		buf := make([]byte, 4096)
		cnt, err := session.Pty.Read(buf)
		if err != nil {
			session.handleExit(err, true)
			break
		}
		session.Host.SendMessage(session.ClientHostname, drshproto.Message{
			Type:       drshproto.Message_PTY_OUTPUT,
			Sender:     session.Host.Hostname,
			PtyPayload: buf[:cnt],
		})
		// This delay is chosen such that output from the pty is able to
		// buffer, resulting larger packets, more efficient usage of the link,
		// and more responsiveness for interactive applications like top.
		// Too large of a delay would create the perception of lag.
		time.Sleep(10 * time.Millisecond)
	}
}

func (session *Session) startFileDownloadHandler() {
	for {
		buf := make([]byte, 4096)
		cnt, err := session.TransferFile.Read(buf)
		if err != nil {
			if err != io.EOF {
				session.handleExit(err, true)
			} else {
				session.Host.SendMessage(session.ClientHostname, drshproto.Message{
					Type:   drshproto.Message_FILE_DOWNLOAD_FINISH,
					Sender: session.Host.Hostname,
				})
			}
			break
		}
		session.Host.SendMessage(session.ClientHostname, drshproto.Message{
			Type:        drshproto.Message_FILE_DOWNLOAD,
			Sender:      session.Host.Hostname,
			FilePayload: buf[:cnt],
		})
	}
}

func (session *Session) startTimeoutHandler() {
	for {
		if !session.Host.IsOpen() {
			break
		}
		if session.isExpired() {
			session.handleExit(fmt.Errorf("client timed out"), true)
		}
		time.Sleep(30 * time.Second)
	}
}

// Start is a non-blocking function that enables session packet processing.
func (session *Session) Start() {
	go session.startTimeoutHandler()
	if session.Mode == drshproto.Message_MODE_FILE_DOWNLOAD {
		go session.startFileDownloadHandler()
	}
	session.Host.Start()
}

// Close is called to perform session cleanup but does not destroy the Redis connection.
func (session *Session) Close() {
	session.Pty.Close()
	session.Host.Close()
	if session.TransferFile != nil {
		session.TransferFile.Close()
	}
}
