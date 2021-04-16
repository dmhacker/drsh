package host

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astromechza/etcpwdparse"
	"github.com/creack/pty"
	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
)

// Represents the server's view of the connection between it and the client.
// Every session between a server and a client is considered unique. The session piggybacks
// off of the server's own Redis connection so that not as much TCP state has to be maintained.
// In many ways, a session is analogous to an encrypted tunnel in SSH, as the session can only
// be created after a successful key exchange occurring in a handshake. Every session also
// maintains its own pseudoterminal that is controlled by the client.
type Session struct {
	Host                 *RedisHost
	mode                 drshproto.SessionMode
	clientHostname       string
	server               *Server
	lastMessageMutex     sync.Mutex
	lastMessageTimestamp time.Time
	ptyFile              *os.File
	ptyResizeFlag        bool
	transferFile         *os.File
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

// Creates a session given that the server has received necessary information like a
// client's public key and target username.
// It sets up the Redis host, subscribes to the proper channel, assigns a name to the session,
// sets up encryption, and initializes the client's interactive pseudoterminal and/or transfer file.
func (serv *Server) NewSession(clientHostname string, keyPart []byte) (*Session, error) {
	session := Session{
		mode:                 drshproto.SessionMode_MODE_WAITING,
		clientHostname:       clientHostname,
		server:               serv,
		lastMessageTimestamp: time.Now(),
	}
	// Set up session properties & Redis connection
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	session.Host, err = NewChildRedisHost("ss-"+name, serv.Host)
	if err != nil {
		return nil, err
	}
	// Set up shared key through key exchange
	err = session.Host.Encryption.PrepareKeyExchange()
	if err != nil {
		return nil, err
	}
	err = session.Host.Encryption.CompleteKeyExchange(keyPart)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (session *Session) refreshExpiry() {
	session.lastMessageMutex.Lock()
	defer session.lastMessageMutex.Unlock()
	session.lastMessageTimestamp = time.Now()
}

func (session *Session) isExpired() bool {
	session.lastMessageMutex.Lock()
	defer session.lastMessageMutex.Unlock()
	return time.Now().Sub(session.lastMessageTimestamp).Minutes() >= 5
}

func (session *Session) handleHeartbeat() {
	session.Host.SendSessionMessage(session.clientHostname, drshproto.SessionMessage{
		Type:   drshproto.SessionMessage_HEARTBEAT_RESPONSE,
		Sender: session.Host.Hostname,
	})
}

func (session *Session) handlePtyInput(payload []byte) {
	if session.mode != drshproto.SessionMode_MODE_PTY {
		return
	}
	_, err := session.ptyFile.Write(payload)
	if err != nil {
		session.handleExit(err, true)
	}
}

func (session *Session) handlePtyWinch(rows uint16, cols uint16, xpixels uint16, ypixels uint16) {
	if session.mode != drshproto.SessionMode_MODE_PTY {
		return
	}
	pty.Setsize(session.ptyFile, &pty.Winsize{
		Rows: rows,
		Cols: cols,
		X:    xpixels,
		Y:    ypixels,
	})
	// The session only begins broadcasting output after it has received initial terminal dimensions from the client.
	// This has to be done so the output sent between the handshake and initial winch does not appear mangled.
	if !session.ptyResizeFlag {
		go session.startPtyOutputHandler()
	}
	session.ptyResizeFlag = true
}

func (session *Session) handleFileChunk(payload []byte) {
	if session.mode == drshproto.SessionMode_MODE_FILE_UPLOAD && session.transferFile != nil {
		_, err := session.transferFile.Write(payload)
		if err != nil {
			session.handleExit(err, true)
		}
	}
}

func (session *Session) handleFileClose() {
	if session.mode == drshproto.SessionMode_MODE_FILE_UPLOAD && session.transferFile != nil {
		session.handleExit(nil, true)
	}
}

func (session *Session) handleExit(err error, ack bool) {
	if err != nil {
		session.Host.Logger.Infof("'%s' has left session %s: %s.", session.clientHostname, session.Host.Hostname, err.Error())
	} else {
		session.Host.Logger.Infof("'%s' has left session %s.", session.clientHostname, session.Host.Hostname)
	}
	if ack {
		resp := drshproto.SessionMessage{
			Type:       drshproto.SessionMessage_EXIT,
			Sender:     session.Host.Hostname,
			ExitNormal: true,
		}
		if err != nil {
			resp.ExitNormal = false
			resp.ExitError = err.Error()
		}
		session.Host.SendSessionMessage(session.clientHostname, resp)
	}
	session.Close()
}

func (session *Session) handleBootstrap(mode drshproto.SessionMode, username string, filename string) {
	// Session must be waiting in order for the bootstrapping process to begin
	if session.mode != drshproto.SessionMode_MODE_WAITING {
		return
	}
	valid := false
	resp := drshproto.SessionMessage{
		Type:   drshproto.SessionMessage_BOOTSTRAP_RESPONSE,
		Sender: session.Host.Hostname,
	}
	if mode == drshproto.SessionMode_MODE_PTY {
		cmd, err := userShell(username)
		if err != nil {
			session.handleExit(err, true)
			return
		}
		ptmx, err := pty.Start(cmd)
		if err != nil {
			session.handleExit(err, true)
			return
		}
		session.ptyFile = ptmx
		session.ptyResizeFlag = false
		valid = true
		resp.BootstrapMotd = drshutil.Motd() + "Logged in successfully to " + strings.TrimPrefix(session.server.Host.Hostname, "se-") + ".\n"
	} else if mode == drshproto.SessionMode_MODE_FILE_UPLOAD || mode == drshproto.SessionMode_MODE_FILE_DOWNLOAD {
		// Adjust remote filename to be relative to current user's home directory
		// filepath.Abs is relative to the working directory, so the WD needs to be temporarily set
		// to the home directory if the server is run from a subdirectory
		savedWd, err := os.Getwd()
		if err != nil {
			session.handleExit(err, true)
			return
		}
		usr, err := user.Lookup(username)
		if err != nil {
			session.handleExit(err, true)
			return
		}
		err = os.Chdir(usr.HomeDir)
		if err != nil {
			session.handleExit(err, true)
			return
		}
		adjustedFilename, err := filepath.Abs(filename)
		if err != nil {
			session.handleExit(err, true)
			return
		}
		os.Chdir(savedWd)
		// Open file for uploading, downloading depending on mode
		var transferFile *os.File
		if mode == drshproto.SessionMode_MODE_FILE_UPLOAD {
			transferFile, err = os.Create(adjustedFilename)
			if err != nil {
				session.handleExit(err, true)
				return
			}
		} else if mode == drshproto.SessionMode_MODE_FILE_DOWNLOAD {
			transferFile, err = os.Open(adjustedFilename)
			if err != nil {
				session.handleExit(err, true)
				return
			}
		}
		session.transferFile = transferFile
		valid = true
	}
	if valid {
		session.mode = mode
		session.Host.SendSessionMessage(session.clientHostname, resp)
		if session.mode == drshproto.SessionMode_MODE_FILE_DOWNLOAD {
			go session.startFileTransferHandler()
		}
	}
}

func (session *Session) startMessageHandler() {
	for imsg := range session.Host.incomingMessages {
		smsg := imsg.sessionMessage
		if smsg == nil {
			session.Host.Logger.Warnf("Session %s only accepts session messages.", session.Host.Hostname)
			continue
		}
		if smsg.GetSender() != session.clientHostname {
			session.Host.Logger.Warnf("Invalid participant '%s' in session %s.", smsg.GetSender(), session.Host.Hostname)
			continue
		}
		session.refreshExpiry()
		switch smsg.GetType() {
		case drshproto.SessionMessage_HEARTBEAT_REQUEST:
			session.handleHeartbeat()
		case drshproto.SessionMessage_PTY_INPUT:
			session.handlePtyInput(smsg.GetPtyPayload())
		case drshproto.SessionMessage_PTY_WINCH:
			dims := drshutil.Unpack64(smsg.GetPtyDimensions())
			session.handlePtyWinch(dims[0], dims[1], dims[2], dims[3])
		case drshproto.SessionMessage_FILE_CHUNK:
			session.handleFileChunk(smsg.GetFilePayload())
		case drshproto.SessionMessage_FILE_CLOSE:
			session.handleFileClose()
		case drshproto.SessionMessage_EXIT:
			if smsg.ExitNormal {
				session.handleExit(nil, false)
			} else {
				session.handleExit(fmt.Errorf("client refused connection: %s", smsg.ExitError), false)
			}
		case drshproto.SessionMessage_BOOTSTRAP_REQUEST:
			session.handleBootstrap(smsg.GetBootstrapMode(), smsg.GetBootstrapUsername(), smsg.GetBootstrapFilename())
		default:
			session.Host.Logger.Warnf("Received invalid message from '%s'.", smsg.GetSender())
		}
	}
}

func (session *Session) startFileTransferHandler() {
	for {
		if !session.Host.IsOpen() {
			break
		}
		buf := make([]byte, 4096)
		cnt, err := session.transferFile.Read(buf)
		if err != nil {
			if err != io.EOF {
				session.handleExit(err, true)
			} else {
				session.Host.SendSessionMessage(session.clientHostname, drshproto.SessionMessage{
					Type:   drshproto.SessionMessage_FILE_CLOSE,
					Sender: session.Host.Hostname,
				})
			}
			break
		}
		session.Host.SendSessionMessage(session.clientHostname, drshproto.SessionMessage{
			Type:        drshproto.SessionMessage_FILE_CHUNK,
			Sender:      session.Host.Hostname,
			FilePayload: buf[:cnt],
		})
	}
}

func (session *Session) startPtyOutputHandler() {
	for {
		if !session.Host.IsOpen() {
			break
		}
		buf := make([]byte, 4096)
		cnt, err := session.ptyFile.Read(buf)
		if err != nil {
			// Most errors with the pty are non-fatal and just occur when the client hangs up the session
			// They shouldn't actually trigger as an error on the client's side
			session.Host.Logger.Infof("'%s' has experienced pty error in session %s: %s.", session.clientHostname, session.Host.Hostname, err.Error())
			session.handleExit(nil, true)
			break
		}
		session.Host.SendSessionMessage(session.clientHostname, drshproto.SessionMessage{
			Type:       drshproto.SessionMessage_PTY_OUTPUT,
			Sender:     session.Host.Hostname,
			PtyPayload: buf[:cnt],
		})
		// This delay is chosen such that output from the pty is able to
		// buffer, resulting larger messages, more efficient usage of the link,
		// and more responsiveness for interactive applications like top.
		// Too large of a delay would create the perception of lag.
		time.Sleep(10 * time.Millisecond)
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

// Non-blocking function that enables session message processing.
func (session *Session) Start() {
	session.Host.Start()
	go session.startMessageHandler()
	go session.startTimeoutHandler()
	// Ensure that a server can keep track of all of its sessions
	session.server.Sessions.Store(session.Host.Hostname, session)
}

// Performs session cleanup but does not destroy the Redis connection.
func (session *Session) Close() {
	session.ptyFile.Close()
	session.Host.Close()
	if session.transferFile != nil {
		session.transferFile.Close()
	}
	// Make sure closed sessions can be garbage collected
	session.server.Sessions.Delete(session.Host.Hostname)
}
