package host

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	drshproto "github.com/dmhacker/drsh/internal/drsh/proto"
	drshutil "github.com/dmhacker/drsh/internal/drsh/util"
	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"
	"golang.org/x/term"
)

type pingResponse struct {
	sender   string
	size     int
	recvTime time.Time
}

type sessionControlEvent struct {
	exitFlag  bool
	exitError error
}

// Client represents a host on the network who wishes to do something with a specific server,
// whether this is a file-transfer operation, an interactive session, or a series of pings.
type Client struct {
	Host                 *RedisHost
	rawRemoteHostname    string
	remoteUsername       string
	remoteHostname       string
	pingResponses        chan pingResponse
	sessionHostname      string
	sessionOnline        bool
	sessionMode          drshproto.SessionMode
	sessionProposedMode  drshproto.SessionMode
	sessionControl       chan sessionControlEvent
	transferFile         *os.File
	lastMessageMutex     sync.Mutex
	lastMessageTimestamp time.Time
}

// NewClient creates a new client and its underlying connection to Redis. It is not actively
// receiving, sending, or processing messages at this point; that is only enabled upon start.
func NewClient(username string, hostname string, uri string, logger *zap.SugaredLogger) (*Client, error) {
	clnt := Client{
		rawRemoteHostname:    hostname,
		remoteUsername:       username,
		remoteHostname:       "se-" + hostname,
		pingResponses:        make(chan pingResponse, 1),
		sessionMode:          drshproto.SessionMode_MODE_WAITING,
		sessionProposedMode:  drshproto.SessionMode_MODE_WAITING,
		sessionOnline:        false,
		sessionControl:       make(chan sessionControlEvent, 1),
		transferFile:         nil,
		lastMessageTimestamp: time.Now(),
	}
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	clnt.Host, err = NewRedisHost("cl-"+name, uri, logger)
	if err != nil {
		return nil, err
	}
	return &clnt, nil
}

func (clnt *Client) refreshExpiry() {
	clnt.lastMessageMutex.Lock()
	defer clnt.lastMessageMutex.Unlock()
	clnt.lastMessageTimestamp = time.Now()
}

func (clnt *Client) isExpired() bool {
	clnt.lastMessageMutex.Lock()
	defer clnt.lastMessageMutex.Unlock()
	return time.Now().Sub(clnt.lastMessageTimestamp).Minutes() >= 5
}

func (clnt *Client) handlePing(sender string, size int) {
	clnt.pingResponses <- pingResponse{
		sender:   sender,
		size:     size,
		recvTime: time.Now(),
	}
}

func (clnt *Client) handleSession(sender string, success bool, err string, keyPart []byte, sessionHostname string) {
	if !success {
		clnt.handleExit(fmt.Errorf("server refused connection: %s", err), false)
		return
	}
	if !clnt.sessionOnline && sender == clnt.remoteHostname {
		err := clnt.Host.Encryption.CompleteKeyExchange(keyPart)
		if err != nil {
			clnt.handleExit(err, false)
			return
		}
		clnt.Host.Encryption.FreePrivateKeys()
		clnt.sessionHostname = sessionHostname
		clnt.sessionOnline = true
		clnt.sessionControl <- sessionControlEvent{
			exitFlag:  false,
			exitError: nil,
		}
	}
}

func (clnt *Client) handleBootstrap(sender string, motd string) {
	if clnt.sessionMode == drshproto.SessionMode_MODE_WAITING && sender == clnt.sessionHostname {
		fmt.Print(motd)
		clnt.sessionMode = clnt.sessionProposedMode
		clnt.sessionControl <- sessionControlEvent{
			exitFlag:  false,
			exitError: nil,
		}
	}
}

func (clnt *Client) handlePtyOutput(sender string, payload []byte) {
	if clnt.sessionMode == drshproto.SessionMode_MODE_PTY && sender == clnt.sessionHostname {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleFileChunk(sender string, payload []byte) {
	if clnt.sessionMode == drshproto.SessionMode_MODE_FILE_DOWNLOAD && sender == clnt.sessionHostname && clnt.transferFile != nil {
		_, err := clnt.transferFile.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleFileClose(sender string) {
	if clnt.sessionMode == drshproto.SessionMode_MODE_FILE_DOWNLOAD && sender == clnt.sessionHostname && clnt.transferFile != nil {
		clnt.handleExit(nil, true)
	}
}

func (clnt *Client) handleExit(err error, ack bool) {
	if ack {
		resp := drshproto.SessionMessage{
			Type:       drshproto.SessionMessage_EXIT,
			Sender:     clnt.Host.Hostname,
			ExitNormal: true,
		}
		if err != nil {
			resp.ExitNormal = false
			resp.ExitError = err.Error()
		}
		clnt.Host.SendSessionMessage(clnt.sessionHostname, resp)
		// Add a slight delay so the exit message can send before the client quits
		time.Sleep(100 * time.Millisecond)
	}
	clnt.sessionControl <- sessionControlEvent{
		exitFlag:  true,
		exitError: err,
	}
}

func (clnt *Client) startMessageHandler() {
	for imsg := range clnt.Host.incomingMessages {
		pmsg := clnt.Host.GetPublicMessage(imsg)
		smsg, err := clnt.Host.GetSessionMessage(imsg)
		if err != nil {
			clnt.Host.Logger.Warnf("Error handling message: %s", err)
			continue
		}
		if pmsg != nil {
			switch pmsg.GetType() {
			case drshproto.PublicMessage_PING_RESPONSE:
				clnt.handlePing(pmsg.GetSender(), proto.Size(pmsg))
			case drshproto.PublicMessage_SESSION_RESPONSE:
				clnt.handleSession(pmsg.GetSender(), pmsg.GetSessionCreated(), pmsg.GetSessionError(), pmsg.GetSessionKeyPart(), pmsg.GetSessionHostname())
			default:
				clnt.Host.Logger.Warnf("Received invalid message from '%s'.", pmsg.GetSender())
			}
		} else if smsg != nil {
			clnt.refreshExpiry()
			switch smsg.GetType() {
			case drshproto.SessionMessage_HEARTBEAT_RESPONSE:
				// Heartbeats don't require any processing
			case drshproto.SessionMessage_PTY_OUTPUT:
				clnt.handlePtyOutput(smsg.GetSender(), smsg.GetPtyPayload())
			case drshproto.SessionMessage_FILE_CHUNK:
				clnt.handleFileChunk(smsg.GetSender(), smsg.GetFilePayload())
			case drshproto.SessionMessage_FILE_CLOSE:
				clnt.handleFileClose(smsg.GetSender())
			case drshproto.SessionMessage_EXIT:
				if smsg.ExitNormal {
					clnt.handleExit(nil, false)
				} else {
					clnt.handleExit(fmt.Errorf("server refused connection: %s", smsg.ExitError), false)
				}
			case drshproto.SessionMessage_BOOTSTRAP_RESPONSE:
				clnt.handleBootstrap(smsg.GetSender(), smsg.GetBootstrapMotd())
			default:
				clnt.Host.Logger.Warnf("Received invalid message from '%s'.", smsg.GetSender())
			}
		}

	}
}

func (clnt *Client) startSession() {
	if !clnt.Host.IsListening(clnt.remoteHostname) {
		clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.rawRemoteHostname), false)
		return
	}
	// Send handshake request to the server
	err := clnt.Host.Encryption.PrepareKeyExchange()
	if err != nil {
		clnt.handleExit(err, false)
		return
	}
	clnt.Host.SendPublicMessage(clnt.remoteHostname, drshproto.PublicMessage{
		Type:           drshproto.PublicMessage_SESSION_REQUEST,
		Sender:         clnt.Host.Hostname,
		SessionKeyPart: clnt.Host.Encryption.PrivateKey.Bytes(),
	})
}

func (clnt *Client) configureSession(mode drshproto.SessionMode, filename string) {
	clnt.sessionProposedMode = mode
	clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
		Type:              drshproto.SessionMessage_BOOTSTRAP_REQUEST,
		Sender:            clnt.Host.Hostname,
		BootstrapMode:     mode,
		BootstrapUsername: clnt.remoteUsername,
		BootstrapFilename: filename,
	})
}

// Uploads a file to the remote server.
func (clnt *Client) UploadFile(localFilename string, remoteFilename string) error {
	// Open file for reading
	transferFile, err := os.Open(localFilename)
	if err != nil {
		return err
	}
	clnt.transferFile = transferFile
	defer clnt.transferFile.Close()
	// Establish secure connection to the server
	clnt.startSession()
	control := <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	clnt.configureSession(drshproto.SessionMode_MODE_FILE_UPLOAD, remoteFilename)
	control = <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	// Read from local file, break into chunks, and send each one individually
	go (func() {
		for {
			buf := make([]byte, 4096)
			cnt, err := clnt.transferFile.Read(buf)
			if err != nil {
				if err != io.EOF {
					clnt.handleExit(err, true)
				} else {
					clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
						Type:   drshproto.SessionMessage_FILE_CLOSE,
						Sender: clnt.Host.Hostname,
					})
				}
				break
			}
			clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
				Type:        drshproto.SessionMessage_FILE_CHUNK,
				Sender:      clnt.Host.Hostname,
				FilePayload: buf[:cnt],
			})
		}
	})()
	// Wait for some signal that the session should end
	control = <-clnt.sessionControl
	return control.exitError
}

// Downloads a file from the remote server.
func (clnt *Client) DownloadFile(remoteFilename string, localFilename string) error {
	// Open file for writing
	transferFile, err := os.Create(localFilename)
	if err != nil {
		return err
	}
	clnt.transferFile = transferFile
	defer clnt.transferFile.Close()
	// Establish secure connection to the server
	clnt.startSession()
	control := <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	clnt.configureSession(drshproto.SessionMode_MODE_FILE_DOWNLOAD, remoteFilename)
	control = <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	// Wait for some signal that the session should end
	control = <-clnt.sessionControl
	return control.exitError
}

// Creates an interactive session with its server.
func (clnt *Client) LoginInteractively() error {
	// Establish secure connection to the server
	clnt.startSession()
	control := <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	clnt.configureSession(drshproto.SessionMode_MODE_PTY, "")
	control = <-clnt.sessionControl
	if control.exitFlag {
		return control.exitError
	}
	// Capture SIGWINCH signals
	winchChan := make(chan os.Signal)
	signal.Notify(winchChan, syscall.SIGWINCH)
	go (func() {
		for range winchChan {
			ws, err := drshutil.TerminalSize()
			if err != nil {
				clnt.handleExit(err, true)
				break
			}
			clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
				Type:          drshproto.SessionMessage_PTY_WINCH,
				Sender:        clnt.Host.Hostname,
				PtyDimensions: drshutil.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
			})
		}
	})()
	winchChan <- syscall.SIGWINCH
	// Capture input and send to server
	go (func() {
		for {
			buf := make([]byte, 4096)
			cnt, err := os.Stdin.Read(buf)
			if err != nil {
				clnt.handleExit(err, true)
				break
			}
			clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
				Type:       drshproto.SessionMessage_PTY_INPUT,
				Sender:     clnt.Host.Hostname,
				PtyPayload: buf[:cnt],
			})
		}
	})()
	// Keepalive routine sends messages every so often to keep connection alive
	go (func() {
		for {
			clnt.Host.SendSessionMessage(clnt.sessionHostname, drshproto.SessionMessage{
				Type:   drshproto.SessionMessage_HEARTBEAT_REQUEST,
				Sender: clnt.Host.Hostname,
			})
			time.Sleep(60 * time.Second)
		}
	})()
	// Put the current tty into raw mode and revert on exit
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		clnt.handleExit(err, false)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	// Wait for some signal that the session should end
	control = <-clnt.sessionControl
	return control.exitError
}

// Sends an infinite series of pings to the server until it receives an interrupt from the user.
func (clnt *Client) Ping() {
	if !clnt.Host.IsListening(clnt.remoteHostname) {
		clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.rawRemoteHostname), false)
		return
	}
	start := time.Now()
	msg := drshproto.PublicMessage{
		Type:   drshproto.PublicMessage_PING_REQUEST,
		Sender: clnt.Host.Hostname,
	}
	intr := make(chan os.Signal, 1)
	signal.Notify(intr, os.Interrupt)
	sentCnt := 0
	recvCnt := 0
	minDuration := time.Now().Sub(time.Now())
	maxDuration := minDuration
	first := true
	go func() {
		for range intr {
			loss := (sentCnt - recvCnt) * 100 / sentCnt
			totalDuration := time.Now().Sub(start)
			fmt.Printf("\n--- %s ping statistics ---\n", clnt.rawRemoteHostname)
			fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %s\n", sentCnt, recvCnt, loss, totalDuration)
			fmt.Printf("rtt min/max %s/%s\n", minDuration, maxDuration)
			os.Exit(0)
		}
	}()
	fmt.Printf("PING %s %d data bytes\n", clnt.rawRemoteHostname, proto.Size(&msg))
	for {
		if !clnt.Host.IsListening(clnt.remoteHostname) {
			clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.rawRemoteHostname), false)
			break
		}
		sentTime := time.Now()
		clnt.Host.SendPublicMessage(clnt.remoteHostname, msg)
		sentCnt++
		var resp pingResponse
		for {
			resp = <-clnt.pingResponses
			if resp.sender == clnt.remoteHostname {
				break
			}
		}
		recvCnt++
		recvDuration := resp.recvTime.Sub(sentTime)
		if recvDuration < minDuration || first {
			minDuration = recvDuration
		}
		if recvDuration > maxDuration || first {
			maxDuration = recvDuration
		}
		first = false
		fmt.Printf("%d bytes from %s: time=%s\n", resp.size, clnt.rawRemoteHostname, recvDuration)
		time.Sleep(1 * time.Second)
	}
}

func (clnt *Client) startTimeoutHandler() {
	for {
		if !clnt.Host.IsOpen() {
			break
		}
		if clnt.isExpired() {
			clnt.handleExit(fmt.Errorf("server timed out"), true)
			break
		}
		time.Sleep(30 * time.Second)
	}
}

// Start is a non-blocking function that enables client message processing.
func (clnt *Client) Start() {
	clnt.Host.Start()
	go clnt.startTimeoutHandler()
	go clnt.startMessageHandler()
}

// Close is called to destroy the client's Redis connection and perform cleanup.
func (clnt *Client) Close() {
	clnt.Host.Close()
}
