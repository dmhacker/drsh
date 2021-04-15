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

// Client represents a host on the network who wishes to do something with a specific server,
// whether this is a file-transfer operation, an interactive session, or a series of pings.
type Client struct {
	Host                 *RedisHost
	rawRemoteHostname    string
	remoteUsername       string
	remoteHostname       string
	connectedFlag        bool
	connectedSession     string
	pinged               chan pingResponse
	connected            chan bool
	finished             chan bool
	transferFile         *os.File
	displayMotd          bool
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
		connected:            make(chan bool, 1),
		finished:             make(chan bool, 1),
		pinged:               make(chan pingResponse, 1),
		transferFile:         nil,
		displayMotd:          false,
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
	clnt.pinged <- pingResponse{
		sender:   sender,
		size:     size,
		recvTime: time.Now(),
	}
}

func (clnt *Client) handleSession(sender string, success bool, err string, keyPart []byte, session string, motd string) {
	if !success {
		clnt.handleExit(fmt.Errorf("server refused connection: %s", err), false)
		return
	}
	if !clnt.connectedFlag && sender == clnt.remoteHostname {
		err := clnt.Host.Encryption.CompleteKeyExchange(keyPart)
		if err != nil {
			clnt.handleExit(err, false)
			return
		}
		clnt.Host.Encryption.FreePrivateKeys()
		if clnt.displayMotd {
			fmt.Print(motd)
		}
		clnt.connectedFlag = true
		clnt.connectedSession = session
		clnt.connected <- true
	}
}

func (clnt *Client) handlePtyOutput(sender string, payload []byte) {
	if clnt.connectedFlag && sender == clnt.connectedSession {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleFileTransfer(sender string, payload []byte) {
	if clnt.connectedFlag && sender == clnt.connectedSession && clnt.transferFile != nil {
		_, err := clnt.transferFile.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleFileTransferFinish(sender string) {
	if clnt.connectedFlag && sender == clnt.connectedSession && clnt.transferFile != nil {
		clnt.handleExit(nil, true)
	}
}

func (clnt *Client) handleExit(err error, ack bool) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
	}
	if clnt.connectedFlag {
		if ack {
			clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
				Type:   drshproto.SessionMessage_EXIT,
				Sender: clnt.Host.Hostname,
			})
			// Add a slight delay so the exit message can send
			time.Sleep(100 * time.Millisecond)
		}
		clnt.finished <- true
	} else {
		os.Exit(1)
	}
}

func (clnt *Client) startMessageHandler() {
	for imsg := range clnt.Host.incomingMessages {
		pmsg := clnt.Host.GetPublicMessage(imsg)
		smsg, err := clnt.Host.GetSessionMessage(imsg)
		if err != nil {
			clnt.Host.Logger.Warnf("Error receiving message: %s", err)
			continue
		}
		if pmsg != nil {
			switch pmsg.GetType() {
			case drshproto.PublicMessage_PING_RESPONSE:
				clnt.handlePing(pmsg.GetSender(), proto.Size(pmsg))
			case drshproto.PublicMessage_SESSION_RESPONSE:
				clnt.handleSession(pmsg.GetSender(), pmsg.GetSessionCreated(), pmsg.GetSessionError(), pmsg.GetSessionKeyPart(), pmsg.GetSessionId(), pmsg.GetSessionMotd())
			default:
				clnt.Host.Logger.Warnf("Received invalid message from '%s'.", pmsg.GetSender())
			}
		} else if smsg != nil {
			clnt.refreshExpiry()
			switch smsg.GetType() {
			case drshproto.SessionMessage_HEARTBEAT_SERVER:
				// Heartbeats don't require any processing other than timestamping
			case drshproto.SessionMessage_PTY_OUTPUT:
				clnt.handlePtyOutput(smsg.GetSender(), smsg.GetPtyPayload())
			case drshproto.SessionMessage_FILE_TRANSFER:
				clnt.handleFileTransfer(smsg.GetSender(), smsg.GetFilePayload())
			case drshproto.SessionMessage_FILE_TRANSFER_FINISH:
				clnt.handleFileTransferFinish(smsg.GetSender())
			case drshproto.SessionMessage_EXIT:
				clnt.handleExit(nil, false)
			default:
				clnt.Host.Logger.Warnf("Received invalid message from '%s'.", smsg.GetSender())
			}
		}

	}
}

func (clnt *Client) connect(mode drshproto.SessionMode, filename string) {
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
		Type:            drshproto.PublicMessage_SESSION_REQUEST,
		Sender:          clnt.Host.Hostname,
		SessionKeyPart:  clnt.Host.Encryption.PrivateKey.Bytes(),
		SessionMode:     mode,
		SessionUser:     clnt.remoteUsername,
		SessionFilename: filename,
	})
	// Wait until we have received a handshake response from the server
	// This will put us into our own server session
	<-clnt.connected
}

// UploadFile uploads a file to the remote server.
func (clnt *Client) UploadFile(localFilename string, remoteFilename string) {
	// Open file for reading
	transferFile, err := os.Open(localFilename)
	if err != nil {
		clnt.handleExit(fmt.Errorf("cannot open file '%s'", localFilename), true)
		return
	}
	clnt.transferFile = transferFile
	defer clnt.transferFile.Close()
	clnt.displayMotd = false
	// Establish secure connection to the server
	clnt.connect(drshproto.SessionMode_MODE_FILE_UPLOAD, remoteFilename)
	// Read from local file, break into chunks, and send each one individually
	go (func() {
		for {
			buf := make([]byte, 4096)
			cnt, err := clnt.transferFile.Read(buf)
			if err != nil {
				if err != io.EOF {
					clnt.handleExit(err, true)
				} else {
					clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
						Type:   drshproto.SessionMessage_FILE_TRANSFER_FINISH,
						Sender: clnt.Host.Hostname,
					})
				}
				break
			}
			clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
				Type:        drshproto.SessionMessage_FILE_TRANSFER,
				Sender:      clnt.Host.Hostname,
				FilePayload: buf[:cnt],
			})
		}
	})()
	// Finished channel will be triggered on error or by the server due to completion
	<-clnt.finished
	fmt.Printf("File '%s' was uploaded to '%s@%s' as '%s'.\n", localFilename, clnt.remoteUsername, clnt.rawRemoteHostname, remoteFilename)
}

// DownloadFile downloads a file from the remote server.
func (clnt *Client) DownloadFile(remoteFilename string, localFilename string) {
	// Open file for writing
	transferFile, err := os.Create(localFilename)
	if err != nil {
		clnt.handleExit(fmt.Errorf("cannot create file '%s'", localFilename), true)
		return
	}
	clnt.transferFile = transferFile
	defer clnt.transferFile.Close()
	clnt.displayMotd = false
	// Establish secure connection to the server
	clnt.connect(drshproto.SessionMode_MODE_FILE_DOWNLOAD, remoteFilename)
	// Finished channel will be triggered on error or server exit due to completion
	<-clnt.finished
	fmt.Printf("File '%s' was downloaded from '%s@%s' to '%s'.\n", remoteFilename, clnt.remoteUsername, clnt.rawRemoteHostname, localFilename)
}

// LoginInteractively is a blocking function that facilitates an interactive session with its server.
func (clnt *Client) LoginInteractively() {
	clnt.displayMotd = true
	clnt.connect(drshproto.SessionMode_MODE_PTY, "")
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
			clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
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
			clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
				Type:       drshproto.SessionMessage_PTY_INPUT,
				Sender:     clnt.Host.Hostname,
				PtyPayload: buf[:cnt],
			})
		}
	})()
	// Keepalive routine sends messages every so often to keep connection alive
	go (func() {
		for {
			clnt.Host.SendSessionMessage(clnt.connectedSession, drshproto.SessionMessage{
				Type:   drshproto.SessionMessage_HEARTBEAT_CLIENT,
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
	// Wait until at least one thread messages the finished channel
	<-clnt.finished
	fmt.Printf("Connection to %s closed.\n", clnt.rawRemoteHostname)
}

// Ping is a blocking function that streams an infinite series of pings to the server,
// until it receives an interrupt from the user.
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
			resp = <-clnt.pinged
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
