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
	Sender   string
	Size     int
	RecvTime time.Time
}

// Client represents a host on the network who wishes to do something with a specific server,
// whether this is a file-transfer operation, an interactive session, or a series of pings.
type Client struct {
	Host                 *RedisHost
	Logger               *zap.SugaredLogger
	RawHostname          string
	RemoteUsername       string
	RemoteHostname       string
	LastMessageMutex     sync.Mutex
	LastMessageTimestamp time.Time
	ConnectedState       bool
	ConnectedSession     string
	Pinged               chan pingResponse
	Connected            chan bool
	Finished             chan bool
	TransferFile         *os.File
	DisplayMotd          bool
}

// NewClient creates a new client and its underlying connection to Redis. It is not actively
// receiving and sending packets at this point; that is only enabled upon start.
func NewClient(username string, hostname string, uri string, logger *zap.SugaredLogger) (*Client, error) {
	clnt := Client{
		Logger:               logger,
		RawHostname:          hostname,
		RemoteUsername:       username,
		RemoteHostname:       "se-" + hostname,
		LastMessageTimestamp: time.Now(),
		ConnectedState:       false,
		Connected:            make(chan bool, 1),
		Finished:             make(chan bool, 1),
		Pinged:               make(chan pingResponse, 1),
		TransferFile:         nil,
		DisplayMotd:          false,
	}
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	clnt.Host, err = NewRedisHost("cl-"+name, uri, logger, clnt.handleMessage)
	if err != nil {
		return nil, err
	}
	return &clnt, nil
}

func (clnt *Client) refreshExpiry() {
	clnt.LastMessageMutex.Lock()
	defer clnt.LastMessageMutex.Unlock()
	clnt.LastMessageTimestamp = time.Now()
}

func (clnt *Client) isExpired() bool {
	clnt.LastMessageMutex.Lock()
	defer clnt.LastMessageMutex.Unlock()
	return time.Now().Sub(clnt.LastMessageTimestamp).Minutes() >= 5
}

func (clnt *Client) handlePing(sender string, size int) {
	clnt.Pinged <- pingResponse{
		Sender:   sender,
		Size:     size,
		RecvTime: time.Now(),
	}
}

func (clnt *Client) handleHandshake(sender string, success bool, key []byte, session string, motd string) {
	if !success {
		clnt.handleExit(fmt.Errorf("server refused connection"), false)
		return
	}
	if !clnt.ConnectedState && sender == clnt.RemoteHostname {
		err := clnt.Host.CompleteKeyExchange(key)
		if err != nil {
			clnt.handleExit(err, false)
			return
		}
		clnt.Host.FreePrivateKeys()
		clnt.Host.SetEncryptionEnabled(true)
		if clnt.DisplayMotd {
			fmt.Print(motd)
		}
		clnt.ConnectedSession = session
		clnt.ConnectedState = true
		clnt.Connected <- true
	}
}

func (clnt *Client) handlePtyOutput(sender string, payload []byte) {
	if clnt.ConnectedState && sender == clnt.ConnectedSession {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleFileDownload(sender string, payload []byte) {
	if clnt.ConnectedState && sender == clnt.ConnectedSession && clnt.TransferFile != nil {
		_, err := clnt.TransferFile.Write(payload)
		if err != nil {
			clnt.handleExit(err, true)
		}
	}
}

func (clnt *Client) handleExit(err error, ack bool) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		clnt.Logger.Infof("Client exited with error: %s", err)
	} else {
		clnt.Logger.Info("Client exited normally.")
	}
	if clnt.ConnectedState {
		if ack {
			clnt.Host.SendMessage(clnt.ConnectedSession, drshproto.Message{
				Type:   drshproto.Message_EXIT,
				Sender: clnt.Host.Hostname,
			})
			// Add a slight delay so the disconnect packet can send
			time.Sleep(100 * time.Millisecond)
		}
		clnt.Finished <- true
	} else {
		os.Exit(1)
	}
}

func (clnt *Client) handleMessage(msg drshproto.Message) {
	clnt.refreshExpiry()
	switch msg.GetType() {
	case drshproto.Message_PING_RESPONSE:
		clnt.handlePing(msg.GetSender(), proto.Size(&msg))
	case drshproto.Message_HEARTBEAT_RESPONSE:
		// Heartbeats don't require any processing other than timestamping
	case drshproto.Message_HANDSHAKE_RESPONSE:
		clnt.handleHandshake(msg.GetSender(), msg.GetHandshakeSuccess(), msg.GetHandshakeKey(), msg.GetHandshakeSession(), msg.GetHandshakeMotd())
	case drshproto.Message_PTY_OUTPUT:
		clnt.handlePtyOutput(msg.GetSender(), msg.GetPtyPayload())
	case drshproto.Message_FILE_DOWNLOAD:
		clnt.handleFileDownload(msg.GetSender(), msg.GetFilePayload())
	case drshproto.Message_EXIT:
		clnt.handleExit(nil, false)
	default:
		clnt.Logger.Warnf("Received invalid packet from '%s'.", msg.GetSender())
	}
}

func (clnt *Client) connect(mode drshproto.Message_SessionMode, filename string) {
	if !clnt.Host.IsListening(clnt.RemoteHostname) {
		clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.RawHostname), false)
		return
	}
	// Send handshake request to the server
	err := clnt.Host.PrepareKeyExchange()
	if err != nil {
		clnt.handleExit(err, false)
		return
	}
	clnt.Host.SendMessage(clnt.RemoteHostname, drshproto.Message{
		Type:              drshproto.Message_HANDSHAKE_REQUEST,
		Sender:            clnt.Host.Hostname,
		HandshakeKey:      clnt.Host.KXPrivateKey.Bytes(),
		HandshakeUser:     clnt.RemoteUsername,
		HandshakeMode:     mode,
		HandshakeFilename: filename,
	})
	// Wait until we have received a handshake response from the server
	// This will put us into our own server session
	<-clnt.Connected
}

// UploadFile uploads a file to the remote server.
func (clnt *Client) UploadFile(localFilename string, remoteFilename string) {
	// Open file for reading
	transferFile, err := os.Open(localFilename)
	if err != nil {
		clnt.handleExit(fmt.Errorf("cannot open file '%s'", localFilename), true)
		return
	}
	clnt.TransferFile = transferFile
	defer clnt.TransferFile.Close()
	clnt.DisplayMotd = false
	// Establish secure connection to the server
	clnt.connect(drshproto.Message_MODE_FILE_UPLOAD, remoteFilename)
	// Read from local file, break into packets, and send each one individually
	go (func() {
		for {
			buf := make([]byte, 4096)
			cnt, err := clnt.TransferFile.Read(buf)
			if err != nil {
				if err != io.EOF {
					clnt.handleExit(err, true)
				} else {
					fmt.Printf("File '%s' was uploaded to '%s@%s:%s'.\n", localFilename, clnt.RemoteUsername, clnt.RawHostname, remoteFilename)
					clnt.handleExit(nil, true)
				}
				break
			}
			clnt.Host.SendMessage(clnt.ConnectedSession, drshproto.Message{
				Type:        drshproto.Message_FILE_UPLOAD,
				Sender:      clnt.Host.Hostname,
				FilePayload: buf[:cnt],
			})
		}
	})()
	// Finished channel will be triggered on error or client exit due to completion
	<-clnt.Finished
}

// DownloadFile downloads a file from the remote server.
func (clnt *Client) DownloadFile(remoteFilename string, localFilename string) {
	// Open file for writing
	transferFile, err := os.Create(localFilename)
	if err != nil {
		clnt.handleExit(fmt.Errorf("cannot create file '%s'", localFilename), true)
		return
	}
	clnt.TransferFile = transferFile
	defer clnt.TransferFile.Close()
	clnt.DisplayMotd = false
	// Establish secure connection to the server
	clnt.connect(drshproto.Message_MODE_FILE_DOWNLOAD, remoteFilename)
	// Finished channel will be triggered on error or server exit due to completion
	<-clnt.Finished
}

// LoginInteractively is a blocking function that facilitates an interactive session with its server.
func (clnt *Client) LoginInteractively() {
	clnt.DisplayMotd = true
	clnt.connect(drshproto.Message_MODE_TERMINAL, "")
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
			clnt.Host.SendMessage(clnt.ConnectedSession, drshproto.Message{
				Type:          drshproto.Message_PTY_WINCH,
				Sender:        clnt.Host.Hostname,
				PtyDimensions: drshutil.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
			})
		}
	})()
	winchChan <- syscall.SIGWINCH
	// Capture input in packets and send to server
	go (func() {
		for {
			buf := make([]byte, 4096)
			cnt, err := os.Stdin.Read(buf)
			if err != nil {
				clnt.handleExit(err, true)
				break
			}
			clnt.Host.SendMessage(clnt.ConnectedSession, drshproto.Message{
				Type:       drshproto.Message_PTY_INPUT,
				Sender:     clnt.Host.Hostname,
				PtyPayload: buf[:cnt],
			})
		}
	})()
	// Keepalive routine sends packets every so often to keep connection alive
	go (func() {
		for {
			clnt.Host.SendMessage(clnt.ConnectedSession, drshproto.Message{
				Type:   drshproto.Message_HEARTBEAT_REQUEST,
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
	<-clnt.Finished
	fmt.Printf("Connection to %s closed.\n", clnt.RawHostname)
}

// Ping is a blocking function that streams an infinite series of pings to the server,
// until it receives an interrupt from the user.
func (clnt *Client) Ping() {
	if !clnt.Host.IsListening(clnt.RemoteHostname) {
		clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.RawHostname), false)
		return
	}
	start := time.Now()
	msg := drshproto.Message{
		Type:   drshproto.Message_PING_REQUEST,
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
			fmt.Printf("\n--- %s ping statistics ---\n", clnt.RawHostname)
			fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %s\n", sentCnt, recvCnt, loss, totalDuration)
			fmt.Printf("rtt min/max %s/%s\n", minDuration, maxDuration)
			os.Exit(0)
		}
	}()
	fmt.Printf("PING %s %d data bytes\n", clnt.RawHostname, proto.Size(&msg))
	for {
		if !clnt.Host.IsListening(clnt.RemoteHostname) {
			clnt.handleExit(fmt.Errorf("host '%s' does not exist or is offline", clnt.RawHostname), false)
			break
		}
		sentTime := time.Now()
		clnt.Host.SendMessage(clnt.RemoteHostname, msg)
		sentCnt++
		var resp pingResponse
		for {
			resp = <-clnt.Pinged
			if resp.Sender == clnt.RemoteHostname {
				break
			}
		}
		recvCnt++
		recvDuration := resp.RecvTime.Sub(sentTime)
		if recvDuration < minDuration || first {
			minDuration = recvDuration
		}
		if recvDuration > maxDuration || first {
			maxDuration = recvDuration
		}
		first = false
		fmt.Printf("%d bytes from %s: time=%s\n", resp.Size, clnt.RawHostname, recvDuration)
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

// Start is a non-blocking function that enables client packet processing.
func (clnt *Client) Start() {
	go clnt.startTimeoutHandler()
	clnt.Host.Start()
}

// Close is called to destroy the client's Redis connection and perform cleanup.
func (clnt *Client) Close() {
	clnt.Host.Close()
}
