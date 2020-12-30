package drshclient

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dmhacker/drsh/internal/drshcomms"
	"github.com/dmhacker/drsh/internal/drshhost"
	"github.com/dmhacker/drsh/internal/drshutil"
	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"
	"golang.org/x/term"
)

type PingResponse struct {
	Sender   string
	Size     int
	RecvTime time.Time
}

type Client struct {
	Host                *drshhost.RedisHost
	Logger              *zap.SugaredLogger
	RemoteUser          string
	RemoteHostname      string
	LastPacketMutex     sync.Mutex
	LastPacketTimestamp time.Time
	ConnectedState      bool
	ConnectedSession    string
	Pinged              chan PingResponse
	Connected           chan bool
	Finished            chan bool
}

var ctx = context.Background()

func NewClient(user string, hostname string, uri string, logger *zap.SugaredLogger) (*Client, error) {
	clnt := Client{
		Logger:              logger,
		RemoteUser:          user,
		RemoteHostname:      "se-" + hostname,
		LastPacketMutex:     sync.Mutex{},
		LastPacketTimestamp: time.Now(),
		ConnectedState:      false,
		Connected:           make(chan bool, 1),
		Finished:            make(chan bool, 1),
		Pinged:              make(chan PingResponse, 1),
	}
	name, err := drshutil.RandomName()
	if err != nil {
		return nil, err
	}
	clnt.Host, err = drshhost.NewRedisHost("cl-"+name, uri, logger, clnt.HandlePacket)
	if err != nil {
		return nil, err
	}
	return &clnt, nil
}

func (clnt *Client) RefreshExpiry() {
	clnt.LastPacketMutex.Lock()
	defer clnt.LastPacketMutex.Unlock()
	clnt.LastPacketTimestamp = time.Now()
}

func (clnt *Client) IsExpired() bool {
	clnt.LastPacketMutex.Lock()
	defer clnt.LastPacketMutex.Unlock()
	return time.Now().Sub(clnt.LastPacketTimestamp).Minutes() >= 5
}

func (clnt *Client) HandlePing(sender string, size int) {
	clnt.Pinged <- PingResponse{
		Sender:   sender,
		Size:     size,
		RecvTime: time.Now(),
	}
}

func (clnt *Client) HandleHandshake(sender string, success bool, key []byte, session string) {
	if !success {
		clnt.HandleExit(fmt.Errorf("server refused connection"), false)
		return
	}
	if !clnt.ConnectedState && sender == clnt.RemoteHostname {
		err := clnt.Host.CompleteKeyExchange(key)
		if err != nil {
			clnt.HandleExit(err, false)
			return
		}
		clnt.Host.FreePrivateKeys()
		clnt.Host.SetEncryptionEnabled(true)
		clnt.ConnectedSession = session
		clnt.ConnectedState = true
		clnt.Connected <- true
	}
}

func (clnt *Client) HandleOutput(sender string, payload []byte) {
	if clnt.ConnectedState && sender == clnt.ConnectedSession {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			clnt.HandleExit(err, true)
		}
	}
}

func (clnt *Client) HandleExit(err error, ack bool) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if ack {
		clnt.Host.SendPacket(clnt.RemoteHostname, drshcomms.Packet{
			Type:   drshcomms.Packet_CLIENT_EXIT,
			Sender: clnt.Host.Hostname,
		})
		// Add a slight delay so the disconnect packet can send
		time.Sleep(100 * time.Millisecond)
	}
	if clnt.ConnectedState {
		clnt.Finished <- true
	} else {
		os.Exit(1)
	}
}

func (clnt *Client) HandlePacket(pckt drshcomms.Packet) {
	clnt.RefreshExpiry()
	switch pckt.GetType() {
	case drshcomms.Packet_SERVER_PING:
		clnt.HandlePing(pckt.GetSender(), proto.Size(&pckt))
	case drshcomms.Packet_SERVER_HEARTBEAT:
		// Heartbeats don't require any processing other than timestamping
	case drshcomms.Packet_SERVER_HANDSHAKE:
		clnt.HandleHandshake(pckt.GetSender(), pckt.GetHandshakeSuccess(), pckt.GetHandshakeKey(), pckt.GetHandshakeSession())
	case drshcomms.Packet_SERVER_OUTPUT:
		clnt.HandleOutput(pckt.GetSender(), pckt.GetPayload())
	case drshcomms.Packet_SERVER_EXIT:
		clnt.HandleExit(nil, false)
	default:
		clnt.Logger.Warnf("Received invalid packet from '%s'.", pckt.GetSender())
	}
}

func (clnt *Client) Connect() {
	if !clnt.Host.IsListening(clnt.RemoteHostname) {
		clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
		return
	}
	// Send handshake request to the server
	err := clnt.Host.PrepareKeyExchange()
	if err != nil {
		clnt.HandleExit(err, false)
		return
	}
	clnt.Host.SendPacket(clnt.RemoteHostname, drshcomms.Packet{
		Type:          drshcomms.Packet_CLIENT_HANDSHAKE,
		Sender:        clnt.Host.Hostname,
		HandshakeKey:  clnt.Host.KXPrivateKey.Bytes(),
		HandshakeUser: clnt.RemoteUser,
	})
	// Wait until we have received a handshake response from the server
	// This will put us into our own server session
	<-clnt.Connected
	// Capture SIGWINCH signals
	winchChan := make(chan os.Signal)
	signal.Notify(winchChan, syscall.SIGWINCH)
	go (func() {
		for range winchChan {
			ws, err := drshutil.TerminalSize()
			if err != nil {
				clnt.HandleExit(err, true)
				break
			}
			clnt.Host.SendPacket(clnt.ConnectedSession, drshcomms.Packet{
				Type:          drshcomms.Packet_CLIENT_PTY_WINCH,
				Sender:        clnt.Host.Hostname,
				PtyDimensions: drshutil.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
			})
		}
	})()
	winchChan <- syscall.SIGWINCH
	// Capture input in packets and send to server
	go (func() {
		for {
			buf := make([]byte, 1096)
			cnt, err := os.Stdin.Read(buf)
			if err != nil {
				clnt.HandleExit(err, true)
				break
			}
			clnt.Host.SendPacket(clnt.ConnectedSession, drshcomms.Packet{
				Type:    drshcomms.Packet_CLIENT_OUTPUT,
				Sender:  clnt.Host.Hostname,
				Payload: buf[:cnt],
			})
		}
	})()
	// Keepalive routine sends packets every so often to keep connection alive
	go (func() {
		for {
			clnt.Host.SendPacket(clnt.ConnectedSession, drshcomms.Packet{
				Type:   drshcomms.Packet_CLIENT_HEARTBEAT,
				Sender: clnt.Host.Hostname,
			})
			time.Sleep(60 * time.Second)
		}
	})()
	// Put the current tty into raw mode and revert on exit
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		clnt.HandleExit(err, false)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	// Wait until at least one thread messages the finished channel
	<-clnt.Finished
}

func (clnt *Client) Ping() {
	if !clnt.Host.IsListening(clnt.RemoteHostname) {
		clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
		return
	}
	start := time.Now()
	pckt := drshcomms.Packet{
		Type:   drshcomms.Packet_CLIENT_PING,
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
			fmt.Printf("\n--- %s ping statistics ---\n", clnt.RemoteHostname)
			fmt.Printf("%d packets transmitted, %d received, %d%% packet loss, time %s\n", sentCnt, recvCnt, loss, totalDuration)
			fmt.Printf("rtt min/max %s/%s\n", minDuration, maxDuration)
			os.Exit(0)
		}
	}()
	fmt.Printf("PING %s %d data bytes\n", clnt.RemoteHostname, proto.Size(&pckt))
	for {
		if !clnt.Host.IsListening(clnt.RemoteHostname) {
			clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
			break
		}
		sentTime := time.Now()
		clnt.Host.SendPacket(clnt.RemoteHostname, pckt)
		sentCnt++
		var resp PingResponse
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
		fmt.Printf("%d bytes from %s: time=%s\n", resp.Size, clnt.RemoteHostname, recvDuration)
		time.Sleep(1 * time.Second)
	}
}

func (clnt *Client) StartTimeoutHandler() {
	for {
		if clnt.IsExpired() {
			clnt.HandleExit(fmt.Errorf("server timed out"), true)
			break
		}
		time.Sleep(30 * time.Second)
	}
}

func (clnt *Client) Start() {
	go clnt.StartTimeoutHandler()
	clnt.Host.Start()
}

func (clnt *Client) Close() {
	clnt.Host.Close()
}
