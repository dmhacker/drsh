package client

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/dmhacker/drsh/internal/util"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

type PingResponse struct {
	Sender   string
	Size     int
	RecvTime time.Time
}

type Client struct {
	Proxy               *proxy.RedisProxy
	Logger              *zap.SugaredLogger
	Group               *dhkx.DHGroup
	PrivateKey          *dhkx.DHKey
	Cipher              cipher.AEAD
	RemoteUser          string
	RemoteHostname      string
	LastPacketMutex     sync.Mutex
	LastPacketTimestamp time.Time
	ConnectedState      bool
	Pinged              chan PingResponse
	Connected           chan bool
	Finished            chan bool
}

var ctx = context.Background()

func NewClient(user string, hostname string, uri string, logger *zap.SugaredLogger) (*Client, error) {
	g, err := dhkx.GetGroup(0)
	if err != nil {
		return nil, err
	}
	priv, err := g.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}
	name, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	clnt := Client{
		Logger:              logger,
		Group:               g,
		PrivateKey:          priv,
		RemoteUser:          user,
		RemoteHostname:      hostname,
		LastPacketMutex:     sync.Mutex{},
		LastPacketTimestamp: time.Now(),
		ConnectedState:      false,
		Connected:           make(chan bool, 1),
		Finished:            make(chan bool, 1),
		Pinged:              make(chan PingResponse, 1),
	}
	clnt.Proxy, err = proxy.NewRedisProxy("client", base64.RawURLEncoding.EncodeToString(name[:]), uri, logger, clnt.HandlePacket)
	if err != nil {
		return nil, err
	}
	return &clnt, nil
}

func (clnt *Client) TerminalSize() *pty.Winsize {
	ws := new(pty.Winsize)
	rc, _, _ := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)))
	if int(rc) == -1 {
		clnt.Logger.Fatal("Could not obtain tty dimensions")
	}
	return ws
}

func (clnt *Client) SaveHostTimestamp() {
	clnt.LastPacketMutex.Lock()
	defer clnt.LastPacketMutex.Unlock()
	clnt.LastPacketTimestamp = time.Now()
}

func (clnt *Client) HostExpired() bool {
	clnt.LastPacketMutex.Lock()
	defer clnt.LastPacketMutex.Unlock()
	return time.Now().Sub(clnt.LastPacketTimestamp).Minutes() >= 10
}

func (clnt *Client) HandlePing(sender string, size int) {
	clnt.Pinged <- PingResponse{
		Sender:   sender,
		Size:     size,
		RecvTime: time.Now(),
	}
}

func (clnt *Client) HandleHandshake(sender string, key []byte, success bool) {
	if !success {
		clnt.HandleExit(fmt.Errorf("server refused connection"), false)
	}
	if !clnt.ConnectedState && sender == clnt.RemoteHostname {
		pkey := dhkx.NewPublicKey(key)
		skey, err := clnt.Group.ComputeKey(pkey, clnt.PrivateKey)
		if err != nil {
			clnt.HandleExit(err, false)
		}
		// TODO: Are there issues with only using the first 32 bytes?
		clnt.Cipher, err = chacha20poly1305.New(skey.Bytes()[:chacha20poly1305.KeySize])
		if err != nil {
			clnt.HandleExit(err, false)
		}
		clnt.ConnectedState = true
		clnt.Connected <- true
	}
}

func (clnt *Client) HandleOutput(sender string, payload []byte, nonce []byte) {
	if clnt.ConnectedState && sender == clnt.RemoteHostname {
		plaintext, err := clnt.Cipher.Open(nil, nonce, payload, nil)
		if err != nil {
			clnt.HandleExit(err, true)
			return
		}
		_, err = os.Stdout.Write(plaintext)
		if err != nil {
			clnt.HandleExit(err, true)
		}
	}
}

func (clnt *Client) HandleExit(err error, ack bool) {
	if err != nil {
		fmt.Println(err)
	}
	if ack {
		clnt.Proxy.SendPacket(proxy.DirectedPacket{
			Category:  "server",
			Recipient: clnt.RemoteHostname,
			Packet: comms.Packet{
				Type:   comms.Packet_CLIENT_EXIT,
				Sender: clnt.Proxy.Hostname,
			},
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

func (clnt *Client) HandlePacket(dirpckt proxy.DirectedPacket) {
	pckt := dirpckt.Packet
	sender := pckt.GetSender()
	if clnt.ConnectedState && clnt.RemoteHostname == sender {
		clnt.SaveHostTimestamp()
	}
	switch pckt.GetType() {
	case comms.Packet_SERVER_PING:
		clnt.HandlePing(sender, proto.Size(&pckt))
	case comms.Packet_SERVER_HANDSHAKE:
		clnt.HandleHandshake(sender, pckt.GetKey(), pckt.GetHandshakeSuccess())
	case comms.Packet_SERVER_OUTPUT:
		clnt.HandleOutput(sender, pckt.GetPayload(), pckt.GetNonce())
	case comms.Packet_SERVER_EXIT:
		clnt.HandleExit(nil, false)
	default:
		clnt.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (clnt *Client) Connect() {
	if !clnt.Proxy.IsListening("server", clnt.RemoteHostname) {
		clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
	}
	ws := clnt.TerminalSize()
	clnt.Proxy.SendPacket(proxy.DirectedPacket{
		Category:  "server",
		Recipient: clnt.RemoteHostname,
		Packet: comms.Packet{
			Type:          comms.Packet_CLIENT_HANDSHAKE,
			Sender:        clnt.Proxy.Hostname,
			PtyDimensions: util.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
			Key:           clnt.PrivateKey.Bytes(),
		},
	})
	<-clnt.Connected
	// Capture SIGWINCH signals
	winchChan := make(chan os.Signal)
	signal.Notify(winchChan, syscall.SIGWINCH)
	go (func() {
		for range winchChan {
			ws := clnt.TerminalSize()
			clnt.Proxy.SendPacket(proxy.DirectedPacket{
				Category:  "server",
				Recipient: clnt.RemoteHostname,
				Packet: comms.Packet{
					Type:          comms.Packet_CLIENT_PTY_WINCH,
					Sender:        clnt.Proxy.Hostname,
					PtyDimensions: util.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
				},
			})
		}
	})()
	// Capture input in packets and send to server
	go (func() {
		for {
			buf := make([]byte, 2048)
			cnt, err := os.Stdin.Read(buf)
			if err != nil {
				clnt.HandleExit(err, true)
				break
			}
			nonce := make([]byte, chacha20poly1305.NonceSize)
			_, err = rand.Read(nonce)
			if err != nil {
				clnt.HandleExit(err, true)
				break
			}
			ciphertext := clnt.Cipher.Seal(nil, nonce, buf[:cnt], nil)
			clnt.Proxy.SendPacket(proxy.DirectedPacket{
				Category:  "server",
				Recipient: clnt.RemoteHostname,
				Packet: comms.Packet{
					Type:    comms.Packet_CLIENT_OUTPUT,
					Sender:  clnt.Proxy.Hostname,
					Payload: ciphertext,
					Nonce:   nonce,
				},
			})
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
	if !clnt.Proxy.IsListening("server", clnt.RemoteHostname) {
		clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
	}
	start := time.Now()
	pckt := comms.Packet{
		Type:   comms.Packet_CLIENT_PING,
		Sender: clnt.Proxy.Hostname,
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
		sentTime := time.Now()
		clnt.Proxy.SendPacket(proxy.DirectedPacket{
			Category:  "server",
			Recipient: clnt.RemoteHostname,
			Packet:    pckt,
		})
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
	// Runs every 30 seconds and performs a check to make sure server
	// has not timed out (last packet received >10 minutes ago)
	for {
		if clnt.HostExpired() {
			clnt.HandleExit(fmt.Errorf("server timed out"), true)
			break
		}
		time.Sleep(30 * time.Second)
	}
}

func (clnt *Client) Start() {
	// Connect to Redis and run background routines
	go clnt.StartTimeoutHandler()
	clnt.Proxy.Start()
}

func (clnt *Client) Close() {
	clnt.Proxy.Close()
}
