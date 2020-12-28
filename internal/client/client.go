package client

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/dmhacker/drsh/internal/util"
	"github.com/golang/protobuf/proto"
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
	ConnectedSession    string
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
	name, err := util.RandomName()
	if err != nil {
		return nil, err
	}
	clnt.Proxy, err = proxy.NewRedisProxy("client", name, uri, logger, clnt.HandlePacket)
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
	return time.Now().Sub(clnt.LastPacketTimestamp).Minutes() >= 10
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
	}
	if !clnt.ConnectedState && sender == clnt.RemoteHostname {
		pub := dhkx.NewPublicKey(key)
		skey, err := clnt.Group.ComputeKey(pub, clnt.PrivateKey)
		if err != nil {
			clnt.HandleExit(err, false)
		}
		// TODO: Are there issues with only using the first 32 bytes?
		clnt.Cipher, err = chacha20poly1305.New(skey.Bytes()[:chacha20poly1305.KeySize])
		if err != nil {
			clnt.HandleExit(err, false)
		}
		clnt.ConnectedSession = session
		clnt.ConnectedState = true
		clnt.Connected <- true
	}
}

func (clnt *Client) HandleOutput(sender string, payload []byte, nonce []byte) {
	if clnt.ConnectedState && sender == clnt.ConnectedSession {
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
		fmt.Fprintln(os.Stderr, err)
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
	sender := dirpckt.Packet.GetSender()
	clnt.RefreshExpiry()
	switch dirpckt.Packet.GetType() {
	case comms.Packet_SERVER_PING:
		clnt.HandlePing(sender, proto.Size(&dirpckt.Packet))
	case comms.Packet_SERVER_HANDSHAKE:
		clnt.HandleHandshake(sender, dirpckt.Packet.GetHandshakeSuccess(), dirpckt.Packet.GetHandshakeKey(), dirpckt.Packet.GetHandshakeSession())
	case comms.Packet_SERVER_OUTPUT:
		clnt.HandleOutput(sender, dirpckt.Packet.GetPayload(), dirpckt.Packet.GetNonce())
	case comms.Packet_SERVER_EXIT:
		clnt.HandleExit(nil, false)
	default:
		clnt.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (clnt *Client) Connect() {
	if !clnt.Proxy.IsListening("server", clnt.RemoteHostname) {
		clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
		return
	}
	// Send handshake request to the server
	ws, err := util.TerminalSize()
	if err != nil {
		clnt.HandleExit(err, false)
		return
	}
	clnt.Proxy.SendPacket(proxy.DirectedPacket{
		Category:  "server",
		Recipient: clnt.RemoteHostname,
		Packet: comms.Packet{
			Type:          comms.Packet_CLIENT_HANDSHAKE,
			Sender:        clnt.Proxy.Hostname,
			HandshakeKey:  clnt.PrivateKey.Bytes(),
			PtyDimensions: util.Pack64(ws.Rows, ws.Cols, ws.X, ws.Y),
		},
	})
	// Wait until we have received a handshake response from the server
	// This will put us into our own server session
	<-clnt.Connected
	// Capture SIGWINCH signals
	winchChan := make(chan os.Signal)
	signal.Notify(winchChan, syscall.SIGWINCH)
	go (func() {
		for range winchChan {
			ws, err := util.TerminalSize()
			if err != nil {
				clnt.HandleExit(err, true)
				break
			}
			clnt.Proxy.SendPacket(proxy.DirectedPacket{
				Category:  "server-session",
				Recipient: clnt.ConnectedSession,
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
				Category:  "server-session",
				Recipient: clnt.ConnectedSession,
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
		return
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
		if !clnt.Proxy.IsListening("server", clnt.RemoteHostname) {
			clnt.HandleExit(fmt.Errorf("host '%s' does not exist", clnt.RemoteHostname), false)
			break
		}
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
	clnt.Proxy.Start()
}

func (clnt *Client) Close() {
	clnt.Proxy.Close()
}
