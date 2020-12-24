package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/dmhacker/drsh/internal/packet"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/dmhacker/drsh/internal/server"
	"github.com/google/uuid"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/term"
)

const (
	PingStage = iota
	SelectStage
	HandshakeStage
	ConnectStage
)

type Client struct {
	Stage            int
	Proxy            *proxy.RedisProxy
	Logger           *zap.SugaredLogger
	Mtx              sync.Mutex
	Cnd              *sync.Cond
	PingInfo         map[string]server.ServerProperties
	PingLeft         int
	HandshakeChan    chan bool
	ConnectTimestamp time.Time
	ConnectTo        string
	DoneChan         chan bool
	Group            *dhkx.DHGroup
	PrivateKey       *dhkx.DHKey
	SharedKey        []byte
}

var ctx = context.Background()

func NewClient(uri string, logger *zap.SugaredLogger) (*Client, error) {
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
		Stage:         PingStage,
		Logger:        logger,
		Mtx:           sync.Mutex{},
		PingInfo:      make(map[string]server.ServerProperties),
		HandshakeChan: make(chan bool),
		DoneChan:      make(chan bool),
		Group:         g,
		PrivateKey:    priv,
	}
	clnt.Cnd = sync.NewCond(&clnt.Mtx)
	prx, err := proxy.NewRedisProxy(base64.RawURLEncoding.EncodeToString(name[:]), "client", uri, logger, clnt.HandlePacket)
	if err != nil {
		return nil, err
	}
	clnt.Proxy = prx
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

func (clnt *Client) HandlePing(sender string, properties server.ServerProperties) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	clnt.PingInfo[sender] = properties
	if clnt.Stage == PingStage {
		clnt.PingLeft--
		if clnt.PingLeft == 0 {
			clnt.Cnd.Signal()
		}
	}
}

func (clnt *Client) HandleHandshake(sender string, key []byte) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if clnt.Stage == HandshakeStage && sender == clnt.ConnectTo {
		pkey := dhkx.NewPublicKey(key)
		skey, err := clnt.Group.ComputeKey(pkey, clnt.PrivateKey)
		if err != nil {
			clnt.Logger.Fatalf("Received invalid key from server: %s", err)
		}
		clnt.SharedKey = skey.Bytes()
		clnt.HandshakeChan <- true
	}
}

func (clnt *Client) HandleOutput(sender string, output []byte) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if clnt.Stage == ConnectStage && sender == clnt.ConnectTo {
		cnt, err := os.Stdout.Write(output)
		if err != nil || cnt != len(output) {
			clnt.HandleExit(err, true)
		}
	}
}

func (clnt *Client) HandleExit(err error, ack bool) {
	if ack {
		resp := packet.Packet{
			Type:      packet.Packet_CLIENT_EXIT,
			Sender:    clnt.Proxy.Name,
			Recipient: clnt.ConnectTo,
		}
		clnt.Proxy.SendPacket("server", &resp)
		// Add a slight delay so the disconnect packet can send
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Printf("An error occurred on exit: %s\n", err)
	}
	clnt.DoneChan <- true
}

func (clnt *Client) HandlePacket(pckt *packet.Packet) {
	sender := pckt.GetSender()
	clnt.Mtx.Lock()
	if clnt.Stage == ConnectStage && clnt.ConnectTo == sender {
		clnt.ConnectTimestamp = time.Now()
	}
	clnt.Mtx.Unlock()
	switch pckt.GetType() {
	case packet.Packet_SERVER_PING:
		clnt.HandlePing(sender, server.ServerProperties{
			StartedAt: time.Now().Add(-1 * pckt.GetPingUptime().AsDuration()),
		})
	case packet.Packet_SERVER_HANDSHAKE:
		clnt.HandleHandshake(sender, pckt.GetKey())
	case packet.Packet_SERVER_OUTPUT:
		clnt.HandleOutput(sender, pckt.GetPayload())
	case packet.Packet_SERVER_EXIT:
		clnt.HandleExit(nil, false)
	default:
		clnt.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (clnt *Client) PingAll() {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	clnt.Stage = PingStage
	servers := clnt.Proxy.CandidateServers()
	fmt.Printf("Pinging %d candidate servers. This will take a moment.\n", len(servers))
	for _, server := range servers {
		ping := packet.Packet{
			Type:      packet.Packet_CLIENT_PING,
			Sender:    clnt.Proxy.Name,
			Recipient: server,
		}
		clnt.Proxy.SendPacket("server", &ping)
	}
	clnt.PingLeft = len(servers)
	if clnt.PingLeft > 0 {
		// This goroutine times out the ping if a server takes too long to respond
		go (func() {
			time.Sleep(10 * time.Second)
			clnt.Mtx.Lock()
			clnt.Cnd.Signal()
			clnt.Mtx.Unlock()
		})()
		clnt.Cnd.Wait()
	}
}

func (clnt *Client) SelectServer() *string {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if len(clnt.PingInfo) == 0 {
		fmt.Println("No available servers.")
		return nil
	}
	clnt.Stage = SelectStage
	selections := make([]string, len(clnt.PingInfo))
	fmt.Println("Available servers:")
	i := 0
	for server, info := range clnt.PingInfo {
		fmt.Printf("%d) %s (%s uptime)\n", i+1, server, info.Uptime().String())
		selections[i] = server
		i++
	}
	for {
		fmt.Print("#? ")
		var selection string
		fmt.Scanln(&selection)
		j, err := strconv.ParseInt(selection, 0, 64)
		if err != nil || j < 1 || j > int64(len(selections)) {
			fmt.Println("Invalid selection. Try again.")
			continue
		}
		return &selections[j-1]
	}
}

func (clnt *Client) Connect(name string) {
	clnt.Mtx.Lock()
	clnt.Stage = HandshakeStage
	clnt.ConnectTo = name
	ws := clnt.TerminalSize()
	handshake := packet.Packet{
		Type:       packet.Packet_CLIENT_HANDSHAKE,
		Sender:     clnt.Proxy.Name,
		Recipient:  clnt.ConnectTo,
		PtyRows:    uint32(ws.Rows),
		PtyCols:    uint32(ws.Cols),
		PtyXpixels: uint32(ws.X),
		PtyYpixels: uint32(ws.Y),
		Key:        clnt.PrivateKey.Bytes(),
	}
	clnt.Proxy.SendPacket("server", &handshake)
	clnt.Mtx.Unlock()
	<-clnt.HandshakeChan
	clnt.Mtx.Lock()
	clnt.Stage = ConnectStage
	clnt.Mtx.Unlock()
	// Capture SIGWINCH signals
	winchChan := make(chan os.Signal)
	signal.Notify(winchChan, syscall.SIGWINCH)
	go (func() {
		for range winchChan {
			ws := clnt.TerminalSize()
			winch := packet.Packet{
				Type:       packet.Packet_CLIENT_PTY_WINCH,
				Sender:     clnt.Proxy.Name,
				Recipient:  clnt.ConnectTo,
				PtyRows:    uint32(ws.Rows),
				PtyCols:    uint32(ws.Cols),
				PtyXpixels: uint32(ws.X),
				PtyYpixels: uint32(ws.Y),
			}
			clnt.Proxy.SendPacket("server", &winch)
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
			in := packet.Packet{
				Type:      packet.Packet_CLIENT_OUTPUT,
				Sender:    clnt.Proxy.Name,
				Recipient: clnt.ConnectTo,
				Payload:   buf[:cnt],
			}
			clnt.Proxy.SendPacket("server", &in)
		}
	})()
}

func (clnt *Client) StartTimeoutHandler() {
	// Runs every 30 seconds and performs a check to make sure server
	// has not timed out (last packet received >10 minutes ago)
	for {
		clnt.Mtx.Lock()
		stage := clnt.Stage
		timestamp := clnt.ConnectTimestamp
		clnt.Mtx.Unlock()
		if stage == ConnectStage && time.Now().Sub(timestamp).Minutes() >= 10 {
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
	// Send out pings to determine available servers
	clnt.PingAll()
	// Have the client select one of these servers
	servId := clnt.SelectServer()
	if servId == nil {
		return
	}
	// Put the current tty into raw mode and revert on exit
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		clnt.Logger.Fatalf("Could not put tty into raw mode: %s", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	// Connect to the specified server
	clnt.Connect(*servId)
	// Wait until at least one thread messages the done channel
	<-clnt.DoneChan
}

func (clnt *Client) Close() {
	clnt.Proxy.Close()
}
