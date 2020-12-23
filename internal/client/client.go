package client

import (
	"context"
    "os"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

    "golang.org/x/term"
	"github.com/dmhacker/drsh/internal/packet"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/google/uuid"
	"go.uber.org/zap"
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
	PingNames        map[uuid.UUID]string
	PingLeft         int
	HandshakeChan    chan bool
	ConnectTimestamp time.Time
	ConnectId        uuid.UUID
}

var ctx = context.Background()

func NewClient(uri string, logger *zap.SugaredLogger) (*Client, error) {
	clnt := Client{
		Stage:         PingStage,
		Logger:        logger,
		Mtx:           sync.Mutex{},
		PingNames:     make(map[uuid.UUID]string),
		HandshakeChan: make(chan bool),
	}
	clnt.Cnd = sync.NewCond(&clnt.Mtx)
	prx, err := proxy.NewRedisProxy("client", uri, logger, clnt.HandlePacket)
	if err != nil {
		return nil, err
	}
	clnt.Proxy = prx
	return &clnt, nil
}

func (clnt *Client) HandlePing(sender uuid.UUID, serverName string) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if clnt.Stage == PingStage {
		clnt.PingNames[sender] = serverName
		clnt.PingLeft--
		if clnt.PingLeft == 0 {
			clnt.Cnd.Signal()
		}
	}
}

func (clnt *Client) HandleHandshake(sender uuid.UUID) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if clnt.Stage == HandshakeStage && sender == clnt.ConnectId {
		clnt.HandshakeChan <- true
	}
}

func (clnt *Client) HandleOutput(sender uuid.UUID, output []byte) {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if clnt.Stage == ConnectStage && sender == clnt.ConnectId {
        fmt.Printf("Got output '%v'\n", output)
        // cnt, err := os.Stdout.Write(output)
        // if err != nil || cnt != len(output) {
        //     // TODO: Implement exit condition
        // }
    }
}

func (clnt *Client) HandlePacket(pckt *packet.Packet) {
	sender, _ := uuid.FromBytes(pckt.GetSender())
	clnt.Mtx.Lock()
	if clnt.Stage == ConnectStage && clnt.ConnectId == sender {
		clnt.ConnectTimestamp = time.Now()
	}
	clnt.Mtx.Unlock()
	switch pt := pckt.GetType(); pt {
	case packet.Packet_SERVER_PING:
		clnt.HandlePing(sender, pckt.GetServerName())
	case packet.Packet_SERVER_HANDSHAKE:
		clnt.HandleHandshake(sender)
	case packet.Packet_SERVER_OUTPUT:
        clnt.HandleOutput(sender, pckt.GetPayload())
	case packet.Packet_SERVER_EXIT:
		// TODO: Implement
	default:
		clnt.Logger.Errorf("Received invalid packet from %s.", sender.String())
	}
}

func (clnt *Client) PingAll() {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	channels, err := clnt.Proxy.Rdb.PubSubChannels(ctx, "drsh:server:*").Result()
	if err != nil {
		clnt.Logger.Fatalf("Could not obtain Redis channels: %s", err)
	}
	clnt.Stage = PingStage
	clnt.PingLeft = len(channels)
	fmt.Printf("Pinging %d candidate servers. This will take a moment.\n", len(channels))
	for _, channel := range channels {
		recipient, err := uuid.Parse(strings.Split(channel, ":")[2])
		if err != nil {
			clnt.PingLeft--
			continue
		}
		ping := packet.Packet{}
		ping.Type = packet.Packet_CLIENT_PING
		ping.Sender = clnt.Proxy.Id[:]
		ping.Recipient = recipient[:]
		clnt.Proxy.SendPacket(&ping)
	}
	if clnt.PingLeft > 0 {
		go (func() {
			time.Sleep(10 * time.Second)
			clnt.Mtx.Lock()
			clnt.Cnd.Signal()
			clnt.Mtx.Unlock()
		})()
		clnt.Cnd.Wait()
	}
}

func (clnt *Client) SelectServer() *uuid.UUID {
	clnt.Mtx.Lock()
	defer clnt.Mtx.Unlock()
	if len(clnt.PingNames) == 0 {
		fmt.Println("No available servers.")
		return nil
	}
	clnt.Stage = SelectStage
	selections := make([]uuid.UUID, len(clnt.PingNames))
	fmt.Println("Available servers:")
	i := 0
	for servId, servName := range clnt.PingNames {
		fmt.Printf("%d) %s (%s)\n", i+1, servName, servId.String())
		selections[i] = servId
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

func (clnt *Client) Connect(servId uuid.UUID) {
	clnt.Mtx.Lock()
	clnt.Stage = HandshakeStage
	clnt.ConnectId = servId
    rows, cols, err := term.GetSize(int(os.Stdin.Fd()))
    if err != nil {
	    clnt.Mtx.Unlock()
		clnt.Logger.Fatalf("Could not obtain tty dimensions: %s", err)
    }
    handshake := packet.Packet{}
    handshake.Type = packet.Packet_CLIENT_HANDSHAKE
    handshake.Sender = clnt.Proxy.Id[:]
    handshake.Recipient = clnt.ConnectId[:]
    handshake.PtyRows = uint32(rows)
    handshake.PtyCols = uint32(cols)
    handshake.PtyXpixels = 80
    handshake.PtyYpixels = 24
    clnt.Proxy.SendPacket(&handshake)
	clnt.Mtx.Unlock()
    <-clnt.HandshakeChan
	clnt.Mtx.Lock()
    clnt.Stage = ConnectStage
	clnt.Mtx.Unlock()
    fmt.Println("Server has acknowledged connection.")
    // TODO: Put terminal in raw mode
    // TODO: Capture SIGWINCH os signals 
    <-make(chan int)
}

func (clnt *Client) StartTimeoutHandler() {
	// Runs every 30 seconds and performs a check to make sure server
	// has not timed out (last packet received >10 minutes ago)
	for {
		// TODO: Implement
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
    clnt.Connect(*servId)
}

func (clnt *Client) Close() {
	clnt.Proxy.Close()
}
