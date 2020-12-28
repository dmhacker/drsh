package server

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/astromechza/etcpwdparse"
	"github.com/creack/pty"
	"github.com/dmhacker/drsh/internal/comms"
	"github.com/dmhacker/drsh/internal/proxy"
	"github.com/dmhacker/drsh/internal/util"
	"github.com/monnand/dhkx"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
)

type Session struct {
	Proxy               *proxy.RedisProxy
	Pty                 *os.File
	Group               *dhkx.DHGroup
	PrivateKey          *dhkx.DHKey
	Cipher              cipher.AEAD
	LastPacketMutex     sync.Mutex
	LastPacketTimestamp time.Time
	Logger              *zap.SugaredLogger
	Client              string
	Finished            chan bool
}

func NewSessionFromHandshake(serv *Server, clnt string, key []byte) (*Session, error) {
	// Set up interactive pseudoterminal
	// TODO: Client will decide which user is run in the future
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, err
	}
	cache, err := etcpwdparse.NewLoadedEtcPasswdCache()
	if err != nil {
		return nil, err
	}
	entry, _ := cache.LookupUserByUid(uid)
	shell := entry.Shell()
	cmd := exec.Command(shell)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	// Set up shared key
	g, err := dhkx.GetGroup(0)
	if err != nil {
		return nil, err
	}
	priv, err := g.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}
	pub := dhkx.NewPublicKey(key)
	skey, err := g.ComputeKey(pub, priv)
	if err != nil {
		return nil, err
	}
	ciph, err := chacha20poly1305.New(skey.Bytes()[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}

	// Initialize session
	session := Session{
		Client:              clnt,
		Pty:                 ptmx,
		Group:               g,
		PrivateKey:          priv,
		Cipher:              ciph,
		LastPacketTimestamp: time.Now(),
		LastPacketMutex:     sync.Mutex{},
		Logger:              serv.Logger,
	}

	// Set up session properties & Redis connection
	name, err := util.RandomName()
	if err != nil {
		return nil, err
	}
	session.Proxy, err = proxy.InheritRedisProxy("server-session", name, serv.Proxy.Rdb, serv.Logger, session.HandlePacket)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (session *Session) RefreshExpiry() {
	session.LastPacketMutex.Lock()
	defer session.LastPacketMutex.Unlock()
	session.LastPacketTimestamp = time.Now()
}

func (session *Session) IsExpired() bool {
	session.LastPacketMutex.Lock()
	defer session.LastPacketMutex.Unlock()
	return time.Now().Sub(session.LastPacketTimestamp).Minutes() >= 10
}

func (session *Session) HandleOutput(payload []byte, nonce []byte) {
	plaintext, err := session.Cipher.Open(nil, nonce, payload, nil)
	if err != nil {
		session.HandleExit(err, true)
	}
	_, err = session.Pty.Write(plaintext)
	if err != nil {
		session.HandleExit(err, true)
	}
}

func (session *Session) HandlePty(rows uint16, cols uint16, xpixels uint16, ypixels uint16) {
	pty.Setsize(session.Pty, &pty.Winsize{
		Rows: rows,
		Cols: cols,
		X:    xpixels,
		Y:    ypixels,
	})
}

func (session *Session) HandleExit(err error, ack bool) {
	// Send an acknowledgement back to the client to indicate that we have
	// closed the session on the server's end
	if ack {
		session.Proxy.SendPacket(proxy.DirectedPacket{
			Category:  "client",
			Recipient: session.Client,
			Packet: comms.Packet{
				Type:   comms.Packet_SERVER_EXIT,
				Sender: session.Proxy.Hostname,
			},
		})
	}
	if err != nil {
		session.Logger.Infof("'%s' has left session %s: %s.", session.Client, session.Proxy.Hostname, err.Error())
	} else {
		session.Logger.Infof("'%s' has left session %s.", session.Client, session.Proxy.Hostname)
	}
	session.Finished <- true
}

func (session *Session) HandlePacket(dirpckt proxy.DirectedPacket) {
	sender := dirpckt.Packet.GetSender()
	if sender != session.Client {
		session.Logger.Errorf("Invalid participant in session '%s'.", sender)
		return
	}
	session.RefreshExpiry()
	switch dirpckt.Packet.GetType() {
	case comms.Packet_CLIENT_OUTPUT:
		session.HandleOutput(dirpckt.Packet.GetPayload(), dirpckt.Packet.GetNonce())
	case comms.Packet_CLIENT_PTY_WINCH:
		dims := util.Unpack64(dirpckt.Packet.GetPtyDimensions())
		session.HandlePty(dims[0], dims[1], dims[2], dims[3])
	case comms.Packet_CLIENT_EXIT:
		session.HandleExit(nil, false)
	default:
		session.Logger.Errorf("Received invalid packet from '%s'.", sender)
	}
}

func (session *Session) StartOutputHandler() {
	for {
		buf := make([]byte, 2048)
		cnt, err := session.Pty.Read(buf)
		if err != nil {
			session.HandleExit(err, true)
			break
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		_, err = rand.Read(nonce)
		if err != nil {
			session.HandleExit(err, true)
			break
		}
		ciphertext := session.Cipher.Seal(nil, nonce, buf[:cnt], nil)
		session.Proxy.SendPacket(proxy.DirectedPacket{
			Category:  "client",
			Recipient: session.Client,
			Packet: comms.Packet{
				Type:    comms.Packet_SERVER_OUTPUT,
				Sender:  session.Proxy.Hostname,
				Payload: ciphertext,
				Nonce:   nonce,
			},
		})
	}
}

func (session *Session) StartTimeoutHandler() {
	for {
		if session.IsExpired() {
			session.HandleExit(fmt.Errorf("client timed out"), true)
		}
		time.Sleep(30 * time.Second)
	}
}

func (session *Session) Start() {
	go session.StartTimeoutHandler()
	session.Proxy.Start()
	go session.StartOutputHandler()
	<-session.Finished
}

func (session *Session) Close() {
	session.Proxy.Rps.Close()
	session.Pty.Close()
}
