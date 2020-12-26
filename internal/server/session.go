package server

import (
	"crypto/cipher"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"github.com/astromechza/etcpwdparse"
	"github.com/creack/pty"
	"github.com/monnand/dhkx"
)

type Session struct {
	Pty        *os.File
	Timestamp  time.Time
	Group      *dhkx.DHGroup
	PrivateKey *dhkx.DHKey
	Cipher     cipher.AEAD
}

func NewSession() (*Session, error) {
	g, err := dhkx.GetGroup(0)
	if err != nil {
		return nil, err
	}
	priv, err := g.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}
	// TODO: In the future, the client will decide which user they will log in as
	// For now, just assume that the user is the person running drshd
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, err
	}
	// Extract the shell that the user is using
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
	return &Session{
		Pty:        ptmx,
		Timestamp:  time.Now(),
		Group:      g,
		PrivateKey: priv,
	}, nil
}

func (session *Session) RefreshExpiry() {
	session.Timestamp = time.Now()
}

func (session *Session) IsExpired() bool {
	return time.Now().Sub(session.Timestamp).Minutes() >= 10
}

func (session *Session) Resize(rows uint16, cols uint16, xpixels uint16, ypixels uint16) {
	pty.Setsize(session.Pty, &pty.Winsize{
		Rows: rows,
		Cols: cols,
		X:    xpixels,
		Y:    ypixels,
	})
}

func (session *Session) Send(payload []byte) (int, error) {
	return session.Pty.Write(payload)
}

func (session *Session) Receive(buffer []byte) (int, error) {
	return session.Pty.Read(buffer)
}

func (session *Session) Close() {
	session.Pty.Close()
}
