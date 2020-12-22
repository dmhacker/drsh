package server

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type Session struct {
	Pty *os.File
}

func NewSession(rows uint32, cols uint32, xpixels uint32, ypixels uint32) (*Session, error) {
	sz := pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
		X:    uint16(xpixels),
		Y:    uint16(ypixels),
	}
	cmd := exec.Command("bash")
	ptmx, err := pty.StartWithSize(cmd, &sz)
	if err != nil {
		return nil, err
	}
	return &Session{
		Pty: ptmx,
	}, nil
}

func (session *Session) Send(payload []byte) {
	session.Pty.Write(payload)
}

func (session *Session) Resize(rows uint32, cols uint32, xpixels uint32, ypixels uint32) {
	sz := pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
		X:    uint16(xpixels),
		Y:    uint16(ypixels),
	}
	pty.Setsize(session.Pty, &sz)
}

func (session *Session) Receive(buffer []byte) (int, error) {
	return session.Pty.Read(buffer)
}

func (session *Session) Close() {
	session.Pty.Close()
}
