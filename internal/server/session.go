package server

import (
	"os"
    "os/exec"
    "errors"

	"github.com/creack/pty"
    "github.com/dmhacker/drsh/internal/packet"
)

type Session struct {
	Pty *os.File
}

func NewSession(sz *pty.Winsize) (error, Session) {
	cmd := exec.Command("bash")
	ptmx, err := pty.StartWithSize(cmd, sz)
	session := Session{
		Pty: ptmx,
	}
	return err, session
}

func (session *Session) ProcessInput(pckt *packet.Packet) error {
    switch pcktType := pckt.GetType(); pcktType {
    case packet.Packet_CLIENT_INPUT:
        session.Pty.Write(pckt.GetPayload())
        return nil
    case packet.Packet_CLIENT_PTY:
        sz := pty.Winsize {
            Rows: uint16(pckt.GetPtyRows()),
            Cols: uint16(pckt.GetPtyCols()),
            X: uint16(pckt.GetPtyXpixels()),
            Y: uint16(pckt.GetPtyYpixels()),
        }
        pty.Setsize(session.Pty, &sz)
        return nil
    default:
        // Client should not be sending SERVER packets
        // CLIENT_PING, CLIENT_HANDSHAKE, CLIENT_HEARTBEAT handled upstream
        return errors.New("Server received invalid packet from client")
    }
}

func (session *Session) ReceiveOutput() (error, packet.Packet) {
}

func (session *Session) Close() {
    session.Pty.Close() 
}
