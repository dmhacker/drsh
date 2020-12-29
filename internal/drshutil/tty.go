package drshutil

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
)

func TerminalSize() (*pty.Winsize, error) {
	ws := new(pty.Winsize)
	rc, _, _ := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdin),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)))
	if int(rc) == -1 {
		return nil, fmt.Errorf("could not obtain tty dimensions")
	}
	return ws, nil
}
