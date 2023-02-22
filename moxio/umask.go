package moxio

import (
	"fmt"
	"syscall"
)

// CheckUmask checks that the umask is 7 for "other". Because files written
// should not be world-accessible. E.g. database files, and the control unix
// domain socket.
func CheckUmask() error {
	old := syscall.Umask(007)
	syscall.Umask(old)
	if old&7 != 7 {
		return fmt.Errorf(`umask must have 7 for world/other, e.g. 007, not current %03o`, old)
	}
	return nil
}
