//go:build !plan9
// +build !plan9

package sherpa

import (
	"errors"
	"syscall"
)

func isConnectionClosed(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}
