package moxio

import (
	"errors"
	"net"
	"syscall"
)

// In separate file because of import of syscall.

// IsClosed returns whether i/o failed, typically because the connection is closed
// or otherwise cannot be used for further i/o.
//
// Used to prevent error logging for connections that are closed.
func IsClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || isRemoteTLSError(err)
}

// A remote TLS client can send a message indicating failure, this makes it back to
// us as a write error.
func isRemoteTLSError(err error) bool {
	var netErr *net.OpError
	return errors.As(err, &netErr) && netErr.Op == "remote error"
}
