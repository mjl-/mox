/*
Written 2024 by Harald Rudell <harald.rudell@gmail.com> (https://haraldrudell.github.io/haraldrudell/)
*/

package imaptemp

import (
	"net"
	"time"
)

// NoDeadline is a wrapper for a net.Conn socket that disables attempts to set a timeout on the socket
type NoDeadline struct{ net.Conn }

// NewNoDeadline wraps conn disabling any attempt to set a timeout on the socket
func NewNoDeadline(conn net.Conn) (noDeadline *NoDeadline) { return &NoDeadline{Conn: conn} }

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (n *NoDeadline) SetDeadline(t time.Time) (err error) { return }

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
func (n *NoDeadline) SetReadDeadline(t time.Time) (err error) { return }

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
func (n *NoDeadline) SetWriteDeadline(t time.Time) (err error) { return }
