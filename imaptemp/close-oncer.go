/*
Written 2024 by Harald Rudell <harald.rudell@gmail.com> (https://haraldrudell.github.io/haraldrudell/)
*/

package imaptemp

import (
	"net"
	"sync/atomic"
)

// closeOncer ensures a net.Conn to have thread-safe idempotent observable Close
type closeOncer struct {
	net.Conn
	CloseWait chan struct{}
	IsClosed  atomic.Bool
}

// newCloseOncer returns a wrapper making the net.Conn to have thread-safe idempotent observable Close
func newCloseOncer(conn net.Conn) (c net.Conn) {
	return &closeOncer{
		Conn:      conn,
		CloseWait: make(chan struct{}),
	}
}

// Close is thread-safe idempotent observable
//   - only the winner thread actually closing receives a possible error
//   - no thread returns prior to the connection being closed
//   - Close can be awaited by <-c.CloseWait
//   - Close is observable by c.IsClosed.Load()
func (c *closeOncer) Close() (err error) {
	if !c.IsClosed.CompareAndSwap(false, true) {
		// loser thread gets to wait
		<-c.CloseWait
		return
	}
	defer close(c.CloseWait)

	// winner thread does close
	err = c.Conn.Close()

	return
}
