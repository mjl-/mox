package moxio

import (
	"io"
	"net"
)

// PrefixConn is a net.Conn prefixed with a reader that is first drained.
// Used for STARTTLS where already did a buffered read of initial TLS data.
type PrefixConn struct {
	PrefixReader io.Reader // If not nil, reads are fulfilled from here. It is cleared when a read returns io.EOF.
	net.Conn
}

// Read returns data when PrefixReader when not nil, and net.Conn otherwise.
func (c *PrefixConn) Read(buf []byte) (int, error) {
	if c.PrefixReader != nil {
		n, err := c.PrefixReader.Read(buf)
		if err == io.EOF {
			c.PrefixReader = nil
		}
		return n, err
	}
	return c.Conn.Read(buf)
}
