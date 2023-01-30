package imapserver

import (
	"net"
)

// prefixConn is a net.Conn with a buffer from which the first reads are satisfied.
// used for STARTTLS where already did a buffered read of initial TLS data.
type prefixConn struct {
	prefix []byte
	net.Conn
}

func (c *prefixConn) Read(buf []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := len(buf)
		if n > len(c.prefix) {
			n = len(c.prefix)
		}
		copy(buf[:n], c.prefix[:n])
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(buf)
}
