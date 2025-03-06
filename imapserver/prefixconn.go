package imapserver

import (
	"bufio"
	"io"
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
		n := min(len(buf), len(c.prefix))
		copy(buf[:n], c.prefix[:n])
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(buf)
}

// xprefixConn returns either the original net.Conn passed as parameter, or returns
// a *prefixConn returning the buffered data available in br followed data from the
// net.Conn passed in.
func xprefixConn(c net.Conn, br *bufio.Reader) net.Conn {
	n := br.Buffered()
	if n == 0 {
		return c
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(c, buf)
	xcheckf(err, "get buffered data")
	return &prefixConn{buf, c}
}
