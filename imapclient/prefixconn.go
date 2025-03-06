package imapclient

import (
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

// xprefixConn checks if there are any buffered unconsumed reads. If not, it
// returns c.conn. Otherwise, it returns a *prefixConn from which the buffered data
// can be read followed by data from c.conn.
func (c *Conn) xprefixConn() net.Conn {
	n := c.br.Buffered()
	if n == 0 {
		return c.conn
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(c.br, buf)
	c.xcheckf(err, "get buffered data")
	return &prefixConn{buf, c.conn}
}
