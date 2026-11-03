// Package proxyprotocol adapts the PROXY protocol implementation from
// github.com/pires/go-proxyproto to Mox's listener policy.
package proxyprotocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

const (
	headerTimeout = 30 * time.Second

	// PP2_CLIENT_SSL indicates that the client connected to the proxy over
	// SSL/TLS. Mox terminates TLS itself, so such connections are rejected.
	pp2ClientSSL byte = 0x01

	// The longest PROXY v1 line is 107 bytes including CRLF. The v1 parser
	// requires the complete line to fit in the reader's first buffer.
	headerReaderSize     = 108
	headerReaderPoolSize = 64
)

var headerReaders = make(chan *bufio.Reader, headerReaderPoolSize)

// Conn is a connection with the source and destination addresses supplied by a
// PROXY header. Deadlines and writes are delegated to the underlying connection.
type Conn struct {
	net.Conn
	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	closeErr   error
	prefix     []byte
	remoteAddr net.Addr
	localAddr  net.Addr
}

// Read first drains bytes already read while parsing the PROXY header, then
// reads directly from the underlying connection.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// Close marks the connection closed before closing the underlying connection,
// so buffered bytes are not returned by a later Read.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.prefix = nil
		c.mu.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

// RemoteAddr returns the source address from the PROXY header.
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

// LocalAddr returns the destination address from the PROXY header.
func (c *Conn) LocalAddr() net.Addr { return c.localAddr }

// NewConn verifies the underlying peer against trustedProxies, reads one
// required PROXY protocol v1 or v2 header, and returns a connection that reports
// the addresses from that header. The header is consumed exactly; following
// application data remains available from the returned connection.
//
// A valid v1 UNKNOWN or v2 LOCAL header is accepted and leaves the underlying
// connection addresses unchanged. Only TCP over IPv4 and IPv6 is accepted;
// Mox ignores v2 TLVs except for rejecting the client-TLS indication.
func NewConn(conn net.Conn, trustedProxies []*net.IPNet) (*Conn, error) {
	peerIP, err := addrIP(conn.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("get proxy peer address: %w", err)
	}
	trusted := false
	for _, network := range trustedProxies {
		if network != nil && network.Contains(peerIP) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, fmt.Errorf("proxy peer %s is not trusted", peerIP)
	}

	reader := takeHeaderReader(conn)
	defer releaseHeaderReader(reader)
	header, err := proxyproto.ReadHeaderTimeout(conn, reader, headerTimeout)
	if err != nil {
		return nil, fmt.Errorf("read proxy header: %w", err)
	}
	if err := validateHeader(header); err != nil {
		return nil, err
	}

	remoteAddr, localAddr := conn.RemoteAddr(), conn.LocalAddr()
	if !header.Command.IsLocal() {
		remoteAddr, localAddr, _ = header.TCPAddrs()
	}

	var prefix []byte
	if n := reader.Buffered(); n > 0 {
		prefix = make([]byte, n)
		if _, err := io.ReadFull(reader, prefix); err != nil {
			return nil, fmt.Errorf("read buffered proxy data: %w", err)
		}
	}
	return &Conn{Conn: conn, prefix: prefix, remoteAddr: remoteAddr, localAddr: localAddr}, nil
}

func takeHeaderReader(conn net.Conn) *bufio.Reader {
	select {
	case reader := <-headerReaders:
		reader.Reset(conn)
		return reader
	default:
		return bufio.NewReaderSize(conn, headerReaderSize)
	}
}

func releaseHeaderReader(reader *bufio.Reader) {
	reader.Reset(nil)
	select {
	case headerReaders <- reader:
	default:
	}
}

func validateHeader(header *proxyproto.Header) error {
	if header == nil {
		return errors.New("proxy header is missing")
	}

	// UNKNOWN (v1) and LOCAL (v2) carry no client address. The external parser
	// represents both as LOCAL, and Mox intentionally keeps the socket addresses.
	if header.Command.IsLocal() {
		switch header.TransportProtocol {
		case proxyproto.UNSPEC, proxyproto.TCPv4, proxyproto.TCPv6:
			return nil
		default:
			return fmt.Errorf("unsupported local proxy protocol %d", header.TransportProtocol)
		}
	}

	if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
		return fmt.Errorf("unsupported proxy protocol %d", header.TransportProtocol)
	}
	if _, _, ok := header.TCPAddrs(); !ok {
		return errors.New("proxy header has no TCP addresses")
	}

	// PROXY v2 TLVs are optional metadata. We only interpret the SSL TLV: its
	// client flag means that TLS was already used on the client-to-proxy leg,
	// which is not allowed for Mox listeners using PROXY protocol.
	if header.Version == 2 {
		tlvs, err := header.TLVs()
		if err != nil {
			return fmt.Errorf("invalid proxy TLVs: %w", err)
		}
		for _, tlv := range tlvs {
			if tlv.Type != proxyproto.PP2_TYPE_SSL {
				continue
			}
			if len(tlv.Value) < 5 {
				return errors.New("proxy SSL TLV is malformed")
			}
			if tlv.Value[0]&pp2ClientSSL != 0 {
				return errors.New("proxy header indicates client TLS was already handled by proxy")
			}
		}
	}
	return nil
}

func addrIP(addr net.Addr) (net.IP, error) {
	if a, ok := addr.(*net.TCPAddr); ok && a.IP != nil {
		return a.IP, nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", host)
	}
	return ip, nil
}
