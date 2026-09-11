// Package proxyprotocol adapts the PROXY protocol implementation from
// github.com/pires/go-proxyproto to Mox's listener policy.
package proxyprotocol

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

const headerTimeout = 30 * time.Second

// Conn is a connection with the source and destination addresses supplied by a
// PROXY header. All other operations, including closing and deadlines, are
// delegated to the underlying connection.
type Conn struct {
	net.Conn
	reader     *bufio.Reader
	remoteAddr net.Addr
	localAddr  net.Addr
}

// Read first drains bytes already buffered while parsing the PROXY header,
// then reads directly from the underlying connection.
func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
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
// TLVs are parsed by the external library but not interpreted by Mox.
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

	reader := bufio.NewReader(conn)
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
	return &Conn{Conn: conn, reader: reader, remoteAddr: remoteAddr, localAddr: localAddr}, nil
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
