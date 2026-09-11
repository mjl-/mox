package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

var (
	trustedLocal   = &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}
	trustedNetwork = &net.IPNet{IP: net.ParseIP("192.0.2.0").To4(), Mask: net.CIDRMask(24, 32)}
)

const maxV1Header = 108

var v2Signature = [...]byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10}

func run(t *testing.T, input []byte) (*Conn, net.Conn, error) {
	t.Helper()
	server, client := net.Pipe()
	serverConn := addrConn{Conn: server, local: &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 25}, remote: trustedLocal}
	go func() {
		_, _ = client.Write(input)
		_ = client.Close()
	}()
	conn, clientConn, err := func() (*Conn, net.Conn, error) {
		c, err := NewConn(serverConn, []*net.IPNet{trustedNetwork})
		return c, client, err
	}()
	if err != nil {
		_ = client.Close()
	}
	return conn, clientConn, err
}

func TestV1(t *testing.T) {
	conn, client, err := run(t, []byte("PROXY TCP4 203.0.113.4 198.51.100.2 1234 25\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got := conn.RemoteAddr().String(); got != "203.0.113.4:1234" {
		t.Fatalf("remote address %s", got)
	}
	if got := conn.LocalAddr().String(); got != "198.51.100.2:25" {
		t.Fatalf("local address %s", got)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("application data %q, %v", buf, err)
	}
}

func TestV1IPv6AndUnknown(t *testing.T) {
	conn, client, err := run(t, []byte("PROXY TCP6 2001:db8::4 2001:db8::5 1234 993\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if got := conn.RemoteAddr().String(); got != "[2001:db8::4]:1234" {
		t.Fatalf("remote address %s", got)
	}

	conn, client, err = run(t, []byte("PROXY UNKNOWN\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if got := conn.RemoteAddr().String(); got != trustedLocal.String() {
		t.Fatalf("unknown remote address %s", got)
	}
}

func v2Header(command, family, protocol byte, payload []byte) []byte {
	b := make([]byte, 16+len(payload))
	copy(b, v2Signature[:])
	b[12] = 2<<4 | command
	b[13] = family<<4 | protocol
	binary.BigEndian.PutUint16(b[14:16], uint16(len(payload)))
	copy(b[16:], payload)
	return b
}

func TestV2(t *testing.T) {
	payload := make([]byte, 12)
	copy(payload, net.ParseIP("203.0.113.8").To4())
	copy(payload[4:], net.ParseIP("198.51.100.8").To4())
	binary.BigEndian.PutUint16(payload[8:], 4321)
	binary.BigEndian.PutUint16(payload[10:], 465)
	conn, client, err := run(t, append(v2Header(1, 1, 1, payload), []byte("data")...))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got := conn.RemoteAddr().String(); got != "203.0.113.8:4321" {
		t.Fatalf("remote address %s", got)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "data" {
		t.Fatalf("application data %q, %v", buf, err)
	}

	conn, client, err = run(t, v2Header(0, 0, 0, []byte("ignored")))
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if got := conn.RemoteAddr().String(); got != trustedLocal.String() {
		t.Fatalf("local remote address %s", got)
	}
}

func TestV2IPv6AndTLV(t *testing.T) {
	payload := make([]byte, 36+3)
	copy(payload, net.ParseIP("2001:db8::8"))
	copy(payload[16:], net.ParseIP("2001:db8::9"))
	binary.BigEndian.PutUint16(payload[32:], 993)
	binary.BigEndian.PutUint16(payload[34:], 1993)
	copy(payload[36:], []byte{1, 1, 0})
	conn, client, err := run(t, v2Header(1, 2, 1, payload))
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if got := conn.LocalAddr().String(); got != "[2001:db8::9]:1993" {
		t.Fatalf("local address %s", got)
	}
}

func TestRejectsUntrustedAndMalformed(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	conn := addrConn{Conn: server, local: trustedLocal, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 1000}}
	if _, err := NewConn(conn, []*net.IPNet{trustedNetwork}); err == nil {
		t.Fatal("untrusted peer accepted")
	}

	for _, input := range [][]byte{
		[]byte("HELO example\r\n"),
		[]byte("PROXY TCP4 203.0.113.1 198.51.100.1 1 25\n"),
		bytes.Repeat([]byte("x"), maxV1Header+1),
		v2Header(1, 3, 1, make([]byte, 12)),
		v2Header(1, 1, 2, make([]byte, 12)),
		v2Header(1, 1, 1, make([]byte, 11)),
	} {
		_, _, err := run(t, input)
		if err == nil {
			t.Errorf("accepted malformed header %q", input)
		}
	}
}
