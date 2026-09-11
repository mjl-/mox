package imapserver

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mox-"
)

type imapProxyAddrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c imapProxyAddrConn) LocalAddr() net.Addr  { return c.local }
func (c imapProxyAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestProxyProtocolIMAP(t *testing.T) {
	mox.Shutdown, mox.ShutdownCancel = context.WithCancel(context.Background())
	mox.Context, mox.ContextCancel = context.WithCancel(context.Background())

	pp := &config.ProxyProtocol{
		TrustedProxyNets: []*net.IPNet{{IP: net.ParseIP("192.0.2.0").To4(), Mask: net.CIDRMask(24, 32)}},
	}
	test := func(name string, header []byte, expectGreeting bool) {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			serverConn := imapProxyAddrConn{
				Conn:   server,
				local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 993},
				remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000},
			}
			done := make(chan struct{})
			go func() {
				serve("test", 1, nil, serverConn, false, false, true, false, "", pp)
				close(done)
			}()

			if _, err := client.Write(header); err != nil && expectGreeting {
				t.Fatal(err)
			}
			var conn net.Conn = client
			client.SetReadDeadline(time.Now().Add(time.Second))
			line, err := bufio.NewReader(conn).ReadString('\n')
			if expectGreeting {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(line, "* OK ") {
					t.Fatalf("got greeting %q", line)
				}
			} else if err == nil {
				t.Fatalf("got unexpected greeting %q", line)
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("IMAP server did not close")
			}
		})
	}

	test("v1", []byte("PROXY TCP4 203.0.113.4 198.51.100.2 1234 143\r\n"), true)
	test("missing-header", []byte("A001 NOOP\r\n"), false)
}
