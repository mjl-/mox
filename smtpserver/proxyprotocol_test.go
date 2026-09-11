package smtpserver

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
)

type proxyAddrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c proxyAddrConn) LocalAddr() net.Addr  { return c.local }
func (c proxyAddrConn) RemoteAddr() net.Addr { return c.remote }

func smtpProxyConfig() *config.ProxyProtocol {
	return &config.ProxyProtocol{
		TrustedProxyNets: []*net.IPNet{{IP: net.ParseIP("192.0.2.0").To4(), Mask: net.CIDRMask(24, 32)}},
	}
}

func TestProxyProtocolSMTP(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/mox.conf", dns.MockResolver{})
	defer ts.close()

	test := func(name string, header []byte, immediateTLS bool) {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			serverConn := proxyAddrConn{
				Conn:   server,
				local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 465},
				remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000},
			}
			done := make(chan struct{})
			go func() {
				serve("test", ts.cid, dns.Domain{ASCII: "mox.example"}, ts.serverConfig, serverConn, ts.resolver, immediateTLS, immediateTLS, false, false, 100<<20, immediateTLS, immediateTLS, false, nil, 0, smtpProxyConfig())
				close(done)
			}()

			if _, err := client.Write(header); err != nil {
				t.Fatal(err)
			}
			var conn net.Conn = client
			if immediateTLS {
				conn = tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "mox.example"})
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					t.Fatal(err)
				}
			}
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(line, "220 ") {
				t.Fatalf("got greeting %q", line)
			}
			conn.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("SMTP server did not close")
			}
		})
	}

	test("v1", []byte("PROXY TCP4 203.0.113.4 198.51.100.2 1234 25\r\n"), false)
	test("v2-tls", []byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x21, 0x11, 0, 12, 203, 0, 113, 4, 198, 51, 100, 2, 4, 210, 1, 209}, true)
}
