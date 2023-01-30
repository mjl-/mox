package spf

import (
	"net"
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestReceived(t *testing.T) {
	test := func(r Received, exp string) {
		t.Helper()
		s := r.Header()
		if s != exp {
			t.Fatalf("got %q, expected %q", s, exp)
		}
	}

	test(Received{
		Result:       StatusPass,
		Comment:      "c",
		ClientIP:     net.ParseIP("0.0.0.0"),
		EnvelopeFrom: "x@x",
		Helo:         dns.IPDomain{Domain: dns.Domain{ASCII: "y"}},
		Problem:      `a b"\`,
		Receiver:     "z",
		Identity:     ReceivedMailFrom,
		Mechanism:    "+ip4:0.0.0.0/0",
	}, "Received-SPF: pass (c) client-ip=0.0.0.0; envelope-from=\"x@x\"; helo=y;\r\n\tproblem=\"a b\\\"\\\\\"; mechanism=\"+ip4:0.0.0.0/0\"; receiver=z; identity=mailfrom\r\n")

	test(Received{
		Result:       StatusPass,
		ClientIP:     net.ParseIP("0.0.0.0"),
		EnvelopeFrom: "x@x",
		Helo:         dns.IPDomain{IP: net.ParseIP("2001:db8::1")},
		Receiver:     "z",
		Identity:     ReceivedMailFrom,
	}, "Received-SPF: pass client-ip=0.0.0.0; envelope-from=\"x@x\"; helo=\"2001:db8::1\";\r\n\treceiver=z; identity=mailfrom\r\n")
}
