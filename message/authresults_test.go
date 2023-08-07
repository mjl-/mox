package message

import (
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestAuthResults(t *testing.T) {
	dom, err := dns.ParseDomain("møx.example")
	if err != nil {
		t.Fatalf("parsing domain: %v", err)
	}
	authRes := AuthResults{
		Hostname: dom.XName(true),
		Comment:  dom.ASCIIExtra(true),
		Methods: []AuthMethod{
			{"dkim", "pass", "", "", []AuthProp{{"header", "d", dom.XName(true), true, dom.ASCIIExtra(true)}}},
		},
	}
	s := authRes.Header()
	const exp = "Authentication-Results: (xn--mx-lka.example) møx.example; dkim=pass\r\n\theader.d=møx.example (xn--mx-lka.example)\r\n"
	if s != exp {
		t.Fatalf("got %q, expected %q", s, exp)
	}
}
