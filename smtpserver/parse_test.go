package smtpserver

import (
	"reflect"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func tcompare(t *testing.T, got, exp any) {
	t.Helper()
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("got %v, expected %v", got, exp)
	}
}

func TestParse(t *testing.T) {
	tcompare(t, newParser("<@hosta.int,@jkl.org:userc@d.bar.org>", false, nil).xpath(), smtp.Path{Localpart: "userc", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "d.bar.org"}}})

	tcompare(t, newParser("e+3Dmc2@example.com", false, nil).xtext(), "e=mc2@example.com")
	tcompare(t, newParser("", false, nil).xtext(), "")
}
