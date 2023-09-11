package webmail

import (
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestParseListPostAddress(t *testing.T) {
	check := func(s string, exp *MessageAddress) {
		t.Helper()
		v := parseListPostAddress(s)
		tcompare(t, v, exp)
	}

	check("<mailto:list@host.com>", &MessageAddress{User: "list", Domain: dns.Domain{ASCII: "host.com"}})
	check("<mailto:moderator@host.com> (Postings are Moderated)", &MessageAddress{User: "moderator", Domain: dns.Domain{ASCII: "host.com"}})
	check("<mailto:moderator@host.com?subject=list%20posting>", &MessageAddress{User: "moderator", Domain: dns.Domain{ASCII: "host.com"}})
	check("NO (posting not allowed on this list)", nil)
	check("", nil)
}
