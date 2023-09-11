package webmail

import (
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestFormatFirstLine(t *testing.T) {
	check := func(body, expLine string) {
		t.Helper()

		line, err := formatFirstLine(strings.NewReader(body))
		tcompare(t, err, nil)
		if line != expLine {
			t.Fatalf("got %q, expected %q, for body %q", line, expLine, body)
		}
	}

	check("", "")
	check("single line", "single line\n")
	check("single line\n", "single line\n")
	check("> quoted\n", "[...]\n")
	check("> quoted\nresponse\n", "[...]\nresponse\n")
	check("> quoted\n[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check("[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check("[…]\nresponse after author snip\n", "[…]\nresponse after author snip\n")
	check(">> quoted0\n> quoted1\n>quoted2\n[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check(">quoted\n\n>quoted\ncoalesce line-separated quotes\n", "[...]\ncoalesce line-separated quotes\n")
	check("On <date> <user> wrote:\n> hi\nresponse", "[...]\nresponse\n")
	check("On <longdate>\n<user> wrote:\n> hi\nresponse", "[...]\nresponse\n")
	check("> quote\nresponse\n--\nsignature\n", "[...]\nresponse\n")
	check("> quote\nline1\nline2\nline3\n", "[...]\nline1\nline2\nline3\n")
}

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
