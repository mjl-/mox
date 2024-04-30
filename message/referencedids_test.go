package message

import (
	"strings"
	"testing"
)

func TestReferencedIDs(t *testing.T) {
	check := func(msg string, expRefs []string) {
		t.Helper()

		p, err := Parse(pkglog.Logger, true, strings.NewReader(msg))
		tcheck(t, err, "parsing message")

		h, err := p.Header()
		tcheck(t, err, "parsing header")

		refs, err := ReferencedIDs(h["References"], h["In-Reply-To"])
		tcheck(t, err, "parsing references/in-reply-to")
		tcompare(t, refs, expRefs)
	}

	check("References: bogus\r\n", nil)
	check("References: <User@host>\r\n", []string{"user@host"})
	check("References: <User@tést.example>\r\n", []string{"user@tést.example"})
	check("References: <User@xn--tst-bma.example>\r\n", []string{"user@xn--tst-bma.example"})
	check("References: <User@bad_label.domain>\r\n", []string{"user@bad_label.domain"})
	check("References: <truncated@hos <user@host>\r\n", []string{"user@host"})
	check("References: <previously wrapped@host>\r\n", []string{"previouslywrapped@host"})
	check("References: <user1@host> <user2@other.example>\r\n", []string{"user1@host", "user2@other.example"})
	check("References: <missinghost>\r\n", []string{"missinghost"})
	check("References: <user@host@time>\r\n", []string{"user@host@time"})
	check("References: bogus bad <user@host>\r\n", []string{"user@host"})
	check("In-Reply-To: <user@host> more stuff\r\nReferences: bogus bad\r\n", []string{"user@host"})
}
