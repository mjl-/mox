package publicsuffix

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestList(t *testing.T) {
	const data = `
// ===BEGIN ICANN DOMAINS===
com
            
*.jp
// Hosts in .hokkaido.jp can't set cookies below level 4...
*.hokkaido.jp
*.tokyo.jp
// ...except hosts in pref.hokkaido.jp, which can set cookies at level 3.
!pref.hokkaido.jp
!metro.tokyo.jp

bücher.example.com
// ===END ICANN DOMAINS===

ignored.example.com
`

	log := mlog.New("publicsuffix", nil)

	l, err := ParseList(log.Logger, strings.NewReader(data))
	if err != nil {
		t.Fatalf("parsing list: %s", err)
	}

	test := func(domain, orgDomain string) {
		t.Helper()

		d, err := dns.ParseDomain(domain)
		if err != nil {
			t.Fatalf("idna to unicode %q: %s", domain, err)
		}
		od, err := dns.ParseDomain(orgDomain)
		if err != nil {
			t.Fatalf("idna to unicode org domain %q: %s", orgDomain, err)
		}

		r := l.Lookup(context.Background(), log.Logger, d)
		if r != od {
			t.Fatalf("got %q, expected %q, for domain %q", r, orgDomain, domain)
		}
	}

	test("com", "com")
	test("foo.com", "foo.com")
	test("bar.foo.com", "foo.com")
	test("foo.bar.jp", "foo.bar.jp")
	test("baz.foo.bar.jp", "foo.bar.jp")
	test("bar.jp", "bar.jp")
	test("foo.bar.hokkaido.jp", "foo.bar.hokkaido.jp")
	test("baz.foo.bar.hokkaido.jp", "foo.bar.hokkaido.jp")
	test("bar.hokkaido.jp", "bar.hokkaido.jp")
	test("pref.hokkaido.jp", "pref.hokkaido.jp")
	test("foo.pref.hokkaido.jp", "pref.hokkaido.jp")
	test("WwW.EXAMPLE.Com", "example.com")
	test("bücher.example.com", "bücher.example.com")
	test("foo.bücher.example.com", "foo.bücher.example.com")
	test("bar.foo.bücher.example.com", "foo.bücher.example.com")
	test("xn--bcher-kva.example.com", "bücher.example.com")
	test("foo.xn--bcher-kva.example.com", "foo.bücher.example.com")
	test("bar.foo.xn--bcher-kva.example.com", "foo.bücher.example.com")
	test("x.ignored.example.com", "example.com")

	l, err = ParseList(log.Logger, bytes.NewReader(publicsuffixData))
	if err != nil {
		t.Fatalf("parsing public suffix list: %s", err)
	}

	// todo: add testcases from https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt
}
