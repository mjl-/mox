package dns

import (
	"errors"
	"testing"
)

func TestParseDomain(t *testing.T) {
	test := func(s string, exp Domain, expErr error) {
		t.Helper()
		dom, err := ParseDomain(s)
		if (err == nil) != (expErr == nil) || expErr != nil && !errors.Is(err, expErr) {
			t.Fatalf("parse domain %q: err %v, expected %v", s, err, expErr)
		}
		if expErr == nil && dom != exp {
			t.Fatalf("parse domain %q: got %#v, epxected %#v", s, dom, exp)
		}
	}

	// We rely on normalization of names throughout the code base.
	test("xmox.nl", Domain{"xmox.nl", ""}, nil)
	test("XMOX.NL", Domain{"xmox.nl", ""}, nil)
	test("TEST☺.XMOX.NL", Domain{"xn--test-3o3b.xmox.nl", "test☺.xmox.nl"}, nil)
	test("TEST☺.XMOX.NL", Domain{"xn--test-3o3b.xmox.nl", "test☺.xmox.nl"}, nil)
	test("ℂᵤⓇℒ。𝐒🄴", Domain{"curl.se", ""}, nil) // https://daniel.haxx.se/blog/2022/12/14/idn-is-crazy/
	test("xmox.nl.", Domain{}, errTrailingDot)
}
