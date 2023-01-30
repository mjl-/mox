package smtp

import (
	"errors"
	"testing"
)

func TestParseLocalpart(t *testing.T) {
	good := func(s string) {
		t.Helper()
		_, err := ParseLocalpart(s)
		if err != nil {
			t.Fatalf("unexpected error for localpart %q: %v", s, err)
		}
	}

	bad := func(s string) {
		t.Helper()
		_, err := ParseLocalpart(s)
		if err == nil {
			t.Fatalf("did not see expected error for localpart %q", s)
		}
		if !errors.Is(err, ErrBadLocalpart) {
			t.Fatalf("expected ErrBadLocalpart, got %v", err)
		}
	}

	good("user")
	good("a")
	good("a.b.c")
	good(`""`)
	good(`"ok"`)
	good(`"a.bc"`)
	bad("")
	bad(`"`)          // missing ending dquot
	bad("\x00")       // control not allowed
	bad("\"\\")       // ending with backslash
	bad("\"\x01")     // control not allowed in dquote
	bad(`""leftover`) // leftover data after close dquote
}

func TestParseAddress(t *testing.T) {
	good := func(s string) {
		t.Helper()
		_, err := ParseAddress(s)
		if err != nil {
			t.Fatalf("unexpected error for localpart %q: %v", s, err)
		}
	}

	bad := func(s string) {
		t.Helper()
		_, err := ParseAddress(s)
		if err == nil {
			t.Fatalf("did not see expected error for localpart %q", s)
		}
		if !errors.Is(err, ErrBadAddress) {
			t.Fatalf("expected ErrBadAddress, got %v", err)
		}
	}

	good("user@example.com")
	bad("user@@example.com")
	bad("user")                   // missing @domain
	bad("@example.com")           // missing localpart
	bad(`"@example.com`)          // missing ending dquot or domain
	bad("\x00@example.com")       // control not allowed
	bad("\"\\@example.com")       // missing @domain
	bad("\"\x01@example.com")     // control not allowed in dquote
	bad(`""leftover@example.com`) // leftover data after close dquot
}

func TestPackLocalpart(t *testing.T) {
	var l = []struct {
		input, expect string
	}{
		{``, `""`},     // No atom.
		{`a.`, `"a."`}, // Empty atom not allowed.
		{`a.b`, `a.b`}, // Fine.
		{"azAZ09!#$%&'*+-/=?^_`{|}~", "azAZ09!#$%&'*+-/=?^_`{|}~"}, // All ascii that are fine as atom.
		{` `, `" "`},
		{"\x01", "\"\x01\""}, // todo: should probably return an error for control characters.
		{"<>", `"<>"`},
	}

	for _, e := range l {
		r := Localpart(e.input).String()
		if r != e.expect {
			t.Fatalf("PackLocalpart for %q, expect %q, got %q", e.input, e.expect, r)
		}
	}
}
