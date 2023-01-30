package spf

import (
	"net"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	intptr := func(v int) *int {
		return &v
	}

	mustParseIP := func(s string) net.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad ip %q", s)
		}
		return ip
	}

	test := func(txt string, expRecord *Record) {
		t.Helper()
		valid := expRecord != nil
		r, _, err := ParseRecord(txt)
		if valid && err != nil {
			t.Fatalf("expected success, got err %s, txt %q", err, txt)
		}
		if !valid && err == nil {
			t.Fatalf("expected error, got record %#v, txt %q", r, txt)
		}
		if valid && !reflect.DeepEqual(r, expRecord) {
			t.Fatalf("unexpected record:\ngot: %v\nexpected: %v, txt %q", r, expRecord, txt)
		}
	}

	test("", nil)
	test("v=spf1", &Record{Version: "spf1"})
	test("v=SPF1", &Record{Version: "spf1"})
	test("V=spf1  ", &Record{Version: "spf1"})
	test("V=spf1 all Include:example.org a ?a -a +a ~a a:x a:x/0 a:x/24//64 a:x//64 mx mx:x ptr ptr:x IP4:10.0.0.1 ip4:0.0.0.0/0 ip4:10.0.0.1/24 ip6:2001:db8::1 ip6:2001:db8::1/128 exists:x REDIRECT=x exp=X Other=x",
		&Record{
			Version: "spf1",
			Directives: []Directive{
				{Mechanism: "all"},
				{Mechanism: "include", DomainSpec: "example.org"},
				{Mechanism: "a"},
				{Qualifier: "?", Mechanism: "a"},
				{Qualifier: "-", Mechanism: "a"},
				{Qualifier: "+", Mechanism: "a"},
				{Qualifier: "~", Mechanism: "a"},
				{Mechanism: "a", DomainSpec: "x"},
				{Mechanism: "a", DomainSpec: "x", IP4CIDRLen: intptr(0)},
				{Mechanism: "a", DomainSpec: "x", IP4CIDRLen: intptr(24), IP6CIDRLen: intptr(64)},
				{Mechanism: "a", DomainSpec: "x", IP6CIDRLen: intptr(64)},
				{Mechanism: "mx"},
				{Mechanism: "mx", DomainSpec: "x"},
				{Mechanism: "ptr"},
				{Mechanism: "ptr", DomainSpec: "x"},
				{Mechanism: "ip4", IP: mustParseIP("10.0.0.1"), IPstr: "10.0.0.1/32"},
				{Mechanism: "ip4", IP: mustParseIP("0.0.0.0"), IPstr: "0.0.0.0/0", IP4CIDRLen: intptr(0)},
				{Mechanism: "ip4", IP: mustParseIP("10.0.0.1"), IPstr: "10.0.0.1/24", IP4CIDRLen: intptr(24)},
				{Mechanism: "ip6", IP: mustParseIP("2001:db8::1"), IPstr: "2001:db8::1/128"},
				{Mechanism: "ip6", IP: mustParseIP("2001:db8::1"), IPstr: "2001:db8::1/128", IP6CIDRLen: intptr(128)},
				{Mechanism: "exists", DomainSpec: "x"},
			},
			Redirect:    "x",
			Explanation: "X",
			Other: []Modifier{
				{"Other", "x"},
			},
		},
	)
	test("V=spf1 -all", &Record{Version: "spf1", Directives: []Directive{{Qualifier: "-", Mechanism: "all"}}})
	test("v=spf1 !", nil) // Invalid character.
	test("v=spf1 ?redirect=bogus", nil)
	test("v=spf1 redirect=mox.example redirect=mox2.example", nil) // Duplicate redirect.
	test("v=spf1 exp=mox.example exp=mox2.example", nil)           // Duplicate exp.
	test("v=spf1 ip4:10.0.0.256", nil)                             // Invalid address.
	test("v=spf1 ip6:2001:db8:::1", nil)                           // Invalid address.
	test("v=spf1 ip4:10.0.0.1/33", nil)                            // IPv4 prefix >32.
	test("v=spf1 ip6:2001:db8::1/129", nil)                        // IPv6 prefix >128.
	test("v=spf1 a:mox.example/33", nil)                           // IPv4 prefix >32.
	test("v=spf1 a:mox.example//129", nil)                         // IPv6 prefix >128.
	test("v=spf1 a:mox.example//129", nil)                         // IPv6 prefix >128.
	test("v=spf1 exists:%%.%{l1r+}.%{d}",
		&Record{
			Version: "spf1",
			Directives: []Directive{
				{Mechanism: "exists", DomainSpec: "%%.%{l1r+}.%{d}"},
			},
		},
	)
	test("v=spf1 exists:%{l1r+}..", nil)     // Empty toplabel in domain-end.
	test("v=spf1 exists:%{l1r+}._.", nil)    // Invalid toplabel in domain-end.
	test("v=spf1 exists:%{l1r+}.123.", nil)  // Invalid toplabel in domain-end.
	test("v=spf1 exists:%{l1r+}.bad-.", nil) // Invalid toplabel in domain-end.
	test("v=spf1 exists:%{l1r+}.-bad.", nil) // Invalid toplabel in domain-end.
	test("v=spf1 exists:%{l1r+}./.", nil)    // Invalid toplabel in domain-end.
	test("v=spf1 exists:%{x}", nil)          // Unknown macro-letter.
	test("v=spf1 exists:%{s0}", nil)         // Invalid digits.
	test("v=spf1 exists:%{ir}.%{l1r+}.%{d}",
		&Record{
			Version: "spf1",
			Directives: []Directive{
				{Mechanism: "exists", DomainSpec: "%{ir}.%{l1r+}.%{d}"},
			},
		},
	)

	orig := `V=SPF1 all Include:example.org a ?a -a +a ~a a:x a:x/0 a:x/24//64 a:x//64 mx mx:x ptr ptr:x IP4:10.0.0.1 ip4:0.0.0.0/0 ip4:10.0.0.1/24 ip6:2001:db8::1 ip6:2001:db8::1/128 exists:x REDIRECT=x exp=X Other=x`
	exp := `v=spf1 all include:example.org a ?a -a +a ~a a:x a:x/0 a:x/24//64 a:x//64 mx mx:x ptr ptr:x ip4:10.0.0.1 ip4:0.0.0.0/0 ip4:10.0.0.1/24 ip6:2001:db8::1 ip6:2001:db8::1/128 exists:x redirect=x exp=X Other=x`
	r, _, err := ParseRecord(orig)
	if err != nil {
		t.Fatalf("parsing original: %s", err)
	}
	record, err := r.Record()
	if err != nil {
		t.Fatalf("making dns record: %s", err)
	}
	if record != exp {
		t.Fatalf("packing dns record, got %q, expected %q", record, exp)
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add("")
	f.Add("v=spf1")
	f.Add(`V=SPF1 all Include:example.org a ?a -a +a ~a a:x a:x/0 a:x/24//64 a:x//64 mx mx:x ptr ptr:x IP4:10.0.0.1 ip4:0.0.0.0/0 ip4:10.0.0.1/24 ip6:2001:db8::1 ip6:2001:db8::1/128 exists:x REDIRECT=x exp=X Other=x`)
	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			if _, err := r.Record(); err != nil {
				t.Errorf("r.Record for %s, %#v: %s", s, r, err)
			}
		}
	})
}
