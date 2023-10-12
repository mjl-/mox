package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func TestLookup(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"temperror.example.": {"irrelevant"},
			"malformed.example.": {"v=spf1 !"},
			"multiple.example.":  {"v=spf1", "v=spf1"},
			"nonspf.example.":    {"something else"},
			"ok.example.":        {"v=spf1"},
		},
		Fail: []string{
			"txt temperror.example.",
		},
	}

	test := func(domain string, expStatus Status, expRecord *Record, expErr error) {
		t.Helper()

		d := dns.Domain{ASCII: domain}
		status, txt, record, _, err := Lookup(context.Background(), resolver, d)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected err %v", err, expErr)
		}
		if err != nil {
			return
		}
		if status != expStatus || txt == "" || !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("got status %q, txt %q, record %#v, expected %q, ..., %#v", status, txt, record, expStatus, expRecord)
		}
	}

	test("..", StatusNone, nil, ErrName)
	test("absent.example", StatusNone, nil, ErrNoRecord)
	test("temperror.example", StatusTemperror, nil, ErrDNS)
	test("malformed.example", StatusPermerror, nil, ErrRecordSyntax)
	test("multiple.example", StatusPermerror, nil, ErrMultipleRecords)
	test("nonspf.example", StatusNone, nil, ErrNoRecord)
	test("ok.example", StatusNone, &Record{Version: "spf1"}, nil)
}

func TestExpand(t *testing.T) {
	defArgs := Args{
		senderLocalpart: "strong-bad",
		senderDomain:    dns.Domain{ASCII: "email.example.com"},
		domain:          dns.Domain{ASCII: "email.example.com"},

		MailFromLocalpart: "x",
		MailFromDomain:    dns.Domain{ASCII: "mox.example"},
		HelloDomain:       dns.IPDomain{Domain: dns.Domain{ASCII: "mx.mox.example"}},
		LocalIP:           net.ParseIP("10.10.10.10"),
		LocalHostname:     dns.Domain{ASCII: "self.example"},
	}

	resolver := dns.MockResolver{
		PTR: map[string][]string{
			"10.0.0.1": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
			"10.0.0.2": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
			"10.0.0.3": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
		},
		A: map[string][]string{
			"mx.mox.example.":     {"10.0.0.1"},
			"sub.mx.mox.example.": {"10.0.0.2"},
			"other.example.":      {"10.0.0.3"},
		},
	}

	mustParseIP := func(s string) net.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad ip %q", s)
		}
		return ip
	}

	ctx := context.Background()

	// Examples from ../rfc/7208:1777
	test := func(dns bool, macro, ip, exp string) {
		t.Helper()

		args := defArgs
		args.dnsRequests = new(int)
		args.voidLookups = new(int)
		if ip != "" {
			args.RemoteIP = mustParseIP(ip)
		}

		r, _, err := expandDomainSpec(ctx, resolver, macro, args, dns)
		if (err == nil) != (exp != "") {
			t.Fatalf("got err %v, expected expansion %q, for macro %q", err, exp, macro)
		}
		if r != exp {
			t.Fatalf("got expansion %q, expected %q, for macro %q", r, exp, macro)
		}
	}

	testDNS := func(macro, ip, exp string) {
		t.Helper()
		test(true, macro, ip, exp)
	}

	testExpl := func(macro, ip, exp string) {
		t.Helper()
		test(false, macro, ip, exp)
	}

	testDNS("%{s}", "", "strong-bad@email.example.com")
	testDNS("%{o}", "", "email.example.com")
	testDNS("%{d}", "", "email.example.com")
	testDNS("%{d4}", "", "email.example.com")
	testDNS("%{d3}", "", "email.example.com")
	testDNS("%{d2}", "", "example.com")
	testDNS("%{d1}", "", "com")
	testDNS("%{dr}", "", "com.example.email")
	testDNS("%{d2r}", "", "example.email")
	testDNS("%{l}", "", "strong-bad")
	testDNS("%{l-}", "", "strong.bad")
	testDNS("%{lr}", "", "strong-bad")
	testDNS("%{lr-}", "", "bad.strong")
	testDNS("%{l1r-}", "", "strong")

	testDNS("%", "", "")
	testDNS("%b", "", "")
	testDNS("%{", "", "")
	testDNS("%{s", "", "")
	testDNS("%{s1", "", "")
	testDNS("%{s0}", "", "")
	testDNS("%{s1r", "", "")
	testDNS("%{s99999999999999999999999999999999999999999999999999999999999999999999999}", "", "")

	testDNS("%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr._spf.example.com")
	testDNS("%{lr-}.lp._spf.%{d2}", "192.0.2.3", "bad.strong.lp._spf.example.com")
	testDNS("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com")
	testDNS("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr.strong.lp._spf.example.com")
	testDNS("%{d2}.trusted-domains.example.net", "192.0.2.3", "example.com.trusted-domains.example.net")

	testDNS("%{ir}.%{v}._spf.%{d2}", "2001:db8::cb01", "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com")

	// Additional.
	testDNS("%%%-%_", "10.0.0.1", "%%20 ")
	testDNS("%{p}", "10.0.0.1", "mx.mox.example.")
	testDNS("%{p}", "10.0.0.2", "sub.mx.mox.example.")
	testDNS("%{p}", "10.0.0.3", "other.example.")
	testDNS("%{p}", "10.0.0.4", "unknown")
	testExpl("%{c}", "10.0.0.1", "10.10.10.10")
	testExpl("%{r}", "10.0.0.1", "self.example")
	orig := timeNow
	now := orig()
	defer func() {
		timeNow = orig
	}()
	timeNow = func() time.Time {
		return now
	}
	testExpl("%{t}", "10.0.0.1", fmt.Sprintf("%d", now.Unix()))
	// DNS name can be 253 bytes long, each label can be 63 bytes.
	xlabel := make([]byte, 62)
	for i := range xlabel {
		xlabel[i] = 'a'
	}
	label := string(xlabel)
	name := label + "." + label + "." + label + "." + label // 4*62+3 = 251
	testDNS("x."+name, "10.0.0.1", "x."+name)               // Still fits.
	testDNS("xx."+name, "10.0.0.1", name)                   // Does not fit, "xx." is truncated to make it fit.
	testDNS("%{p}..", "10.0.0.1", "")
	testDNS("%{h}", "10.0.0.1", "mx.mox.example")
}

func TestVerify(t *testing.T) {
	xip := func(s string) net.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad ip: %q", s)
		}
		return ip
	}
	iplist := func(l ...string) []net.IP {
		r := make([]net.IP, len(l))
		for i, s := range l {
			r[i] = xip(s)
		}
		return r
	}

	// ../rfc/7208:2975 Appendix A.  Extended Examples
	r := dns.MockResolver{
		PTR: map[string][]string{
			"192.0.2.10":  {"example.com."},
			"192.0.2.11":  {"example.com."},
			"192.0.2.65":  {"amy.example.com."},
			"192.0.2.66":  {"bob.example.com."},
			"192.0.2.129": {"mail-a.example.com."},
			"192.0.2.130": {"mail-b.example.com."},
			"192.0.2.140": {"mail-c.example.org."},
			"10.0.0.4":    {"bob.example.com."},
		},
		TXT: map[string][]string{
			// Additional from DNSBL, ../rfc/7208:3115
			"mobile-users._spf.example.com.": {"v=spf1 exists:%{l1r+}.%{d}"},
			"remote-users._spf.example.com.": {"v=spf1 exists:%{ir}.%{l1r+}.%{d}"},

			// Additional ../rfc/7208:3171
			"ip4._spf.example.com.": {"v=spf1 -ip4:192.0.2.0/24 +all"},
			"ptr._spf.example.com.": {"v=spf1 -ptr:example.com +all"}, // ../rfc/7208-eid6216 ../rfc/7208:3172

			// Additional tests
			"_spf.example.com.":      {"v=spf1 include:_netblock.example.com -all"},
			"_netblock.example.com.": {"v=spf1 ip4:192.0.2.128/28 -all"},
		},
		A: map[string][]string{
			"example.com.":        {"192.0.2.10", "192.0.2.11"},
			"amy.example.com.":    {"192.0.2.65"},
			"bob.example.com.":    {"192.0.2.66"},
			"mail-a.example.com.": {"192.0.2.129"},
			"mail-b.example.com.": {"192.0.2.130"},
			"mail-c.example.org.": {"192.0.2.140"},

			// Additional from DNSBL, ../rfc/7208:3115
			"mary.mobile-users._spf.example.com.":               {"127.0.0.2"},
			"fred.mobile-users._spf.example.com.":               {"127.0.0.2"},
			"15.15.168.192.joel.remote-users._spf.example.com.": {"127.0.0.2"},
			"16.15.168.192.joel.remote-users._spf.example.com.": {"127.0.0.2"},
		},
		AAAA: map[string][]string{},
		MX: map[string][]*net.MX{
			"example.com.": {
				{Host: "mail-a.example.com.", Pref: 10},
				{Host: "mail-b.example.com.", Pref: 20},
			},
			"example.org.": {
				{Host: "mail-c.example.org.", Pref: 10},
			},
		},
	}

	ctx := context.Background()

	verify := func(ip net.IP, localpart string, status Status) {
		t.Helper()

		args := Args{
			MailFromLocalpart: smtp.Localpart(localpart),
			MailFromDomain:    dns.Domain{ASCII: "example.com"},
			RemoteIP:          ip,
			LocalIP:           xip("127.0.0.1"),
			LocalHostname:     dns.Domain{ASCII: "localhost"},
		}
		received, _, _, _, err := Verify(ctx, r, args)
		if received.Result != status {
			t.Fatalf("got status %q, expected %q, for ip %q (err %v)", received.Result, status, ip, err)
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}

	test := func(txt string, ips []net.IP, only bool) {
		r.TXT["example.com."] = []string{txt}
		seen := map[string]struct{}{}
		for _, ip := range ips {
			verify(ip, "", StatusPass)
			seen[ip.String()] = struct{}{}
		}
		if !only {
			return
		}
		for ip := range r.PTR {
			if _, ok := seen[ip]; ok {
				continue
			}
			verify(xip(ip), "", StatusFail)
		}
	}

	// ../rfc/7208:3031 A.1. Simple Examples
	test("v=spf1 +all", iplist("192.0.2.129", "1.2.3.4"), false)
	test("v=spf1 a -all", iplist("192.0.2.10", "192.0.2.11"), true)
	test("v=spf1 a:example.org -all", iplist(), true)
	test("v=spf1 mx -all", iplist("192.0.2.129", "192.0.2.130"), true)
	test("v=spf1 mx:example.org -all", iplist("192.0.2.140"), true)
	test("v=spf1 mx mx:example.org -all", iplist("192.0.2.129", "192.0.2.130", "192.0.2.140"), true)
	test("v=spf1 mx/30 mx:example.org/30 -all", iplist("192.0.2.129", "192.0.2.130", "192.0.2.140"), true)
	test("v=spf1 ptr -all", iplist("192.0.2.10", "192.0.2.11", "192.0.2.65", "192.0.2.66", "192.0.2.129", "192.0.2.130"), true)
	test("v=spf1 ip4:192.0.2.128/28 -all", iplist("192.0.2.129", "192.0.2.130", "192.0.2.140"), true)

	// Additional tests
	test("v=spf1 redirect=_spf.example.com", iplist("192.0.2.129", "192.0.2.130", "192.0.2.140"), true)

	// Additional from DNSBL, ../rfc/7208:3115
	r.TXT["example.com."] = []string{"v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all"}
	verify(xip("1.2.3.4"), "mary", StatusPass)
	verify(xip("1.2.3.4"), "fred", StatusPass)
	verify(xip("1.2.3.4"), "fred+wildcard", StatusPass)
	verify(xip("1.2.3.4"), "joel", StatusFail)
	verify(xip("1.2.3.4"), "other", StatusFail)
	verify(xip("192.168.15.15"), "joel", StatusPass)
	verify(xip("192.168.15.16"), "joel", StatusPass)
	verify(xip("192.168.15.17"), "joel", StatusFail)
	verify(xip("192.168.15.17"), "other", StatusFail)

	// Additional ../rfc/7208:3171
	r.TXT["example.com."] = []string{"v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all"}
	r.PTR["192.0.2.1"] = []string{"a.example.com."}
	r.PTR["192.0.0.1"] = []string{"b.example.com."}
	r.A["a.example.com."] = []string{"192.0.2.1"}
	r.A["b.example.com."] = []string{"192.0.0.1"}

	verify(xip("192.0.2.1"), "", StatusPass) // IP in range and PTR matches.
	verify(xip("192.0.2.2"), "", StatusFail) // IP in range but no PTR match.
	verify(xip("192.0.0.1"), "", StatusFail) // PTR match but IP not in range.
	verify(xip("192.0.0.2"), "", StatusFail) // No PTR match and IP not in range.
}

// ../rfc/7208:3093
func TestVerifyMultipleDomain(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"example.org.":    {"v=spf1 include:example.com include:example.net -all"},
			"la.example.org.": {"v=spf1 redirect=example.org"},
			"example.com.":    {"v=spf1 ip4:10.0.0.1 -all"},
			"example.net.":    {"v=spf1 ip4:10.0.0.2 -all"},
		},
	}

	verify := func(domain, ip string, status Status) {
		t.Helper()

		args := Args{
			MailFromDomain: dns.Domain{ASCII: domain},
			RemoteIP:       net.ParseIP(ip),
			LocalIP:        net.ParseIP("127.0.0.1"),
			LocalHostname:  dns.Domain{ASCII: "localhost"},
		}
		received, _, _, _, err := Verify(context.Background(), resolver, args)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if received.Result != status {
			t.Fatalf("got status %q, expected %q, for ip %q", received.Result, status, ip)
		}
	}

	verify("example.com", "10.0.0.1", StatusPass)
	verify("example.net", "10.0.0.2", StatusPass)
	verify("example.com", "10.0.0.2", StatusFail)
	verify("example.net", "10.0.0.1", StatusFail)
	verify("example.org", "10.0.0.1", StatusPass)
	verify("example.org", "10.0.0.2", StatusPass)
	verify("example.org", "10.0.0.3", StatusFail)
	verify("la.example.org", "10.0.0.1", StatusPass)
	verify("la.example.org", "10.0.0.2", StatusPass)
	verify("la.example.org", "10.0.0.3", StatusFail)
}

func TestVerifyScenarios(t *testing.T) {
	test := func(resolver dns.Resolver, args Args, expStatus Status, expDomain string, expExpl string, expErr error) {
		t.Helper()

		recv, d, expl, _, err := Verify(context.Background(), resolver, args)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %v, expected %v", err, expErr)
		}
		if expStatus != recv.Result || expDomain != "" && d.ASCII != expDomain || expExpl != "" && expl != expExpl {
			t.Fatalf("got status %q, domain %q, expl %q, err %v", recv.Result, d, expl, err)
		}
	}

	r := dns.MockResolver{
		TXT: map[string][]string{
			"mox.example.":                {"v=spf1 ip6:2001:db8::0/64 -all"},
			"void.example.":               {"v=spf1 exists:absent1.example exists:absent2.example ip4:1.2.3.4 exists:absent3.example -all"},
			"loop.example.":               {"v=spf1 include:loop.example -all"},
			"a-unknown.example.":          {"v=spf1 a:absent.example"},
			"include-bad-expand.example.": {"v=spf1 include:%{c}"},  // macro 'c' only valid while expanding for "exp".
			"exists-bad-expand.example.":  {"v=spf1 exists:%{c}"},   // macro 'c' only valid while expanding for "exp".
			"redir-bad-expand.example.":   {"v=spf1 redirect=%{c}"}, // macro 'c' only valid while expanding for "exp".
			"a-bad-expand.example.":       {"v=spf1 a:%{c}"},        // macro 'c' only valid while expanding for "exp".
			"mx-bad-expand.example.":      {"v=spf1 mx:%{c}"},       // macro 'c' only valid while expanding for "exp".
			"ptr-bad-expand.example.":     {"v=spf1 ptr:%{c}"},      // macro 'c' only valid while expanding for "exp".
			"include-temperror.example.":  {"v=spf1 include:temperror.example"},
			"include-none.example.":       {"v=spf1 include:absent.example"},
			"include-permerror.example.":  {"v=spf1 include:permerror.example"},
			"permerror.example.":          {"v=spf1 a:%%"},
			"no-mx.example.":              {"v=spf1 mx -all"},
			"many-mx.example.":            {"v=spf1 mx -all"},
			"many-ptr.example.":           {"v=spf1 ptr:many-mx.example ~all"},
			"expl.example.":               {"v=spf1 ip4:10.0.1.1 -ip4:10.0.1.2 ?all exp=details.expl.example"},
			"details.expl.example.":       {"your ip %{i} is not allowed"},
			"expl-multi.example.":         {"v=spf1 ip4:10.0.1.1 -ip4:10.0.1.2 ~all exp=details-multi.expl.example"},
			"details-multi.expl.example.": {"your ip ", "%{i} is not allowed"},
		},
		A: map[string][]string{
			"mail.mox.example.":     {"10.0.0.1"},
			"mx1.many-mx.example.":  {"10.0.1.1"},
			"mx2.many-mx.example.":  {"10.0.1.2"},
			"mx3.many-mx.example.":  {"10.0.1.3"},
			"mx4.many-mx.example.":  {"10.0.1.4"},
			"mx5.many-mx.example.":  {"10.0.1.5"},
			"mx6.many-mx.example.":  {"10.0.1.6"},
			"mx7.many-mx.example.":  {"10.0.1.7"},
			"mx8.many-mx.example.":  {"10.0.1.8"},
			"mx9.many-mx.example.":  {"10.0.1.9"},
			"mx10.many-mx.example.": {"10.0.1.10"},
			"mx11.many-mx.example.": {"10.0.1.11"},
		},
		AAAA: map[string][]string{
			"mail.mox.example.": {"2001:db8::1"},
		},
		MX: map[string][]*net.MX{
			"no-mx.example.": {{Host: ".", Pref: 10}},
			"many-mx.example.": {
				{Host: "mx1.many-mx.example.", Pref: 1},
				{Host: "mx2.many-mx.example.", Pref: 2},
				{Host: "mx3.many-mx.example.", Pref: 3},
				{Host: "mx4.many-mx.example.", Pref: 4},
				{Host: "mx5.many-mx.example.", Pref: 5},
				{Host: "mx6.many-mx.example.", Pref: 6},
				{Host: "mx7.many-mx.example.", Pref: 7},
				{Host: "mx8.many-mx.example.", Pref: 8},
				{Host: "mx9.many-mx.example.", Pref: 9},
				{Host: "mx10.many-mx.example.", Pref: 10},
				{Host: "mx11.many-mx.example.", Pref: 11},
			},
		},
		PTR: map[string][]string{
			"2001:db8::1": {"mail.mox.example."},
			"10.0.1.1":    {"mx1.many-mx.example.", "mx2.many-mx.example.", "mx3.many-mx.example.", "mx4.many-mx.example.", "mx5.many-mx.example.", "mx6.many-mx.example.", "mx7.many-mx.example.", "mx8.many-mx.example.", "mx9.many-mx.example.", "mx10.many-mx.example.", "mx11.many-mx.example."},
		},
		Fail: []string{
			"txt temperror.example.",
		},
	}

	// IPv6 remote IP.
	test(r, Args{RemoteIP: net.ParseIP("2001:db8::1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "mox.example"}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("2001:fa11::1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "mox.example"}}, StatusFail, "", "", nil)

	// Use EHLO identity.
	test(r, Args{RemoteIP: net.ParseIP("2001:db8::1"), HelloDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("2001:db8::1"), HelloDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mail.mox.example"}}}, StatusNone, "", "", ErrNoRecord)

	// Too many void lookups.
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "void.example"}}, StatusPass, "", "", nil)                        // IP found after 2 void lookups, but before 3rd.
	test(r, Args{RemoteIP: net.ParseIP("1.1.1.1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "void.example"}}, StatusPermerror, "", "", ErrTooManyVoidLookups) // IP not found, not doing 3rd lookup.

	// Too many DNS requests.
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "loop.example"}}, StatusPermerror, "", "", ErrTooManyDNSRequests) // Self-referencing record, will abort after 10 includes.

	// a:other where other does not exist.
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "a-unknown.example"}}, StatusNeutral, "", "", nil)

	// Expand with an invalid macro.
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "include-bad-expand.example"}}, StatusPermerror, "", "", ErrMacroSyntax)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "exists-bad-expand.example"}}, StatusPermerror, "", "", ErrMacroSyntax)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "redir-bad-expand.example"}}, StatusPermerror, "", "", ErrMacroSyntax)

	// Expand with invalid character (because macros are not expanded).
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "a-bad-expand.example"}}, StatusPermerror, "", "", ErrName)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "mx-bad-expand.example"}}, StatusPermerror, "", "", ErrName)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "ptr-bad-expand.example"}}, StatusPermerror, "", "", ErrName)

	// Include with varying results.
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "include-temperror.example"}}, StatusTemperror, "", "", ErrDNS)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "include-none.example"}}, StatusPermerror, "", "", ErrNoRecord)
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "include-permerror.example"}}, StatusPermerror, "", "", ErrName)

	// MX with explicit "." for "no mail".
	test(r, Args{RemoteIP: net.ParseIP("1.2.3.4"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "no-mx.example"}}, StatusFail, "", "", nil)

	// MX names beyond 10th entry result in Permerror.
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-mx.example"}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.10"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-mx.example"}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.11"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-mx.example"}}, StatusPermerror, "", "", ErrTooManyDNSRequests)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.254"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-mx.example"}}, StatusPermerror, "", "", ErrTooManyDNSRequests)

	// PTR names beyond 10th entry are ignored.
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-ptr.example"}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.2"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "many-ptr.example"}}, StatusSoftfail, "", "", nil)

	// Explanation from txt records.
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.1"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "expl.example"}}, StatusPass, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.2"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "expl.example"}}, StatusFail, "", "your ip 10.0.1.2 is not allowed", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.3"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "expl.example"}}, StatusNeutral, "", "", nil)
	test(r, Args{RemoteIP: net.ParseIP("10.0.1.2"), MailFromLocalpart: "x", MailFromDomain: dns.Domain{ASCII: "expl-multi.example"}}, StatusFail, "", "your ip 10.0.1.2 is not allowed", nil)

	// Verify with IP EHLO.
	test(r, Args{RemoteIP: net.ParseIP("2001:db8::1"), HelloDomain: dns.IPDomain{IP: net.ParseIP("::1")}}, StatusNone, "", "", nil)
}

func TestEvaluate(t *testing.T) {
	record := &Record{}
	resolver := dns.MockResolver{}
	args := Args{}
	status, _, _, _, _ := Evaluate(context.Background(), record, resolver, args)
	if status != StatusNone {
		t.Fatalf("got status %q, expected none", status)
	}

	args = Args{
		HelloDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "test.example"}},
	}
	status, mechanism, _, _, err := Evaluate(context.Background(), record, resolver, args)
	if status != StatusNeutral || mechanism != "default" || err != nil {
		t.Fatalf("got status %q, mechanism %q, err %v, expected neutral, default, no error", status, mechanism, err)
	}
}
