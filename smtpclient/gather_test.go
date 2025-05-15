package smtpclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func domain(s string) dns.Domain {
	d, err := dns.ParseDomain(s)
	if err != nil {
		panic("parse domain: " + err.Error())
	}
	return d
}

func ipdomain(s string) dns.IPDomain {
	ip := net.ParseIP(s)
	if ip != nil {
		return dns.IPDomain{IP: ip}
	}
	d, err := dns.ParseDomain(s)
	if err != nil {
		panic(fmt.Sprintf("parse domain %q: %v", s, err))
	}
	return dns.IPDomain{Domain: d}
}

func hostprefs(pref int, names ...string) (l []HostPref) {
	for _, s := range names {
		l = append(l, HostPref{Host: ipdomain(s), Pref: pref})
	}
	return l
}

// Test basic MX lookup case, but also following CNAME, detecting CNAME loops and
// having a CNAME limit, connecting directly to a host, and domain that does not
// exist or has temporary error.
func TestGatherDestinations(t *testing.T) {
	ctxbg := context.Background()
	log := mlog.New("smtpclient", nil)

	resolver := dns.MockResolver{
		MX: map[string][]*net.MX{
			"basic.example.":        {{Host: "mail.basic.example.", Pref: 10}},
			"multimx.example.":      {{Host: "mail1.multimx.example.", Pref: 10}, {Host: "mail2.multimx.example.", Pref: 10}},
			"nullmx.example.":       {{Host: ".", Pref: 10}},
			"temperror-mx.example.": {{Host: "absent.example.", Pref: 10}},
		},
		A: map[string][]string{
			"mail.basic.example":   {"10.0.0.1"},
			"justhost.example.":    {"10.0.0.1"}, // No MX record for domain, only an A record.
			"temperror-a.example.": {"10.0.0.1"},
		},
		AAAA: map[string][]string{
			"justhost6.example.": {"2001:db8::1"}, // No MX record for domain, only an AAAA record.
		},
		CNAME: map[string]string{
			"cname.example.":                "basic.example.",
			"cname-to-inauthentic.example.": "cnameinauthentic.example.",
			"cnameinauthentic.example.":     "basic.example.",
			"cnameloop.example.":            "cnameloop2.example.",
			"cnameloop2.example.":           "cnameloop.example.",
			"danglingcname.example.":        "absent.example.", // Points to missing name.
			"temperror-cname.example.":      "absent.example.",
		},
		Fail: []string{
			"mx temperror-mx.example.",
			"host temperror-a.example.",
			"cname temperror-cname.example.",
		},
		Inauthentic: []string{"cname cnameinauthentic.example."},
	}
	for i := 0; i <= 16; i++ {
		s := fmt.Sprintf("cnamelimit%d.example.", i)
		next := fmt.Sprintf("cnamelimit%d.example.", i+1)
		resolver.CNAME[s] = next
	}

	test := func(ipd dns.IPDomain, expHostPrefs []HostPref, expDomain dns.Domain, expPerm, expAuthic, expExpAuthic bool, expErr error) {
		t.Helper()

		_, authic, authicExp, ed, hostPrefs, perm, err := GatherDestinations(ctxbg, log.Logger, resolver, ipd)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			// todo: could also check the individual errors? code currently does not have structured errors.
			t.Fatalf("gather hosts: %v, expected %v", err, expErr)
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(hostPrefs, expHostPrefs) || ed != expDomain || perm != expPerm || authic != expAuthic || authicExp != expExpAuthic {
			t.Fatalf("got hosts %#v, effectiveDomain %#v, permanent %#v, authic %v %v, expected %#v %#v %#v %v %v", hostPrefs, ed, perm, authic, authicExp, expHostPrefs, expDomain, expPerm, expAuthic, expExpAuthic)
		}
	}

	var zerodom dns.Domain

	for i := range 2 {
		authic := i == 1
		resolver.AllAuthentic = authic
		// Basic with simple MX.
		test(ipdomain("basic.example"), hostprefs(10, "mail.basic.example"), domain("basic.example"), false, authic, authic, nil)
		test(ipdomain("multimx.example"), hostprefs(10, "mail1.multimx.example", "mail2.multimx.example"), domain("multimx.example"), false, authic, authic, nil)
		// Only an A record.
		test(ipdomain("justhost.example"), hostprefs(-1, "justhost.example"), domain("justhost.example"), false, authic, authic, nil)
		// Only an AAAA record.
		test(ipdomain("justhost6.example"), hostprefs(-1, "justhost6.example"), domain("justhost6.example"), false, authic, authic, nil)
		// Follow CNAME.
		test(ipdomain("cname.example"), hostprefs(10, "mail.basic.example"), domain("basic.example"), false, authic, authic, nil)
		// No MX/CNAME, non-existence of host will be found out later.
		test(ipdomain("absent.example"), hostprefs(-1, "absent.example"), domain("absent.example"), false, authic, authic, nil)
		// Followed CNAME, has no MX, non-existence of host will be found out later.
		test(ipdomain("danglingcname.example"), hostprefs(-1, "absent.example"), domain("absent.example"), false, authic, authic, nil)
		test(ipdomain("cnamelimit1.example"), nil, zerodom, true, authic, authic, errCNAMELimit)
		test(ipdomain("cnameloop.example"), nil, zerodom, true, authic, authic, errCNAMELoop)
		test(ipdomain("nullmx.example"), nil, zerodom, true, authic, authic, errNoMail)
		test(ipdomain("temperror-mx.example"), nil, zerodom, false, authic, authic, errDNS)
		test(ipdomain("temperror-cname.example"), nil, zerodom, false, authic, authic, errDNS)
	}

	test(ipdomain("10.0.0.1"), hostprefs(-1, "10.0.0.1"), zerodom, false, false, false, nil)
	test(ipdomain("cnameinauthentic.example"), hostprefs(10, "mail.basic.example"), domain("basic.example"), false, false, false, nil)
	test(ipdomain("cname-to-inauthentic.example"), hostprefs(10, "mail.basic.example"), domain("basic.example"), false, true, false, nil)
}

func TestGatherIPs(t *testing.T) {
	ctxbg := context.Background()
	log := mlog.New("smtpclient", nil)

	resolver := dns.MockResolver{
		A: map[string][]string{
			"host1.example.":       {"10.0.0.1"},
			"host2.example.":       {"10.0.0.2"},
			"temperror-a.example.": {"10.0.0.3"},
		},
		AAAA: map[string][]string{
			"host2.example.": {"2001:db8::1"},
		},
		CNAME: map[string]string{
			"cname1.example.":               "host1.example.",
			"cname-to-inauthentic.example.": "cnameinauthentic.example.",
			"cnameinauthentic.example.":     "host1.example.",
			"cnameloop.example.":            "cnameloop2.example.",
			"cnameloop2.example.":           "cnameloop.example.",
			"danglingcname.example.":        "absent.example.", // Points to missing name.
			"temperror-cname.example.":      "absent.example.",
		},
		Fail: []string{
			"ip temperror-a.example.",
			"cname temperror-cname.example.",
		},
		Inauthentic: []string{"cname cnameinauthentic.example."},
	}

	test := func(host dns.IPDomain, expAuthic, expAuthicExp bool, expHostExp dns.Domain, expIPs []net.IP, expErr any, network string) {
		t.Helper()

		authic, authicExp, hostExp, ips, _, err := GatherIPs(ctxbg, log.Logger, resolver, network, host, nil)
		if (err == nil) != (expErr == nil) || err != nil && !(errors.Is(err, expErr.(error)) || errors.As(err, &expErr)) {
			// todo: could also check the individual errors?
			t.Fatalf("gather hosts: %v, expected %v", err, expErr)
		}
		if err != nil {
			return
		}
		if expHostExp == zerohost {
			expHostExp = host.Domain
		}
		if authic != expAuthic || authicExp != expAuthicExp || hostExp != expHostExp || !reflect.DeepEqual(ips, expIPs) {
			t.Fatalf("got authic %v %v, host %v, ips %v, expected %v %v %v %v", authic, authicExp, hostExp, ips, expAuthic, expAuthicExp, expHostExp, expIPs)
		}
	}

	ips := func(l ...string) (r []net.IP) {
		for _, s := range l {
			r = append(r, net.ParseIP(s))
		}
		return r
	}

	for i := range 2 {
		authic := i == 1
		resolver.AllAuthentic = authic

		test(ipdomain("host1.example"), authic, authic, zerohost, ips("10.0.0.1"), nil, "ip")
		test(ipdomain("host1.example"), authic, authic, zerohost, ips("10.0.0.1"), nil, "ip4")
		test(ipdomain("host1.example"), authic, authic, zerohost, nil, &adns.DNSError{}, "ip6")
		test(ipdomain("host2.example"), authic, authic, zerohost, ips("10.0.0.2", "2001:db8::1"), nil, "ip")
		test(ipdomain("host2.example"), authic, authic, zerohost, ips("10.0.0.2"), nil, "ip4")
		test(ipdomain("host2.example"), authic, authic, zerohost, ips("2001:db8::1"), nil, "ip6")
		test(ipdomain("cname-to-inauthentic.example"), authic, false, domain("host1.example"), ips("10.0.0.1"), nil, "ip")
		test(ipdomain("cnameloop.example"), authic, authic, zerohost, nil, errCNAMELimit, "ip")
		test(ipdomain("bogus.example"), authic, authic, zerohost, nil, &adns.DNSError{}, "ip")
		test(ipdomain("danglingcname.example"), authic, authic, zerohost, nil, &adns.DNSError{}, "ip")
		test(ipdomain("temperror-a.example"), authic, authic, zerohost, nil, &adns.DNSError{}, "ip")
		test(ipdomain("temperror-cname.example"), authic, authic, zerohost, nil, &adns.DNSError{}, "ip")

	}
	test(ipdomain("cnameinauthentic.example"), false, false, domain("host1.example"), ips("10.0.0.1"), nil, "ip")
	test(ipdomain("cname-to-inauthentic.example"), true, false, domain("host1.example"), ips("10.0.0.1"), nil, "ip")
}

func TestGatherTLSA(t *testing.T) {
	ctxbg := context.Background()
	log := mlog.New("smtpclient", nil)

	record := func(usage, selector, matchType uint8) adns.TLSA {
		return adns.TLSA{
			Usage:     adns.TLSAUsage(usage),
			Selector:  adns.TLSASelector(selector),
			MatchType: adns.TLSAMatchType(matchType),
			CertAssoc: make([]byte, sha256.Size), // Assume sha256.
		}
	}
	records := func(l ...adns.TLSA) []adns.TLSA {
		return l
	}

	record0 := record(3, 1, 1)
	list0 := records(record0)
	record1 := record(3, 0, 1)
	list1 := records(record1)

	resolver := dns.MockResolver{
		TLSA: map[string][]adns.TLSA{
			"_25._tcp.host0.example.":           list0,
			"_25._tcp.host1.example.":           list1,
			"_25._tcp.inauthentic.example.":     list1,
			"_25._tcp.temperror-cname.example.": list1,
		},
		CNAME: map[string]string{
			"_25._tcp.cname.example.":                "_25._tcp.host1.example.",
			"_25._tcp.cnameloop.example.":            "_25._tcp.cnameloop2.example.",
			"_25._tcp.cnameloop2.example.":           "_25._tcp.cnameloop.example.",
			"_25._tcp.cname-to-inauthentic.example.": "_25._tcp.cnameinauthentic.example.",
			"_25._tcp.cnameinauthentic.example.":     "_25._tcp.host1.example.",
			"_25._tcp.danglingcname.example.":        "_25._tcp.absent.example.", // Points to missing name.
		},
		Fail: []string{
			"cname _25._tcp.temperror-cname.example.",
		},
		Inauthentic: []string{
			"cname _25._tcp.cnameinauthentic.example.",
			"tlsa _25._tcp.inauthentic.example.",
		},
	}

	test := func(host dns.Domain, expandedAuthentic bool, expandedHost dns.Domain, expDANERequired bool, expRecords []adns.TLSA, expBaseDom dns.Domain, expErr any) {
		t.Helper()

		daneReq, records, baseDom, err := GatherTLSA(ctxbg, log.Logger, resolver, host, expandedAuthentic, expandedHost)
		if (err == nil) != (expErr == nil) || err != nil && !(errors.Is(err, expErr.(error)) || errors.As(err, &expErr)) {
			// todo: could also check the individual errors?
			t.Fatalf("gather tlsa: %v, expected %v", err, expErr)
		}
		if daneReq != expDANERequired {
			t.Fatalf("got daneRequired %v, expected %v", daneReq, expDANERequired)
		}
		if err != nil {
			return
		}
		if !reflect.DeepEqual(records, expRecords) || baseDom != expBaseDom {
			t.Fatalf("got records, baseDomain %v %v, expected %v %v", records, baseDom, expRecords, expBaseDom)
		}
	}

	resolver.AllAuthentic = true
	test(domain("host1.example"), false, domain("host1.example"), true, list1, domain("host1.example"), nil)
	test(domain("host1.example"), true, domain("host1.example"), true, list1, domain("host1.example"), nil)
	test(domain("host0.example"), true, domain("host1.example"), true, list1, domain("host1.example"), nil)
	test(domain("host0.example"), false, domain("host1.example"), true, list0, domain("host0.example"), nil)

	// CNAME for TLSA at cname.example should be followed.
	test(domain("host0.example"), true, domain("cname.example"), true, list1, domain("cname.example"), nil)
	// TLSA records at original domain should be followed.
	test(domain("host0.example"), false, domain("cname.example"), true, list0, domain("host0.example"), nil)

	test(domain("cnameloop.example"), false, domain("cnameloop.example"), true, nil, zerohost, errCNAMELimit)

	test(domain("host0.example"), false, domain("inauthentic.example"), true, list0, domain("host0.example"), nil)
	test(domain("inauthentic.example"), false, domain("inauthentic.example"), false, nil, domain("inauthentic.example"), nil)
	test(domain("temperror-cname.example"), false, domain("temperror-cname.example"), true, nil, domain("temperror-cname.example"), &adns.DNSError{})

	test(domain("host1.example"), true, domain("cname-to-inauthentic.example"), true, list1, domain("host1.example"), nil)
	test(domain("host1.example"), true, domain("danglingcname.example"), true, list1, domain("host1.example"), nil)
	test(domain("danglingcname.example"), true, domain("danglingcname.example"), false, nil, domain("danglingcname.example"), nil)
}

func TestGatherTLSANames(t *testing.T) {
	a, b, c, d := domain("nexthop.example"), domain("nexthopexpanded.example"), domain("base.example"), domain("baseexpanded.example")
	test := func(haveMX, nexthopExpAuth, tlsabaseExpAuth bool, expDoms ...dns.Domain) {
		t.Helper()
		doms := GatherTLSANames(haveMX, nexthopExpAuth, tlsabaseExpAuth, a, b, c, d)
		if !reflect.DeepEqual(doms, expDoms) {
			t.Fatalf("got domains %v, expected %v", doms, expDoms)
		}
	}

	test(false, false, false, c)
	test(false, false, true, d, c)
	test(true, true, true, d, c, a, b)
	test(true, true, false, c, a, b)
	test(true, false, false, a)
}
