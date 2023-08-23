package dmarc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/spf"
)

func TestLookup(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.simple.example.":    {"v=DMARC1; p=none;"},
			"_dmarc.one.example.":       {"v=DMARC1; p=none;", "other"},
			"_dmarc.temperror.example.": {"v=DMARC1; p=none;"},
			"_dmarc.multiple.example.":  {"v=DMARC1; p=none;", "v=DMARC1; p=none;"},
			"_dmarc.malformed.example.": {"v=DMARC1; p=none; bogus;"},
			"_dmarc.example.com.":       {"v=DMARC1; p=none;"},
		},
		Fail: map[dns.Mockreq]struct{}{
			{Type: "txt", Name: "_dmarc.temperror.example."}: {},
		},
	}

	test := func(d string, expStatus Status, expDomain string, expRecord *Record, expErr error) {
		t.Helper()

		status, dom, record, _, err := Lookup(context.Background(), resolver, dns.Domain{ASCII: d})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %#v, expected %#v", err, expErr)
		}
		expd := dns.Domain{ASCII: expDomain}
		if status != expStatus || dom != expd || !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("got status %v, dom %v, record %#v, expected %v %v %#v", status, dom, record, expStatus, expDomain, expRecord)
		}
	}

	r := DefaultRecord
	r.Policy = PolicyNone
	test("simple.example", StatusNone, "simple.example", &r, nil)
	test("one.example", StatusNone, "one.example", &r, nil)
	test("absent.example", StatusNone, "absent.example", nil, ErrNoRecord)
	test("multiple.example", StatusNone, "multiple.example", nil, ErrMultipleRecords)
	test("malformed.example", StatusPermerror, "malformed.example", nil, ErrSyntax)
	test("temperror.example", StatusTemperror, "temperror.example", nil, ErrDNS)
	test("sub.example.com", StatusNone, "example.com", &r, nil) // Policy published at organizational domain, public suffix.
}

func TestLookupExternalReportsAccepted(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"example.com._report._dmarc.simple.example.":    {"v=DMARC1"},
			"example.com._report._dmarc.simple2.example.":   {"v=DMARC1;"},
			"example.com._report._dmarc.one.example.":       {"v=DMARC1; p=none;", "other"},
			"example.com._report._dmarc.temperror.example.": {"v=DMARC1; p=none;"},
			"example.com._report._dmarc.multiple.example.":  {"v=DMARC1; p=none;", "v=DMARC1"},
			"example.com._report._dmarc.malformed.example.": {"v=DMARC1; p=none; bogus;"},
		},
		Fail: map[dns.Mockreq]struct{}{
			{Type: "txt", Name: "example.com._report._dmarc.temperror.example."}: {},
		},
	}

	test := func(dom, extdom string, expStatus Status, expAccepts bool, expErr error) {
		t.Helper()

		accepts, status, _, _, err := LookupExternalReportsAccepted(context.Background(), resolver, dns.Domain{ASCII: dom}, dns.Domain{ASCII: extdom})
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("got err %#v, expected %#v", err, expErr)
		}
		if status != expStatus || accepts != expAccepts {
			t.Fatalf("got status %s, accepts %v, expected %v, %v", status, accepts, expStatus, expAccepts)
		}
	}

	r := DefaultRecord
	r.Policy = PolicyNone
	test("example.com", "simple.example", StatusNone, true, nil)
	test("example.org", "simple.example", StatusNone, false, ErrNoRecord)
	test("example.com", "simple2.example", StatusNone, true, nil)
	test("example.com", "one.example", StatusNone, true, nil)
	test("example.com", "absent.example", StatusNone, false, ErrNoRecord)
	test("example.com", "multiple.example", StatusNone, false, ErrMultipleRecords)
	test("example.com", "malformed.example", StatusPermerror, false, ErrSyntax)
	test("example.com", "temperror.example", StatusTemperror, false, ErrDNS)
}

func TestVerify(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.reject.example.":    {"v=DMARC1; p=reject"},
			"_dmarc.strict.example.":    {"v=DMARC1; p=reject; adkim=s; aspf=s"},
			"_dmarc.test.example.":      {"v=DMARC1; p=reject; pct=0"},
			"_dmarc.subnone.example.":   {"v=DMARC1; p=reject; sp=none"},
			"_dmarc.none.example.":      {"v=DMARC1; p=none"},
			"_dmarc.malformed.example.": {"v=DMARC1; p=none; bogus"},
			"_dmarc.example.com.":       {"v=DMARC1; p=reject"},
		},
		Fail: map[dns.Mockreq]struct{}{
			{Type: "txt", Name: "_dmarc.temperror.example."}: {},
		},
	}

	equalResult := func(got, exp Result) bool {
		if reflect.DeepEqual(got, exp) {
			return true
		}
		if got.Err != nil && exp.Err != nil && (got.Err == exp.Err || errors.Is(got.Err, exp.Err)) {
			got.Err = nil
			exp.Err = nil
			return reflect.DeepEqual(got, exp)
		}
		return false
	}

	test := func(fromDom string, dkimResults []dkim.Result, spfResult spf.Status, spfIdentity *dns.Domain, expUseResult bool, expResult Result) {
		t.Helper()

		from, err := dns.ParseDomain(fromDom)
		if err != nil {
			t.Fatalf("parsing domain: %v", err)
		}
		useResult, result := Verify(context.Background(), resolver, from, dkimResults, spfResult, spfIdentity, true)
		if useResult != expUseResult || !equalResult(result, expResult) {
			t.Fatalf("verify: got useResult %v, result %#v, expected %v %#v", useResult, result, expUseResult, expResult)
		}
	}

	// Basic case, reject policy and no dkim or spf results.
	reject := DefaultRecord
	reject.Policy = PolicyReject
	test("reject.example",
		[]dkim.Result{},
		spf.StatusNone,
		nil,
		true, Result{true, StatusFail, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// Accept with spf pass.
	test("reject.example",
		[]dkim.Result{},
		spf.StatusPass,
		&dns.Domain{ASCII: "sub.reject.example"},
		true, Result{false, StatusPass, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// Accept with dkim pass.
	test("reject.example",
		[]dkim.Result{
			{
				Status: dkim.StatusPass,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "sub.reject.example"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusFail,
		&dns.Domain{ASCII: "reject.example"},
		true, Result{false, StatusPass, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// Reject due to spf and dkim "strict".
	strict := DefaultRecord
	strict.Policy = PolicyReject
	strict.ADKIM = AlignStrict
	strict.ASPF = AlignStrict
	test("strict.example",
		[]dkim.Result{
			{
				Status: dkim.StatusPass,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "sub.strict.example"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusPass,
		&dns.Domain{ASCII: "sub.strict.example"},
		true, Result{true, StatusFail, dns.Domain{ASCII: "strict.example"}, &strict, nil},
	)

	// No dmarc policy, nothing to say.
	test("absent.example",
		[]dkim.Result{},
		spf.StatusNone,
		nil,
		false, Result{false, StatusNone, dns.Domain{ASCII: "absent.example"}, nil, ErrNoRecord},
	)

	// No dmarc policy, spf pass does nothing.
	test("absent.example",
		[]dkim.Result{},
		spf.StatusPass,
		&dns.Domain{ASCII: "absent.example"},
		false, Result{false, StatusNone, dns.Domain{ASCII: "absent.example"}, nil, ErrNoRecord},
	)

	none := DefaultRecord
	none.Policy = PolicyNone
	// Policy none results in no reject.
	test("none.example",
		[]dkim.Result{},
		spf.StatusPass,
		&dns.Domain{ASCII: "none.example"},
		true, Result{false, StatusPass, dns.Domain{ASCII: "none.example"}, &none, nil},
	)

	// No actual reject due to pct=0.
	testr := DefaultRecord
	testr.Policy = PolicyReject
	testr.Percentage = 0
	test("test.example",
		[]dkim.Result{},
		spf.StatusNone,
		nil,
		false, Result{true, StatusFail, dns.Domain{ASCII: "test.example"}, &testr, nil},
	)

	// No reject if subdomain has "none" policy.
	sub := DefaultRecord
	sub.Policy = PolicyReject
	sub.SubdomainPolicy = PolicyNone
	test("sub.subnone.example",
		[]dkim.Result{},
		spf.StatusFail,
		&dns.Domain{ASCII: "sub.subnone.example"},
		true, Result{false, StatusFail, dns.Domain{ASCII: "subnone.example"}, &sub, nil},
	)

	// No reject if spf temperror and no other pass.
	test("reject.example",
		[]dkim.Result{},
		spf.StatusTemperror,
		&dns.Domain{ASCII: "mail.reject.example"},
		true, Result{false, StatusTemperror, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// No reject if dkim temperror and no other pass.
	test("reject.example",
		[]dkim.Result{
			{
				Status: dkim.StatusTemperror,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "sub.reject.example"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusNone,
		nil,
		true, Result{false, StatusTemperror, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// No reject if spf temperror but still dkim pass.
	test("reject.example",
		[]dkim.Result{
			{
				Status: dkim.StatusPass,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "sub.reject.example"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusTemperror,
		&dns.Domain{ASCII: "mail.reject.example"},
		true, Result{false, StatusPass, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// No reject if dkim temperror but still spf pass.
	test("reject.example",
		[]dkim.Result{
			{
				Status: dkim.StatusTemperror,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "sub.reject.example"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusPass,
		&dns.Domain{ASCII: "mail.reject.example"},
		true, Result{false, StatusPass, dns.Domain{ASCII: "reject.example"}, &reject, nil},
	)

	// Bad DMARC record results in permerror without reject.
	test("malformed.example",
		[]dkim.Result{},
		spf.StatusNone,
		nil,
		false, Result{false, StatusPermerror, dns.Domain{ASCII: "malformed.example"}, nil, ErrSyntax},
	)

	// DKIM domain that is higher-level than organizational can not result in a pass. ../rfc/7489:525
	test("example.com",
		[]dkim.Result{
			{
				Status: dkim.StatusPass,
				Sig: &dkim.Sig{ // Just the minimum fields needed.
					Domain: dns.Domain{ASCII: "com"},
				},
				Record: &dkim.Record{},
			},
		},
		spf.StatusNone,
		nil,
		true, Result{true, StatusFail, dns.Domain{ASCII: "example.com"}, &reject, nil},
	)
}
