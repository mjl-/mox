package dmarc

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	// ../rfc/7489:3224

	// bad cases
	bad := func(s string) {
		t.Helper()
		_, _, err := ParseRecord(s)
		if err == nil {
			t.Fatalf("got parse success, expected error")
		}
	}
	bad("")
	bad("v=")
	bad("v=DMARC12")                                           // "2" leftover
	bad("v=DMARC1")                                            // semicolon required
	bad("v=dmarc1; p=none")                                    // dmarc1 is case-sensitive
	bad("v=DMARC1 p=none")                                     // missing ;
	bad("v=DMARC1;")                                           // missing p, no rua
	bad("v=DMARC1; sp=invalid")                                // invalid sp, no rua
	bad("v=DMARC1; sp=reject; p=reject")                       // p must be directly after v
	bad("v=DMARC1; p=none; p=none")                            // dup
	bad("v=DMARC1; p=none; p=reject")                          // dup
	bad("v=DMARC1;;")                                          // missing tag
	bad("v=DMARC1; adkim=x")                                   // bad value
	bad("v=DMARC1; aspf=123")                                  // bad value
	bad("v=DMARC1; ri=")                                       // missing value
	bad("v=DMARC1; ri=-1")                                     // invalid, must be >= 0
	bad("v=DMARC1; ri=99999999999999999999999999999999999999") // does not fit in int
	bad("v=DMARC1; ri=123bad")                                 // leftover data
	bad("v=DMARC1; ri=bad")                                    // not a number
	bad("v=DMARC1; fo=")
	bad("v=DMARC1; fo=01")
	bad("v=DMARC1; fo=bad")
	bad("v=DMARC1; rf=bad-trailing-dash-")
	bad("v=DMARC1; rf=")
	bad("v=DMARC1; rf=bad.non-alphadigitdash")
	bad("v=DMARC1; p=badvalue")
	bad("v=DMARC1; sp=bad")
	bad("v=DMARC1; pct=110")
	bad("v=DMARC1; pct=bogus")
	bad("v=DMARC1; pct=")
	bad("v=DMARC1; rua=")
	bad("v=DMARC1; rua=bogus")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!99999999999999999999999999999999999999999999999")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!10p")

	valid := func(s string, exp Record) {
		t.Helper()

		r, _, err := ParseRecord(s)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !reflect.DeepEqual(r, &exp) {
			t.Fatalf("got:\n%#v\nexpected:\n%#v", r, &exp)
		}
	}

	// Return a record with default values, and overrides from r. Only for the fields used below.
	record := func(r Record) Record {
		rr := DefaultRecord
		if r.Policy != "" {
			rr.Policy = r.Policy
		}
		if r.AggregateReportAddresses != nil {
			rr.AggregateReportAddresses = r.AggregateReportAddresses
		}
		if r.FailureReportAddresses != nil {
			rr.FailureReportAddresses = r.FailureReportAddresses
		}
		if r.Percentage != 0 {
			rr.Percentage = r.Percentage
		}
		return rr
	}

	valid("v=DMARC1; rua=mailto:mjl@mox.example", record(Record{
		Policy: "none",
		AggregateReportAddresses: []URI{
			{Address: "mailto:mjl@mox.example"},
		},
	})) // ../rfc/7489:1407
	valid("v=DMARC1; p=reject; sp=invalid; rua=mailto:mjl@mox.example", record(Record{
		Policy: "none",
		AggregateReportAddresses: []URI{
			{Address: "mailto:mjl@mox.example"},
		},
	})) // ../rfc/7489:1407
	valid("v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com", record(Record{
		Policy: "none",
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
		},
	}))
	valid("v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com;ruf=mailto:auth-reports@example.com", record(Record{
		Policy: "none",
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
		},
		FailureReportAddresses: []URI{
			{Address: "mailto:auth-reports@example.com"},
		},
	}))
	valid("v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25", record(Record{
		Policy: "quarantine",
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
			{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 10, Unit: "m"},
		},
		Percentage: 25,
	}))

	valid("V = DMARC1 ; P = reject ;\tSP=none; unknown \t=\t ignored-future-value \t ; adkim=s; aspf=s; rua=mailto:dmarc-feedback@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!10m; RUF=mailto:auth-reports@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!0G; RI = 123; FO = 0:1:d:s ; RF= afrf : other; Pct = 0",
		Record{
			Version:         "DMARC1",
			Policy:          "reject",
			SubdomainPolicy: "none",
			ADKIM:           "s",
			ASPF:            "s",
			AggregateReportAddresses: []URI{
				{Address: "mailto:dmarc-feedback@example.com"},
				{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 10, Unit: "m"},
			},
			FailureReportAddresses: []URI{
				{Address: "mailto:auth-reports@example.com"},
				{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 0, Unit: "g"},
			},
			AggregateReportingInterval: 123,
			FailureReportingOptions:    []string{"0", "1", "d", "s"},
			ReportingFormat:            []string{"afrf", "other"},
			Percentage:                 0,
		},
	)
}
