package tlsrpt

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestLookup(t *testing.T) {
	log := mlog.New("tlsrpt", nil)
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_smtp._tls.basic.example.":     {"v=TLSRPTv1; rua=mailto:tlsrpt@basic.example"},
			"_smtp._tls.one.example.":       {"v=TLSRPTv1; rua=mailto:tlsrpt@basic.example", "other"},
			"_smtp._tls.multiple.example.":  {"v=TLSRPTv1; rua=mailto:tlsrpt@basic.example", "v=TLSRPTv1; rua=mailto:tlsrpt@basic.example"},
			"_smtp._tls.malformed.example.": {"v=TLSRPTv1; bad"},
			"_smtp._tls.other.example.":     {"other"},
		},
		Fail: []string{
			"txt _smtp._tls.temperror.example.",
		},
	}

	test := func(domain string, expRecord *Record, expErr error) {
		t.Helper()

		d := dns.Domain{ASCII: domain}
		record, _, err := Lookup(context.Background(), log.Logger, resolver, d)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) {
			t.Fatalf("lookup, got err %#v, expected %#v", err, expErr)
		}
		if err == nil && !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("lookup, got %#v, expected %#v", record, expRecord)
		}
	}

	test("basic.example", &Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:tlsrpt@basic.example"}}}, nil)
	test("one.example", &Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:tlsrpt@basic.example"}}}, nil)
	test("multiple.example", nil, ErrMultipleRecords)
	test("absent.example", nil, ErrNoRecord)
	test("other.example", nil, ErrNoRecord)
	test("malformed.example", nil, ErrRecordSyntax)
	test("temperror.example", nil, ErrDNS)
}
