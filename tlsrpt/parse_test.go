package tlsrpt

import (
	"reflect"
	"testing"
)

func TestRecord(t *testing.T) {
	good := func(txt string, want Record) {
		t.Helper()
		r, _, err := ParseRecord(txt)
		if err != nil {
			t.Fatalf("parse: %s", err)
		}
		if !reflect.DeepEqual(r, &want) {
			t.Fatalf("want %v, got %v", want, *r)
		}
	}

	bad := func(txt string) {
		t.Helper()
		r, _, err := ParseRecord(txt)
		if err == nil {
			t.Fatalf("parse, expected error, got record %v", r)
		}
	}

	good("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example;", Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:tlsrpt@mox.example"}}})
	good("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example , \t\t https://mox.example/tlsrpt  ", Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:tlsrpt@mox.example", "https://mox.example/tlsrpt"}}})
	good("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example; ext=yes", Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:tlsrpt@mox.example"}}, Extensions: []Extension{{"ext", "yes"}}})
	good("v=TLSRPTv1 ; rua=mailto:x@x.example; rua=mailto:y@x.example", Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:x@x.example"}, {"mailto:y@x.example"}}})

	bad("v=TLSRPTv0")
	bad("v=TLSRPTv10")
	bad("v=TLSRPTv2")
	bad("v=TLSRPTv1")        // missing rua
	bad("v=TLSRPTv1;")       // missing rua
	bad("v=TLSRPTv1; ext=1") // missing rua
	bad("v=TLSRPTv1; rua=")  // empty rua
	bad("v=TLSRPTv1; rua=noscheme")
	bad("v=TLSRPTv1; rua=,, ,")                                                    // empty uris
	bad("v=TLSRPTv1; rua=mailto:x@x.example; more=")                               // empty value in extension
	bad("v=TLSRPTv1; rua=mailto:x@x.example; a12345678901234567890123456789012=1") // extension name too long
	bad("v=TLSRPTv1; rua=mailto:x@x.example; 1%=a")                                // invalid extension name
	bad("v=TLSRPTv1; rua=mailto:x@x.example; test==")                              // invalid extension name
	bad("v=TLSRPTv1; rua=mailto:x@x.example;;")                                    // additional semicolon
	bad("v=TLSRPTv1; rua=mailto:x@x.example other")                                // trailing characters.
	bad("v=TLSRPTv1; rua=http://bad/%")                                            // bad URI

	const want = `v=TLSRPTv1; rua=mailto:x@mox.example; more=a; ext=2`
	record := Record{Version: "TLSRPTv1", RUAs: [][]RUA{{"mailto:x@mox.example"}}, Extensions: []Extension{{"more", "a"}, {"ext", "2"}}}
	got := record.String()
	if got != want {
		t.Fatalf("record string, got %q, want %q", got, want)
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example;")
	f.Add("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example , \t\t https://mox.example/tlsrpt  ")
	f.Add("v=TLSRPTv1; rua=mailto:tlsrpt@mox.example; ext=yes")

	f.Add("v=TLSRPTv0")
	f.Add("v=TLSRPTv10")
	f.Add("v=TLSRPTv2")
	f.Add("v=TLSRPTv1")        // missing rua
	f.Add("v=TLSRPTv1;")       // missing rua
	f.Add("v=TLSRPTv1; ext=1") // missing rua
	f.Add("v=TLSRPTv1; rua=")  // empty rua
	f.Add("v=TLSRPTv1; rua=noscheme")
	f.Add("v=TLSRPTv1; rua=,, ,")                                                    // empty uris
	f.Add("v=TLSRPTv1; rua=mailto:x@x.example; more=")                               // empty value in extension
	f.Add("v=TLSRPTv1; rua=mailto:x@x.example; a12345678901234567890123456789012=1") // extension name too long
	f.Add("v=TLSRPTv1; rua=mailto:x@x.example; 1%=a")                                // invalid extension name
	f.Add("v=TLSRPTv1; rua=mailto:x@x.example; test==")                              // invalid extension name
	f.Add("v=TLSRPTv1; rua=mailto:x@x.example;;")                                    // additional semicolon
	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			_ = r.String()
		}
	})
}
