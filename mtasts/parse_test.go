package mtasts

import (
	"reflect"
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestRecord(t *testing.T) {
	good := func(txt string, want Record) {
		t.Helper()
		r, _, err := ParseRecord(txt)
		if err != nil {
			t.Fatalf("parse: %s", err)
		}
		if !reflect.DeepEqual(r, &want) {
			t.Fatalf("want %#v, got %#v", want, *r)
		}
	}

	bad := func(txt string) {
		t.Helper()
		r, _, err := ParseRecord(txt)
		if err == nil {
			t.Fatalf("parse, expected error, got record %v", r)
		}
	}

	good("v=STSv1; id=20160831085700Z;", Record{Version: "STSv1", ID: "20160831085700Z"})
	good("v=STSv1; \t id=20160831085700Z  \t;", Record{Version: "STSv1", ID: "20160831085700Z"})
	good("v=STSv1; id=a", Record{Version: "STSv1", ID: "a"})
	good("v=STSv1; id=a; more=a; ext=2", Record{Version: "STSv1", ID: "a", Extensions: []Pair{{"more", "a"}, {"ext", "2"}}})

	bad("v=STSv0")
	bad("v=STSv10")
	bad("v=STSv2")
	bad("v=STSv1")                                            // missing id
	bad("v=STSv1;")                                           // missing id
	bad("v=STSv1; ext=1")                                     // missing id
	bad("v=STSv1; id=")                                       // empty id
	bad("v=STSv1; id=012345678901234567890123456789012")      // id too long
	bad("v=STSv1; id=test-123")                               // invalid id
	bad("v=STSv1; id=a; more=")                               // empty value in extension
	bad("v=STSv1; id=a; a12345678901234567890123456789012=1") // extension name too long
	bad("v=STSv1; id=a; 1%=a")                                // invalid extension name
	bad("v=STSv1; id=a; test==")                              // invalid extension name
	bad("v=STSv1; id=a;;")                                    // additional semicolon

	const want = `v=STSv1; id=a; more=a; ext=2`
	record := Record{Version: "STSv1", ID: "a", Extensions: []Pair{{"more", "a"}, {"ext", "2"}}}
	got := record.String()
	if got != want {
		t.Fatalf("record string, got %q, want %q", got, want)
	}
}

func TestParsePolicy(t *testing.T) {
	good := func(s string, want Policy) {
		t.Helper()
		p, err := ParsePolicy(s)
		if err != nil {
			t.Fatalf("parse policy: %s", err)
		}
		if !reflect.DeepEqual(p, &want) {
			t.Fatalf("want %v, got %v", want, p)
		}
	}

	good(`version: STSv1
mode: testing
mx: mx1.example.com
mx: mx2.example.com
mx: mx.backup-example.com
max_age: 1296000
`,
		Policy{
			Version: "STSv1",
			Mode:    ModeTesting,
			MX: []MX{
				{Domain: dns.Domain{ASCII: "mx1.example.com"}},
				{Domain: dns.Domain{ASCII: "mx2.example.com"}},
				{Domain: dns.Domain{ASCII: "mx.backup-example.com"}},
			},
			MaxAgeSeconds: 1296000,
		},
	)
	good("version: STSv1\nmode: enforce	\nmx: *.example.com \nmax_age: 0 \n",
		Policy{
			Version: "STSv1",
			Mode:    ModeEnforce,
			MX: []MX{
				{Wildcard: true, Domain: dns.Domain{ASCII: "example.com"}},
			},
			MaxAgeSeconds: 0,
		},
	)
	good("version:STSv1\r\nmode:\tenforce\r\nmx:  \t\t *.example.com\nmax_age: 1\nmore:ext e  ns ion",
		Policy{
			Version: "STSv1",
			Mode:    ModeEnforce,
			MX: []MX{
				{Wildcard: true, Domain: dns.Domain{ASCII: "example.com"}},
			},
			MaxAgeSeconds: 1,
			Extensions:    []Pair{{"more", "ext e  ns ion"}},
		},
	)

	bad := func(s string) {
		t.Helper()
		p, err := ParsePolicy(s)
		if err == nil {
			t.Fatalf("parsing policy did not fail: %v", p)
		}
	}

	bad("")                                                                           // missing version
	bad("version:STSv0\nmode:none\nmax_age:0")                                        // bad version
	bad("version:STSv10\nmode:none\nmax_age:0")                                       // bad version
	bad("version:STSv2\nmode:none\nmax_age:0")                                        // bad version
	bad("version:STSv1\nmax_age:0\nmx:example.com")                                   // missing mode
	bad("version:STSv1\nmode:none")                                                   // missing max_age
	bad("version:STSv1\nmax_age:0\nmode:enforce")                                     // missing mx for mode
	bad("version:STSv1\nmax_age:0\nmode:testing")                                     // missing mx for mode
	bad("max_age:0\nmode:none")                                                       // missing version
	bad("version:STSv1\nmode:none\nmax_age:01234567890")                              // max_age too long
	bad("version:STSv1\nmode:bad\nmax_age:1")                                         // bad mode
	bad("version:STSv1\nmode:none\nmax_age:a")                                        // bad max_age
	bad("version:STSv1\nmode:enforce\nmax_age:0\nmx:")                                // missing value
	bad("version:STSv1\nmode:enforce\nmax_age:0\nmx:*.*.example")                     // bad mx
	bad("version:STSv1\nmode:enforce\nmax_age:0\nmx:**.example")                      // bad mx
	bad("version:STSv1\nmode:enforce\nmax_age:0\nmx:**.example-")                     // bad mx
	bad("version:STSv1\nmode:enforce\nmax_age:0\nmx:test.example-")                   // bad mx
	bad("version:STSv1\nmode:none\nmax_age:0\next:")                                  // empty extension
	bad("version:STSv1\nmode:none\nmax_age:0\na12345678901234567890123456789012:123") // long extension name
	bad("version:STSv1\nmode:none\nmax_age:0\n_bad:test")                             // bad ext name
	bad("version:STSv1\nmode:none\nmax_age:0\nmx: møx.example")                       // invalid u-label in mx

	policy := Policy{
		Version: "STSv1",
		Mode:    ModeTesting,
		MX: []MX{
			{Domain: dns.Domain{ASCII: "mx1.example.com"}},
			{Domain: dns.Domain{ASCII: "mx2.example.com"}},
			{Domain: dns.Domain{ASCII: "mx.backup-example.com"}},
		},
		MaxAgeSeconds: 1296000,
	}
	want := `version: STSv1
mode: testing
max_age: 1296000
mx: mx1.example.com
mx: mx2.example.com
mx: mx.backup-example.com
`
	got := policy.String()
	if got != want {
		t.Fatalf("policy string, got %q, want %q", got, want)
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add("v=STSv1; id=20160831085700Z;")
	f.Add("v=STSv1; \t id=20160831085700Z  \t;")
	f.Add("v=STSv1; id=a")
	f.Add("v=STSv1; id=a; more=a; ext=2")

	f.Add("v=STSv0")
	f.Add("v=STSv10")
	f.Add("v=STSv2")
	f.Add("v=STSv1")                                            // missing id
	f.Add("v=STSv1;")                                           // missing id
	f.Add("v=STSv1; ext=1")                                     // missing id
	f.Add("v=STSv1; id=")                                       // empty id
	f.Add("v=STSv1; id=012345678901234567890123456789012")      // id too long
	f.Add("v=STSv1; id=test-123")                               // invalid id
	f.Add("v=STSv1; id=a; more=")                               // empty value in extension
	f.Add("v=STSv1; id=a; a12345678901234567890123456789012=1") // extension name too long
	f.Add("v=STSv1; id=a; 1%=a")                                // invalid extension name
	f.Add("v=STSv1; id=a; test==")                              // invalid extension name
	f.Add("v=STSv1; id=a;;")                                    // additional semicolon

	f.Fuzz(func(t *testing.T, s string) {
		r, _, err := ParseRecord(s)
		if err == nil {
			_ = r.String()
		}
	})
}

func FuzzParsePolicy(f *testing.F) {
	f.Add(`version: STSv1
mode: testing
mx: mx1.example.com
mx: mx2.example.com
mx: mx.backup-example.com
max_age: 1296000
`)
	f.Add(`version: STSv1
mode: enforce
mx: *.example.com
max_age: 0
`)
	f.Add("version:STSv1\r\nmode:\tenforce\r\nmx:  \t\t *.example.com\nmax_age: 1\nmore:ext e  ns ion")

	f.Add("")                                                                           // missing version
	f.Add("version:STSv0\nmode:none\nmax_age:0")                                        // bad version
	f.Add("version:STSv10\nmode:none\nmax_age:0")                                       // bad version
	f.Add("version:STSv2\nmode:none\nmax_age:0")                                        // bad version
	f.Add("version:STSv1\nmax_age:0\nmx:example.com")                                   // missing mode
	f.Add("version:STSv1\nmode:none")                                                   // missing max_age
	f.Add("version:STSv1\nmax_age:0\nmode:enforce")                                     // missing mx for mode
	f.Add("version:STSv1\nmax_age:0\nmode:testing")                                     // missing mx for mode
	f.Add("max_age:0\nmode:none")                                                       // missing version
	f.Add("version:STSv1\nmode:none\nmax_age:0 ")                                       // trailing whitespace
	f.Add("version:STSv1\nmode:none\nmax_age:01234567890")                              // max_age too long
	f.Add("version:STSv1\nmode:bad\nmax_age:1")                                         // bad mode
	f.Add("version:STSv1\nmode:none\nmax_age:a")                                        // bad max_age
	f.Add("version:STSv1\nmode:enforce\nmax_age:0\nmx:")                                // missing value
	f.Add("version:STSv1\nmode:enforce\nmax_age:0\nmx:*.*.example")                     // bad mx
	f.Add("version:STSv1\nmode:enforce\nmax_age:0\nmx:**.example")                      // bad mx
	f.Add("version:STSv1\nmode:enforce\nmax_age:0\nmx:**.example-")                     // bad mx
	f.Add("version:STSv1\nmode:enforce\nmax_age:0\nmx:test.example-")                   // bad mx
	f.Add("version:STSv1\nmode:none\nmax_age:0\next:")                                  // empty extension
	f.Add("version:STSv1\nmode:none\nmax_age:0\next:abc ")                              // trailing space
	f.Add("version:STSv1\nmode:none\nmax_age:0\next:a\t")                               // invalid char
	f.Add("version:STSv1\nmode:none\nmax_age:0\na12345678901234567890123456789012:123") // long extension name
	f.Add("version:STSv1\nmode:none\nmax_age:0\n_bad:test")                             // bad ext name

	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParsePolicy(s)
		if err == nil {
			_ = r.String()
		}
	})
}
