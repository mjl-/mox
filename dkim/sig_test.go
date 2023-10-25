package dkim

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func TestSig(t *testing.T) {
	test := func(s string, smtputf8 bool, expSig *Sig, expErr error) {
		t.Helper()

		isParseErr := func(err error) bool {
			_, ok := err.(parseErr)
			return ok
		}

		sig, _, err := parseSignature([]byte(s), smtputf8)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) && !(isParseErr(err) && isParseErr(expErr)) {
			t.Fatalf("got err %v, expected %v", err, expErr)
		}
		if !reflect.DeepEqual(sig, expSig) {
			t.Fatalf("got sig %#v, expected %#v", sig, expSig)
		}

		if sig == nil {
			return
		}
		h, err := sig.Header()
		if err != nil {
			t.Fatalf("making signature header: %v", err)
		}
		nsig, _, err := parseSignature([]byte(h), smtputf8)
		if err != nil {
			t.Fatalf("parse signature again: %v", err)
		}
		if !reflect.DeepEqual(nsig, sig) {
			t.Fatalf("parsed signature again, got %#v, expected %#v", nsig, sig)
		}
	}

	xbase64 := func(s string) []byte {
		t.Helper()
		buf, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("parsing base64: %v", err)
		}
		return buf
	}

	xdomain := func(s string) dns.Domain {
		t.Helper()
		d, err := dns.ParseDomain(s)
		if err != nil {
			t.Fatalf("parsing domain: %v", err)
		}
		return d
	}

	var empty smtp.Localpart
	sig1 := &Sig{
		Version:          1,
		AlgorithmSign:    "ed25519",
		AlgorithmHash:    "sha256",
		Signature:        xbase64("dGVzdAo="),
		BodyHash:         xbase64("LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q="),
		Domain:           xdomain("mox.example"),
		SignedHeaders:    []string{"from", "to", "cc", "bcc", "date", "subject", "message-id"},
		Selector:         xdomain("test"),
		Canonicalization: "simple/relaxed",
		Length:           10,
		Identity:         &Identity{&empty, xdomain("sub.mox.example")},
		QueryMethods:     []string{"dns/txt", "other"},
		SignTime:         10,
		ExpireTime:       100,
		CopiedHeaders:    []string{"From:<mjl@mox.example>", "Subject:test | with pipe"},
	}
	test("dkim-signature: v = 1 ; a=ed25519-sha256; s=test; d=mox.example; h=from:to:cc:bcc:date:subject:message-id; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q= ; c=simple/relaxed; l=10; i=\"\"@sub.mox.example; q= dns/txt:other; t=10; x=100; z=From:<mjl@mox.example>|Subject:test=20=7C=20with=20pipe; unknown = must be ignored \r\n", true, sig1, nil)

	ulp := smtp.Localpart("møx")
	sig2 := &Sig{
		Version:          1,
		AlgorithmSign:    "ed25519",
		AlgorithmHash:    "sha256",
		Signature:        xbase64("dGVzdAo="),
		BodyHash:         xbase64("LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q="),
		Domain:           xdomain("xn--mx-lka.example"), // møx.example
		SignedHeaders:    []string{"from"},
		Selector:         dns.Domain{ASCII: "xn--tst-bma"},
		Identity:         &Identity{&ulp, xdomain("xn--tst-bma.xn--mx-lka.example")}, // tést.møx.example
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
	test("dkim-signature: v = 1 ; a=ed25519-sha256; s=xn--tst-bma; d=xn--mx-lka.example; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q= ; i=møx@xn--tst-bma.xn--mx-lka.example;\r\n", true, sig2, nil)
	test("dkim-signature: v = 1 ; a=ed25519-sha256; s=xn--tst-bma; d=xn--mx-lka.example; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q= ; i=møx@xn--tst-bma.xn--mx-lka.example;\r\n", false, nil, parseErr("")) // No UTF-8 allowed.

	multiatom := smtp.Localpart("a.b.c")
	sig3 := &Sig{
		Version:          1,
		AlgorithmSign:    "ed25519",
		AlgorithmHash:    "sha256",
		Signature:        xbase64("dGVzdAo="),
		BodyHash:         xbase64("LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q="),
		Domain:           xdomain("mox.example"),
		SignedHeaders:    []string{"from"},
		Selector:         xdomain("test"),
		Identity:         &Identity{&multiatom, xdomain("mox.example")},
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
	test("dkim-signature: v = 1 ; a=ed25519-sha256; s=test; d=mox.example; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q= ; i=a.b.c@mox.example\r\n", true, sig3, nil)

	quotedlp := smtp.Localpart(`test "\test`)
	sig4 := &Sig{
		Version:          1,
		AlgorithmSign:    "ed25519",
		AlgorithmHash:    "sha256",
		Signature:        xbase64("dGVzdAo="),
		BodyHash:         xbase64("LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q="),
		Domain:           xdomain("mox.example"),
		SignedHeaders:    []string{"from"},
		Selector:         xdomain("test"),
		Identity:         &Identity{&quotedlp, xdomain("mox.example")},
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
	test("dkim-signature: v = 1 ; a=ed25519-sha256; s=test; d=mox.example; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q= ; i=\"test \\\"\\\\test\"@mox.example\r\n", true, sig4, nil)

	test("", true, nil, errSigMissingCRLF)
	test("other: ...\r\n", true, nil, errSigHeader)
	test("dkim-signature: v=2\r\n", true, nil, errSigUnknownVersion)
	test("dkim-signature: v=1\r\n", true, nil, errSigMissingTag)
	test("dkim-signature: v=1;v=1\r\n", true, nil, errSigDuplicateTag)
	test("dkim-signature: v=1; d=mox.example; i=@unrelated.example; s=test; a=ed25519-sha256; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q=\r\n", true, nil, errSigIdentityDomain)
	test("dkim-signature: v=1; t=10; x=9; d=mox.example; s=test; a=ed25519-sha256; h=from; b=dGVzdAo=; bh=LjkN2rUhrS3zKXfH2vNgUzz5ERRJkgP9CURXBX0JP0Q=\r\n", true, nil, errSigExpired)
	test("dkim-signature: v=1; d=møx.example\r\n", true, nil, parseErr("")) // Unicode domain not allowed.
	test("dkim-signature: v=1; s=tést\r\n", true, nil, parseErr(""))        // Unicode selector not allowed.
	test("dkim-signature: v=1; ;\r\n", true, nil, parseErr(""))             // Empty tag not allowed.
	test("dkim-signature: v=1; \r\n", true, nil, parseErr(""))              // Cannot have whitespace after last colon.
	test("dkim-signature: v=1; d=mox.example; s=test; a=ed25519-sha256; h=from; b=dGVzdAo=; bh=dGVzdAo=\r\n", true, nil, errSigBodyHash)
	test("dkim-signature: v=1; d=mox.example; s=test; a=rsa-sha1; h=from; b=dGVzdAo=; bh=dGVzdAo=\r\n", true, nil, errSigBodyHash)
}

func TestCopiedHeadersSig(t *testing.T) {
	// ../rfc/6376:1391
	sigHeader := strings.ReplaceAll(`DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=brisbane;
	c=simple; q=dns/txt; i=@eng.example.net;
	t=1117574938; x=1118006938;
	h=from:to:subject:date;
	z=From:foo@eng.example.net|To:joe@example.com|
	 Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
	bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
	b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR
`, "\n", "\r\n")

	sig, _, err := parseSignature([]byte(sigHeader), false)
	if err != nil {
		t.Fatalf("parsing dkim signature with copied headers: %v", err)
	}
	exp := []string{
		"From:foo@eng.example.net",
		"To:joe@example.com",
		"Subject:demo run",
		"Date:July 5, 2005 3:44:08 PM -0700",
	}
	if !reflect.DeepEqual(sig.CopiedHeaders, exp) {
		t.Fatalf("copied headers, got %v, expected %v", sig.CopiedHeaders, exp)
	}
}
