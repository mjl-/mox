package arc

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
)

func parseRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	const rsaText = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu7iTF/AAvJQ3U
WRlcXd+n6HXOSYvmDlqjLsuCKn6/T+Ma0ZtobCRfzyXh5pFQBCHffW6fpEzJs/2o
+e896zb1QKjD8Xxsjarjdw1iXzgMj/lhDGWyNyUHC34+k77UfpQBZgPLvZHyYyQG
sVMzzmvURE+GMFmXYUiGI581PdCx4bNba/4gYQnc/eqQ8oX0T//2RdRqdhdDM2d7
CYALtkxKetH1F+Rz7XDjFmI3GjPs1KwVdh+Cl8kejThi0SVxXpqnoqB2WGsr/lGG
GxsxcpLb/+KWFjI0go3OJjMaxFCmhB0pGdW8I7kNwNrZsCdSvmjMDojNuegx6WMg
/T7go3CvAgMBAAECggEAQA3AlmSDtr+lNDvZ7voKwwN6W6qPmRJpevZQG54u4iPA
/5mAA/kRSqnh77mLPRb+RkU6RCeX3IXVXNIEGhKugZiHE5Sx4FfxmrAFzR8buXHg
uXoeJOdPXiiFtilIh6u/y1FNE4YbUnud/fthgYdU8Zl/2x2KOMWtFj0l94tmhzOI
b2y8/U8r85anI5XGYuzRCqKS1WskXhkXH8LZUB+9yAxX7V5ysgxjofM4FW8ns7yj
K4cBS8KY2v3t7TZ4FgwkAhPcTfBc/E2UWT1Ztmr+18LFV5bqI8g2YlN+BgCxU7U/
1tawxqFhs+xowEpzNwAvjAIPpptIRiY1rz7sBB9g5QKBgQDLo/5rTUwNOPR9dYvA
+DYUSCfxvNamI4GI66AgwOeN8O+W+dRDF/Ewbk/SJsBPSLIYzEiQ2uYKcNEmIjo+
7WwSCJZjKujovw77s9JAHexhpd8uLD2w9l3KeTg41LEYm2uVwoXWEHYSYJ9Ynz0M
PWxvi2Hm0IoQ7gJIfxng/wIw3QKBgQDb6GFvPH/OTs40+dopwtm3irmkBAmT8N0b
3TpehONCOiL4GPxmn2DN6ELhHFV27Jj/1CfpGVbcBlaS1xYUGUGsB9gYukhdaBST
KGHRoeZDcf0gaQLKG15EEfFOvcKI9aGljV8FdFfG+Z4fW3LA8khvpvjLLkv1A1jM
MrEBthco+wKBgD45EM9GohtUMNh450gCT7voxFPICKphJP5qSNZZOyeS3BJ8qdAK
a8cJndgvwQk4xDpxiSbBzBKaoD2Prc52i1QDTbhlbx9W6cQdEPxIaGb54PThzcPZ
s5Tfbz9mNeq36qqq8mwTQZCh926D0YqA5jY7F6IITHeZ0hbGx2iJYuj9AoGARIyK
ms8kE95y3wanX+8ySMmAlsT/a1NgyUfL4xzPbpyKvAWl4CN8XJMzDdL0PS8BfnXW
vw28CrgbEojjg/5ff02uqf6fgiZoi3rCC0PJcGq++fRh/zhKyTNCokX6txDCg8Wu
wheDKS40gRfTjJu5wrwsv8E9wjF546VFkf/99jMCgYEAm/x+kEfWKuzx8pQT66TY
pxnC41upJOO1htTHNIN24J7XrrFI5+OZq90G+t/VgWX08Z8RlhejX+ukBf+SRu3u
5VMGcAs4px+iECX/FHo21YQFnrmArN1zdFxPU3rBWoBueqmGO6FT0HBbKzTuS7N0
7fIv3GQqImz3+ZbYWlXfkPI=
-----END PRIVATE KEY-----`
	rsab, _ := pem.Decode([]byte(rsaText))
	if rsab == nil {
		t.Fatalf("no pem in privKey")
	}
	key, err := x509.ParsePKCS8PrivateKey(rsab.Bytes)
	if err != nil {
		t.Fatalf("parsing private key: %s", err)
	}
	return key.(*rsa.PrivateKey)
}

func makeDKIMRecord(t *testing.T, keyType string, publicKey any) string {
	t.Helper()
	tr := &dkim.Record{
		Version:   "DKIM1",
		Key:       keyType,
		PublicKey: publicKey,
	}
	txt, err := tr.Record()
	if err != nil {
		t.Fatalf("making dns txt record: %s", err)
	}
	return txt
}

func TestSealAndVerifyEd25519(t *testing.T) {
	// Fix time for deterministic tests.
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(1528637909, 0) }
	defer func() { timeNow = origTimeNow }()

	key := ed25519.NewKeyFromSeed(make([]byte, 32))

	msg := strings.ReplaceAll(`From: sender@example.com
To: rcpt@other.com
Subject: test
Date: Mon, 11 Jun 2018 01:00:00 +0000
Message-ID: <test@example.com>

Hello world.
`, "\n", "\r\n")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"sel._domainkey.example.com.": {makeDKIMRecord(t, "ed25519", key.Public())},
		},
	}

	sel := SealSelector{
		Hash:          "sha256",
		PrivateKey:    key,
		Domain:        dns.Domain{ASCII: "example.com"},
		SelectorDomain: dns.Domain{ASCII: "sel"},
		HeaderRelaxed: true,
		BodyRelaxed:   true,
		Headers:       []string{"from", "to", "subject", "date"},
	}

	authResults := message.AuthResults{
		Hostname: "example.com",
		Methods: []message.AuthMethod{
			{Method: "dkim", Result: "pass"},
			{Method: "spf", Result: "pass"},
		},
	}

	headers, err := Seal(context.Background(), pkglog.Logger, resolver, sel, authResults, "example.com", false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if headers == "" {
		t.Fatal("Seal returned empty headers")
	}

	// Verify the headers contain all three ARC headers.
	if !strings.Contains(headers, "ARC-Authentication-Results:") {
		t.Fatal("missing ARC-Authentication-Results header")
	}
	if !strings.Contains(headers, "ARC-Message-Signature:") {
		t.Fatal("missing ARC-Message-Signature header")
	}
	if !strings.Contains(headers, "ARC-Seal:") {
		t.Fatal("missing ARC-Seal header")
	}

	// Prepend headers and verify the chain.
	sealedMsg := headers + msg
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(sealedMsg))
	if err != nil {
		t.Fatalf("Verify after Seal: %v", err)
	}
	if result.Status != ChainStatusPass {
		t.Fatalf("status: got %q, want %q, err: %v", result.Status, ChainStatusPass, result.Err)
	}
	if len(result.Sets) != 1 {
		t.Fatalf("sets: got %d, want 1", len(result.Sets))
	}
	if result.Sets[0].Instance != 1 {
		t.Fatalf("instance: got %d, want 1", result.Sets[0].Instance)
	}
}

func TestSealAndVerifyRSA(t *testing.T) {
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(1528637909, 0) }
	defer func() { timeNow = origTimeNow }()

	key := parseRSAKey(t)

	msg := strings.ReplaceAll(`From: sender@example.com
To: rcpt@other.com
Subject: test
Date: Mon, 11 Jun 2018 01:00:00 +0000
Message-ID: <test@example.com>

Hello world.
`, "\n", "\r\n")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"rsa._domainkey.example.com.": {makeDKIMRecord(t, "rsa", key.Public())},
		},
	}

	sel := SealSelector{
		Hash:           "sha256",
		PrivateKey:     key,
		Domain:         dns.Domain{ASCII: "example.com"},
		SelectorDomain: dns.Domain{ASCII: "rsa"},
		HeaderRelaxed:  true,
		BodyRelaxed:    true,
		Headers:        []string{"from", "to", "subject", "date"},
	}

	authResults := message.AuthResults{
		Hostname: "example.com",
		Methods: []message.AuthMethod{
			{Method: "dkim", Result: "pass"},
		},
	}

	headers, err := Seal(context.Background(), pkglog.Logger, resolver, sel, authResults, "example.com", false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sealedMsg := headers + msg
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(sealedMsg))
	if err != nil {
		t.Fatalf("Verify after Seal: %v", err)
	}
	if result.Status != ChainStatusPass {
		t.Fatalf("status: got %q, want %q, err: %v", result.Status, ChainStatusPass, result.Err)
	}
}

func TestMultiHopSeal(t *testing.T) {
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(1528637909, 0) }
	defer func() { timeNow = origTimeNow }()

	key1 := ed25519.NewKeyFromSeed(make([]byte, 32))
	key2seed := make([]byte, 32)
	key2seed[0] = 1
	key2 := ed25519.NewKeyFromSeed(key2seed)

	msg := strings.ReplaceAll(`From: sender@example.com
To: rcpt@other.com
Subject: test
Date: Mon, 11 Jun 2018 01:00:00 +0000

Hello.
`, "\n", "\r\n")

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"sel._domainkey.hop1.example.": {makeDKIMRecord(t, "ed25519", key1.Public())},
			"sel._domainkey.hop2.example.": {makeDKIMRecord(t, "ed25519", key2.Public())},
		},
	}

	// Hop 1.
	sel1 := SealSelector{
		Hash:           "sha256",
		PrivateKey:     key1,
		Domain:         dns.Domain{ASCII: "hop1.example"},
		SelectorDomain: dns.Domain{ASCII: "sel"},
		HeaderRelaxed:  true,
		BodyRelaxed:    true,
		Headers:        []string{"from", "to", "subject"},
	}

	authResults1 := message.AuthResults{
		Hostname: "hop1.example",
		Methods: []message.AuthMethod{
			{Method: "dkim", Result: "pass"},
		},
	}

	headers1, err := Seal(context.Background(), pkglog.Logger, resolver, sel1, authResults1, "hop1.example", false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Seal hop1: %v", err)
	}

	msg1 := headers1 + msg

	// Verify after hop 1.
	result1, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg1))
	if err != nil {
		t.Fatalf("Verify hop1: %v", err)
	}
	if result1.Status != ChainStatusPass {
		t.Fatalf("hop1 status: got %q, want %q, err: %v", result1.Status, ChainStatusPass, result1.Err)
	}

	// Hop 2.
	sel2 := SealSelector{
		Hash:           "sha256",
		PrivateKey:     key2,
		Domain:         dns.Domain{ASCII: "hop2.example"},
		SelectorDomain: dns.Domain{ASCII: "sel"},
		HeaderRelaxed:  true,
		BodyRelaxed:    true,
		Headers:        []string{"from", "to", "subject"},
	}

	authResults2 := message.AuthResults{
		Hostname: "hop2.example",
		Methods: []message.AuthMethod{
			{Method: "dkim", Result: "fail"},
			{Method: "arc", Result: "pass"},
		},
	}

	headers2, err := Seal(context.Background(), pkglog.Logger, resolver, sel2, authResults2, "hop2.example", false, strings.NewReader(msg1))
	if err != nil {
		t.Fatalf("Seal hop2: %v", err)
	}

	msg2 := headers2 + msg1

	// Verify after hop 2.
	result2, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg2))
	if err != nil {
		t.Fatalf("Verify hop2: %v", err)
	}
	if result2.Status != ChainStatusPass {
		t.Fatalf("hop2 status: got %q, want %q, err: %v", result2.Status, ChainStatusPass, result2.Err)
	}
	if len(result2.Sets) != 2 {
		t.Fatalf("hop2 sets: got %d, want 2", len(result2.Sets))
	}
}

func TestSealBrokenChain(t *testing.T) {
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(1528637909, 0) }
	defer func() { timeNow = origTimeNow }()

	key := ed25519.NewKeyFromSeed(make([]byte, 32))

	// Start with a message that already has a broken ARC chain (invalid signatures).
	msg := "ARC-Authentication-Results: i=1; broken.example; none\r\n" +
		"ARC-Message-Signature: i=1; a=ed25519-sha256; d=broken.example; s=sel;\r\n" +
		" h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n" +
		"ARC-Seal: i=1; a=ed25519-sha256; cv=none; d=broken.example; s=sel; b=dGVzdAo=\r\n" +
		"From: sender@example.com\r\n" +
		"Subject: test\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"sel._domainkey.example.com.": {makeDKIMRecord(t, "ed25519", key.Public())},
		},
	}

	sel := SealSelector{
		Hash:           "sha256",
		PrivateKey:     key,
		Domain:         dns.Domain{ASCII: "example.com"},
		SelectorDomain: dns.Domain{ASCII: "sel"},
		HeaderRelaxed:  true,
		BodyRelaxed:    true,
		Headers:        []string{"from", "subject"},
	}

	authResults := message.AuthResults{
		Hostname: "example.com",
		Methods:  []message.AuthMethod{{Method: "none", Result: "none"}},
	}

	headers, err := Seal(context.Background(), pkglog.Logger, resolver, sel, authResults, "example.com", false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Seal on broken chain: %v", err)
	}

	// The sealed message should have cv=fail for instance 2.
	if !strings.Contains(headers, "cv=fail") {
		t.Fatal("expected cv=fail in headers for broken chain")
	}
}
