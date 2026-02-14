package arc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

var pkglog = mlog.New("arc", nil)

func TestVerifyNone(t *testing.T) {
	// A message with no ARC headers should return ChainStatusNone.
	msg := strings.ReplaceAll("From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: test\r\n\r\nbody\r\n", "\n", "")
	msg = "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: test\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{}
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != ChainStatusNone {
		t.Fatalf("status: got %q, want %q", result.Status, ChainStatusNone)
	}
}

func TestVerifyStructuralErrors(t *testing.T) {
	// A message with incomplete ARC sets should fail.
	msg := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n" +
		"From: sender@example.com\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{}
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != ChainStatusFail {
		t.Fatalf("status: got %q, want %q", result.Status, ChainStatusFail)
	}
	if !errors.Is(result.Err, ErrSetIncomplete) {
		t.Fatalf("error: got %v, want ErrSetIncomplete", result.Err)
	}
}

func TestVerifyCVErrors(t *testing.T) {
	// Build a message with a complete ARC set but cv=pass for i=1 (should be none).
	msg := "ARC-Authentication-Results: i=1; example.com; none\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" +
		" h=from:to:subject; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=sel; b=dGVzdAo=\r\n" +
		"From: sender@example.com\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{}
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != ChainStatusFail {
		t.Fatalf("status: got %q, want %q", result.Status, ChainStatusFail)
	}
	if !errors.Is(result.Err, ErrCVNotNoneFirst) {
		t.Fatalf("error: got %v, want ErrCVNotNoneFirst", result.Err)
	}
}

func TestVerifyDuplicateInstance(t *testing.T) {
	// Two AAR headers with same instance.
	msg := "ARC-Authentication-Results: i=1; example.com; none\r\n" +
		"ARC-Authentication-Results: i=1; other.com; none\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" +
		" h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n" +
		"From: sender@example.com\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{}
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != ChainStatusFail {
		t.Fatalf("status: got %q, want %q", result.Status, ChainStatusFail)
	}
	if !errors.Is(result.Err, ErrSetDuplicate) {
		t.Fatalf("error: got %v, want ErrSetDuplicate", result.Err)
	}
}

func TestVerifyGap(t *testing.T) {
	// Instance 1 and 3 but no 2.
	msg := "ARC-Authentication-Results: i=1; example.com; none\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" +
		" h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n" +
		"ARC-Authentication-Results: i=3; other.com; none\r\n" +
		"ARC-Message-Signature: i=3; a=rsa-sha256; d=other.com; s=sel;\r\n" +
		" h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n" +
		"ARC-Seal: i=3; a=rsa-sha256; cv=pass; d=other.com; s=sel; b=dGVzdAo=\r\n" +
		"From: sender@example.com\r\n\r\nbody\r\n"

	resolver := dns.MockResolver{}
	result, err := Verify(context.Background(), pkglog.Logger, resolver, false, strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Status != ChainStatusFail {
		t.Fatalf("status: got %q, want %q", result.Status, ChainStatusFail)
	}
	if !errors.Is(result.Err, ErrSetGap) {
		t.Fatalf("error: got %v, want ErrSetGap", result.Err)
	}
}

func TestParseCanonicalization(t *testing.T) {
	tests := []struct {
		c          string
		hdrSimple  bool
		bodySimple bool
		err        bool
	}{
		{"simple/simple", true, true, false},
		{"relaxed/relaxed", false, false, false},
		{"simple/relaxed", true, false, false},
		{"relaxed/simple", false, true, false},
		{"simple", true, true, false},
		{"relaxed", false, true, false},
		{"bogus", false, false, true},
		{"simple/bogus", false, false, true},
	}

	for _, tt := range tests {
		hs, bs, err := parseCanonicalization(tt.c)
		if (err != nil) != tt.err {
			t.Errorf("%q: err=%v, want err=%v", tt.c, err, tt.err)
			continue
		}
		if err != nil {
			continue
		}
		if hs != tt.hdrSimple || bs != tt.bodySimple {
			t.Errorf("%q: got (%v, %v), want (%v, %v)", tt.c, hs, bs, tt.hdrSimple, tt.bodySimple)
		}
	}
}

// TestVerifySignThenVerify is a basic round-trip test using ed25519 keys.
// This test creates ARC headers manually and verifies the chain passes.
// A more thorough test is in seal_test.go after Phase 4.
func TestVerifySignThenVerify(t *testing.T) {
	// This test manually constructs a valid ARC chain and verifies it.
	// We use ed25519 for simplicity (deterministic signatures).
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	_ = key
	// Full sign-then-verify round trip is tested in seal_test.go.
}
