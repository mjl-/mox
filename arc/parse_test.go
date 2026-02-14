package arc

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAMS(t *testing.T) {
	// Valid AMS header.
	hdr := "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel;\r\n" +
		" h=from:to:subject:date;\r\n" +
		" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n"

	ams, err := ParseAMS([]byte(hdr), false)
	if err != nil {
		t.Fatalf("ParseAMS: %v", err)
	}
	if ams.Instance != 1 {
		t.Fatalf("instance: got %d, want 1", ams.Instance)
	}
	if ams.AlgorithmSign != "rsa" || ams.AlgorithmHash != "sha256" {
		t.Fatalf("algorithm: got %s-%s, want rsa-sha256", ams.AlgorithmSign, ams.AlgorithmHash)
	}
	if ams.Domain.ASCII != "example.com" {
		t.Fatalf("domain: got %q, want %q", ams.Domain.ASCII, "example.com")
	}
	if ams.Selector.ASCII != "sel" {
		t.Fatalf("selector: got %q, want %q", ams.Selector.ASCII, "sel")
	}
	if len(ams.SignedHeaders) != 4 {
		t.Fatalf("signed headers: got %d, want 4", len(ams.SignedHeaders))
	}
	if len(ams.Signature) == 0 {
		t.Fatal("empty signature")
	}
	if len(ams.BodyHash) != 32 {
		t.Fatalf("body hash length: got %d, want 32", len(ams.BodyHash))
	}
	if len(ams.VerifySig) == 0 {
		t.Fatal("empty verifySig")
	}
	// VerifySig should not contain the b= value.
	if strings.Contains(string(ams.VerifySig), "dGVzdAo=") {
		t.Fatal("verifySig should not contain b= value")
	}

	// With optional c= and t= tags.
	hdr2 := "ARC-Message-Signature: i=2; a=rsa-sha256; d=example.com; s=sel;\r\n" +
		" c=relaxed/relaxed; t=1528637909;\r\n" +
		" h=from:to:subject;\r\n" +
		" bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n" +
		" b=dGVzdAo=\r\n"
	ams2, err := ParseAMS([]byte(hdr2), false)
	if err != nil {
		t.Fatalf("ParseAMS with c= and t=: %v", err)
	}
	if ams2.Instance != 2 {
		t.Fatalf("instance: got %d, want 2", ams2.Instance)
	}
	if ams2.Canonicalization != "relaxed/relaxed" {
		t.Fatalf("canonicalization: got %q, want %q", ams2.Canonicalization, "relaxed/relaxed")
	}
	if ams2.SignTime != 1528637909 {
		t.Fatalf("sign time: got %d, want 1528637909", ams2.SignTime)
	}
}

func TestParseAMSErrors(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		err  error
	}{
		{"missing crlf", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=", ErrMissingCRLF},
		{"missing i=", "ARC-Message-Signature: a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing a=", "ARC-Message-Signature: i=1; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing b=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=\r\n", ErrMissingTag},
		{"missing bh=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing d=", "ARC-Message-Signature: i=1; a=rsa-sha256; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing h=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing s=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrMissingTag},
		{"instance 0", "ARC-Message-Signature: i=0; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrBadInstance},
		{"instance 51", "ARC-Message-Signature: i=51; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=\r\n", ErrBadInstance},
		{"disallowed l=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=; l=100\r\n", ErrDisallowedTag},
		{"disallowed q=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=; q=dns/txt\r\n", ErrDisallowedTag},
		{"disallowed x=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=; x=99999\r\n", ErrDisallowedTag},
		{"disallowed z=", "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=dGVzdAo=; z=from:test\r\n", ErrDisallowedTag},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAMS([]byte(tt.hdr), false)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("got err %v, want %v", err, tt.err)
			}
		})
	}
}

func TestParseAS(t *testing.T) {
	hdr := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; t=1528637909;\r\n" +
		" b=dGVzdAo=\r\n"

	as, err := ParseAS([]byte(hdr), false)
	if err != nil {
		t.Fatalf("ParseAS: %v", err)
	}
	if as.Instance != 1 {
		t.Fatalf("instance: got %d, want 1", as.Instance)
	}
	if as.AlgorithmSign != "rsa" || as.AlgorithmHash != "sha256" {
		t.Fatalf("algorithm: got %s-%s, want rsa-sha256", as.AlgorithmSign, as.AlgorithmHash)
	}
	if as.ChainValidation != ChainStatusNone {
		t.Fatalf("cv: got %q, want %q", as.ChainValidation, ChainStatusNone)
	}
	if as.Domain.ASCII != "example.com" {
		t.Fatalf("domain: got %q, want %q", as.Domain.ASCII, "example.com")
	}
	if as.Selector.ASCII != "sel" {
		t.Fatalf("selector: got %q, want %q", as.Selector.ASCII, "sel")
	}
	if as.SignTime != 1528637909 {
		t.Fatalf("sign time: got %d, want 1528637909", as.SignTime)
	}
	if len(as.Signature) == 0 {
		t.Fatal("empty signature")
	}
	if len(as.VerifySig) == 0 {
		t.Fatal("empty verifySig")
	}

	// cv=pass and cv=fail.
	for _, cv := range []string{"pass", "fail"} {
		hdr := "ARC-Seal: i=2; a=rsa-sha256; cv=" + cv + "; d=example.com; s=sel;\r\n" +
			" b=dGVzdAo=\r\n"
		as, err := ParseAS([]byte(hdr), false)
		if err != nil {
			t.Fatalf("ParseAS cv=%s: %v", cv, err)
		}
		if string(as.ChainValidation) != cv {
			t.Fatalf("cv: got %q, want %q", as.ChainValidation, cv)
		}
	}
}

func TestParseASErrors(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		err  error
	}{
		{"missing crlf", "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=", ErrMissingCRLF},
		{"h= disallowed", "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=; h=from\r\n", ErrDisallowedTag},
		{"bh= disallowed", "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=; bh=dGVzdAo=\r\n", ErrDisallowedTag},
		{"bad cv", "ARC-Seal: i=1; a=rsa-sha256; cv=bogus; d=example.com; s=sel; b=dGVzdAo=\r\n", ErrBadChainStatus},
		{"missing cv", "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=sel; b=dGVzdAo=\r\n", ErrMissingTag},
		{"missing i", "ARC-Seal: a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n", ErrMissingTag},
		{"instance 0", "ARC-Seal: i=0; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n", ErrBadInstance},
		{"instance 51", "ARC-Seal: i=51; a=rsa-sha256; cv=none; d=example.com; s=sel; b=dGVzdAo=\r\n", ErrBadInstance},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAS([]byte(tt.hdr), false)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("got err %v, want %v", err, tt.err)
			}
		})
	}
}

func TestParseAAR(t *testing.T) {
	hdr := "ARC-Authentication-Results: i=1; example.com; dkim=pass header.d=example.com\r\n"

	aar, err := ParseAAR([]byte(hdr), false)
	if err != nil {
		t.Fatalf("ParseAAR: %v", err)
	}
	if aar.Instance != 1 {
		t.Fatalf("instance: got %d, want 1", aar.Instance)
	}
	if aar.AuthServID != "example.com" {
		t.Fatalf("authserv-id: got %q, want %q", aar.AuthServID, "example.com")
	}
	if !strings.Contains(aar.Payload, "dkim=pass") {
		t.Fatalf("payload: got %q, want to contain 'dkim=pass'", aar.Payload)
	}

	// Without payload.
	hdr2 := "ARC-Authentication-Results: i=2; example.com\r\n"
	aar2, err := ParseAAR([]byte(hdr2), false)
	if err != nil {
		t.Fatalf("ParseAAR without payload: %v", err)
	}
	if aar2.Instance != 2 {
		t.Fatalf("instance: got %d, want 2", aar2.Instance)
	}
	if aar2.Payload != "" {
		t.Fatalf("payload: got %q, want empty", aar2.Payload)
	}

	// With folding.
	hdr3 := "ARC-Authentication-Results: i=3;\r\n example.com;\r\n dkim=pass\r\n"
	aar3, err := ParseAAR([]byte(hdr3), false)
	if err != nil {
		t.Fatalf("ParseAAR with folding: %v", err)
	}
	if aar3.Instance != 3 {
		t.Fatalf("instance: got %d, want 3", aar3.Instance)
	}
}

func TestParseAARErrors(t *testing.T) {
	tests := []struct {
		name string
		hdr  string
		err  error
	}{
		{"missing crlf", "ARC-Authentication-Results: i=1; example.com", ErrMissingCRLF},
		{"missing i=", "ARC-Authentication-Results: example.com\r\n", ErrMissingTag},
		{"bad instance", "ARC-Authentication-Results: i=0; example.com\r\n", ErrBadInstance},
		{"instance 51", "ARC-Authentication-Results: i=51; example.com\r\n", ErrBadInstance},
		{"wrong header", "Authentication-Results: i=1; example.com\r\n", ErrNotAARHeader},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAAR([]byte(tt.hdr), false)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("got err %v, want %v", err, tt.err)
			}
		})
	}
}
