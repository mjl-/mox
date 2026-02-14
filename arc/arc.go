// Package arc implements the Authenticated Received Chain (ARC) protocol, RFC
// 8617, allowing mail intermediaries to preserve authentication results across
// hops.
//
// ARC provides a chain of custody so downstream receivers can trust the
// authentication performed by upstream intermediaries, even when DKIM signatures
// break due to message modification during forwarding.
package arc

import (
	"github.com/mjl-/mox/dns"
)

// ChainStatus represents the ARC chain validation result.
type ChainStatus string

const (
	ChainStatusNone ChainStatus = "none" // No ARC headers present.
	ChainStatusPass ChainStatus = "pass" // ARC chain validates.
	ChainStatusFail ChainStatus = "fail" // ARC chain is invalid.
)

// Set represents one ARC set (instance i): the three headers with matching i= value.
type Set struct {
	Instance int
	AAR      *AAR // Parsed ARC-Authentication-Results.
	AMS      *AMS // Parsed ARC-Message-Signature.
	AS       *AS  // Parsed ARC-Seal.
}

// AAR is a parsed ARC-Authentication-Results header.
type AAR struct {
	Instance   int
	AuthServID string // Hostname of the authenticating server.
	Payload    string // Raw authres-payload (after "i=N; hostname;").
	Raw        []byte // Full raw header including name and CRLF.
}

// AMS is a parsed ARC-Message-Signature header (DKIM-like).
type AMS struct {
	Instance         int
	AlgorithmSign    string     // "rsa" or "ed25519".
	AlgorithmHash    string     // "sha256" or "sha1".
	Signature        []byte     // b= value.
	BodyHash         []byte     // bh= value.
	Domain           dns.Domain // d= value.
	Selector         dns.Domain // s= value.
	SignedHeaders    []string   // h= value.
	Canonicalization string     // c= value, e.g. "relaxed/relaxed".
	SignTime         int64      // t= value, -1 if unset.
	Raw              []byte     // Full raw header including name and CRLF.
	VerifySig        []byte     // Header with b= emptied (for hash computation), without trailing CRLF.
}

// Algorithm returns an algorithm string for use in the "a" field, e.g.
// "rsa-sha256".
func (a *AMS) Algorithm() string {
	return a.AlgorithmSign + "-" + a.AlgorithmHash
}

// AS is a parsed ARC-Seal header.
type AS struct {
	Instance        int
	AlgorithmSign   string      // "rsa" or "ed25519".
	AlgorithmHash   string      // "sha256" or "sha1".
	Signature       []byte      // b= value.
	Domain          dns.Domain  // d= value.
	Selector        dns.Domain  // s= value.
	ChainValidation ChainStatus // cv= value.
	SignTime        int64       // t= value, -1 if unset.
	Raw             []byte      // Full raw header including name and CRLF.
	VerifySig       []byte      // Header with b= emptied, without trailing CRLF.
}

// Algorithm returns an algorithm string, e.g. "rsa-sha256".
func (a *AS) Algorithm() string {
	return a.AlgorithmSign + "-" + a.AlgorithmHash
}
