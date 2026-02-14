package arc

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strings"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

// Verification errors.
var (
	ErrNoSets           = errors.New("arc: no arc sets found")
	ErrSetIncomplete    = errors.New("arc: arc set missing one or more of AAR/AMS/AS")
	ErrSetGap           = errors.New("arc: arc set instances have gap")
	ErrSetDuplicate     = errors.New("arc: duplicate arc set instance")
	ErrTooManySets      = errors.New("arc: more than 50 arc sets")
	ErrChainFail        = errors.New("arc: chain validation status is fail")
	ErrCVNoneNotFirst   = errors.New("arc: cv=none but instance is not 1")
	ErrCVNotNoneFirst   = errors.New("arc: cv is not none for instance 1")
	ErrCVNotPass        = errors.New("arc: cv is not pass for instance > 1")
	ErrAMSVerify        = errors.New("arc: AMS signature verification failed")
	ErrASVerify         = errors.New("arc: ARC-Seal signature verification failed")
	ErrBodyHashMismatch = errors.New("arc: body hash mismatch")
	ErrHeaderMalformed  = errors.New("arc: message header is malformed")
)

// Result holds the outcome of ARC chain verification.
type Result struct {
	Status     ChainStatus // none, pass, fail.
	Sets       []Set       // Parsed ARC sets, ordered by instance.
	OldestPass int         // Oldest instance whose AMS verified (0 = none verified or all pass).
	Err        error       // Details if Status is fail.
}

// Verify validates the ARC chain in a message.
// Returns ChainStatusNone if no ARC headers present.
// Returns ChainStatusFail with error details if chain is invalid.
// Returns ChainStatusPass if chain validates.
func Verify(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, smtputf8 bool, r io.ReaderAt) (Result, error) {
	log := mlog.New("arc", elog)

	// Parse all headers.
	hdrs, bodyOffset, err := dkim.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return Result{Status: ChainStatusNone}, fmt.Errorf("%w: %s", ErrHeaderMalformed, err)
	}

	// Collect ARC headers.
	var aarHeaders, amsHeaders, asHeaders []dkim.Header
	for _, h := range hdrs {
		switch h.LKey {
		case "arc-authentication-results":
			aarHeaders = append(aarHeaders, h)
		case "arc-message-signature":
			amsHeaders = append(amsHeaders, h)
		case "arc-seal":
			asHeaders = append(asHeaders, h)
		}
	}

	// No ARC headers means no chain.
	if len(aarHeaders) == 0 && len(amsHeaders) == 0 && len(asHeaders) == 0 {
		return Result{Status: ChainStatusNone}, nil
	}

	// Parse all ARC headers into sets grouped by instance.
	type partialSet struct {
		aar *AAR
		ams *AMS
		as  *AS
	}
	setMap := map[int]*partialSet{}

	ensureSet := func(i int) *partialSet {
		if s, ok := setMap[i]; ok {
			return s
		}
		s := &partialSet{}
		setMap[i] = s
		return s
	}

	for _, h := range aarHeaders {
		aar, err := ParseAAR(h.Raw, smtputf8)
		if err != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("parsing AAR: %w", err)}, nil
		}
		s := ensureSet(aar.Instance)
		if s.aar != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("%w: instance %d", ErrSetDuplicate, aar.Instance)}, nil
		}
		s.aar = aar
	}

	for _, h := range amsHeaders {
		ams, err := ParseAMS(h.Raw, smtputf8)
		if err != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("parsing AMS: %w", err)}, nil
		}
		s := ensureSet(ams.Instance)
		if s.ams != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("%w: instance %d", ErrSetDuplicate, ams.Instance)}, nil
		}
		s.ams = ams
	}

	for _, h := range asHeaders {
		as, err := ParseAS(h.Raw, smtputf8)
		if err != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("parsing AS: %w", err)}, nil
		}
		s := ensureSet(as.Instance)
		if s.as != nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("%w: instance %d", ErrSetDuplicate, as.Instance)}, nil
		}
		s.as = as
	}

	// Find the highest instance.
	n := 0
	for i := range setMap {
		if i > n {
			n = i
		}
	}

	if n > 50 {
		return Result{Status: ChainStatusFail, Err: ErrTooManySets}, nil
	}

	// Verify continuous sequence 1..N.
	sets := make([]Set, n)
	for i := 1; i <= n; i++ {
		ps, ok := setMap[i]
		if !ok {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("%w: missing instance %d", ErrSetGap, i)}, nil
		}
		if ps.aar == nil || ps.ams == nil || ps.as == nil {
			return Result{Status: ChainStatusFail, Err: fmt.Errorf("%w: instance %d", ErrSetIncomplete, i)}, nil
		}
		sets[i-1] = Set{
			Instance: i,
			AAR:      ps.aar,
			AMS:      ps.ams,
			AS:       ps.as,
		}
	}

	// Validate cv values.
	// AS[1].cv must be "none".
	if sets[0].AS.ChainValidation != ChainStatusNone {
		return Result{Status: ChainStatusFail, Sets: sets, Err: ErrCVNotNoneFirst}, nil
	}
	// AS[i].cv for i>1 must be "pass".
	for i := 1; i < n; i++ {
		if sets[i].AS.ChainValidation != ChainStatusPass {
			return Result{Status: ChainStatusFail, Sets: sets, Err: fmt.Errorf("%w: instance %d has cv=%s", ErrCVNotPass, i+1, sets[i].AS.ChainValidation)}, nil
		}
	}
	// The most recent AS must not have cv=fail (already handled above since it's
	// either i=1 requiring "none" or i>1 requiring "pass").

	// Verify AMS[N] (most recent).
	amsN := sets[n-1].AMS
	if err := verifyAMS(ctx, log, resolver, amsN, hdrs, bodyOffset, r); err != nil {
		return Result{Status: ChainStatusFail, Sets: sets, Err: fmt.Errorf("%w: %v", ErrAMSVerify, err)}, nil
	}

	// Optionally verify older AMS for oldest-pass.
	oldestPass := n
	for i := n - 1; i >= 1; i-- {
		if err := verifyAMS(ctx, log, resolver, sets[i-1].AMS, hdrs, bodyOffset, r); err != nil {
			break
		}
		oldestPass = i
	}

	// Verify all ARC-Seals from N to 1.
	for i := n; i >= 1; i-- {
		if err := verifyAS(ctx, log, resolver, sets, i); err != nil {
			return Result{Status: ChainStatusFail, Sets: sets, Err: fmt.Errorf("%w: instance %d: %v", ErrASVerify, i, err)}, nil
		}
	}

	return Result{Status: ChainStatusPass, Sets: sets, OldestPass: oldestPass}, nil
}

// verifyAMS verifies the ARC-Message-Signature for a single instance.
func verifyAMS(ctx context.Context, log mlog.Log, resolver dns.Resolver, ams *AMS, hdrs []dkim.Header, bodyOffset int, msg io.ReaderAt) error {
	// Lookup the DKIM key.
	_, record, _, _, err := dkim.Lookup(ctx, log.Logger, resolver, ams.Selector, ams.Domain)
	if err != nil {
		return fmt.Errorf("dkim lookup for AMS d=%s s=%s: %w", ams.Domain.ASCII, ams.Selector.ASCII, err)
	}

	h, ok := dkim.AlgHash(ams.AlgorithmHash)
	if !ok {
		return fmt.Errorf("unknown hash algorithm %q", ams.AlgorithmHash)
	}

	// Parse canonicalization.
	canonHeaderSimple, canonBodySimple, err := parseCanonicalization(ams.Canonicalization)
	if err != nil {
		return err
	}

	// Build a fake DKIM Sig for DataHash computation.
	sig := &dkim.Sig{
		SignedHeaders: ams.SignedHeaders,
	}

	// Compute data hash (over signed headers + AMS header with b= emptied).
	dh, err := dkim.DataHash(h.New(), canonHeaderSimple, sig, hdrs, ams.VerifySig)
	if err != nil {
		return fmt.Errorf("computing data hash: %w", err)
	}

	// Verify signature against public key.
	if err := verifySignature(record, ams.AlgorithmSign, h, dh, ams.Signature); err != nil {
		return fmt.Errorf("verifying AMS signature: %w", err)
	}

	// Compute and verify body hash.
	br := bufio.NewReader(&moxio.AtReader{R: msg, Offset: int64(bodyOffset)})
	bh, err := dkim.BodyHash(h.New(), canonBodySimple, br)
	if err != nil {
		return fmt.Errorf("computing body hash: %w", err)
	}
	if !bytes.Equal(ams.BodyHash, bh) {
		return fmt.Errorf("%w: expected %x, got %x", ErrBodyHashMismatch, ams.BodyHash, bh)
	}

	return nil
}

// verifyAS verifies the ARC-Seal at the given instance number.
func verifyAS(ctx context.Context, log mlog.Log, resolver dns.Resolver, sets []Set, instance int) error {
	as := sets[instance-1].AS

	// Lookup the DKIM key.
	_, record, _, _, err := dkim.Lookup(ctx, log.Logger, resolver, as.Selector, as.Domain)
	if err != nil {
		return fmt.Errorf("dkim lookup for AS d=%s s=%s: %w", as.Domain.ASCII, as.Selector.ASCII, err)
	}

	h, ok := dkim.AlgHash(as.AlgorithmHash)
	if !ok {
		return fmt.Errorf("unknown hash algorithm %q", as.AlgorithmHash)
	}

	// Compute the seal data hash.
	dh, err := sealDataHash(h.New(), sets, instance)
	if err != nil {
		return fmt.Errorf("computing seal data hash: %w", err)
	}

	// Verify signature.
	if err := verifySignature(record, as.AlgorithmSign, h, dh, as.Signature); err != nil {
		return fmt.Errorf("verifying AS signature: %w", err)
	}

	return nil
}

// sealDataHash computes the hash for verifying/signing an ARC-Seal at instance i.
// It hashes all ARC headers from instance 1 to i in order:
//
//	AAR[1], AMS[1], AS[1], AAR[2], AMS[2], AS[2], ..., AAR[i], AMS[i], AS[i]
//
// where AS[i] has b= emptied. All headers use relaxed canonicalization.
func sealDataHash(h hash.Hash, sets []Set, instance int) ([]byte, error) {
	for i := 1; i <= instance; i++ {
		s := sets[i-1]

		// AAR[i]
		ch, err := dkim.RelaxedCanonicalHeaderWithoutCRLF(string(s.AAR.Raw))
		if err != nil {
			return nil, fmt.Errorf("canonicalizing AAR[%d]: %w", i, err)
		}
		h.Write([]byte(ch))
		h.Write([]byte("\r\n"))

		// AMS[i]
		ch, err = dkim.RelaxedCanonicalHeaderWithoutCRLF(string(s.AMS.Raw))
		if err != nil {
			return nil, fmt.Errorf("canonicalizing AMS[%d]: %w", i, err)
		}
		h.Write([]byte(ch))
		h.Write([]byte("\r\n"))

		// AS[i] - for the current instance, use VerifySig (b= emptied); for others, use Raw.
		var asHdr string
		if i == instance {
			asHdr = string(s.AS.VerifySig)
		} else {
			// For prior instances, use the full raw header (without trailing CRLF).
			asHdr = strings.TrimSuffix(string(s.AS.Raw), "\r\n")
		}
		ch, err = dkim.RelaxedCanonicalHeaderWithoutCRLF(asHdr)
		if err != nil {
			return nil, fmt.Errorf("canonicalizing AS[%d]: %w", i, err)
		}
		if i < instance {
			h.Write([]byte(ch))
			h.Write([]byte("\r\n"))
		} else {
			// For the final AS, no trailing CRLF (like DKIM-Signature in dataHash).
			h.Write([]byte(ch))
		}
	}

	return h.Sum(nil), nil
}

// verifySignature verifies a signature against a DKIM DNS record's public key.
func verifySignature(record *dkim.Record, algSign string, hash crypto.Hash, dataHash, signature []byte) error {
	if record.PublicKey == nil {
		return fmt.Errorf("key has been revoked (empty public key)")
	}

	switch k := record.PublicKey.(type) {
	case *rsa.PublicKey:
		if !strings.EqualFold(record.Key, "rsa") || !strings.EqualFold(algSign, "rsa") {
			return fmt.Errorf("algorithm mismatch: record key=%q, signature=%q", record.Key, algSign)
		}
		if k.N.BitLen() < 1024 {
			return fmt.Errorf("rsa key too weak: %d bits, need at least 1024", k.N.BitLen())
		}
		if err := rsa.VerifyPKCS1v15(k, hash, dataHash, signature); err != nil {
			return fmt.Errorf("rsa verification: %w", err)
		}
	case ed25519.PublicKey:
		if !strings.EqualFold(record.Key, "ed25519") || !strings.EqualFold(algSign, "ed25519") {
			return fmt.Errorf("algorithm mismatch: record key=%q, signature=%q", record.Key, algSign)
		}
		if !ed25519.Verify(k, dataHash, signature) {
			return fmt.Errorf("ed25519 verification failed")
		}
	default:
		return fmt.Errorf("unknown public key type %T", record.PublicKey)
	}
	return nil
}

// parseCanonicalization parses a canonicalization string like "relaxed/relaxed"
// into header-simple and body-simple booleans.
func parseCanonicalization(c string) (headerSimple, bodySimple bool, err error) {
	t := strings.SplitN(c, "/", 2)
	switch strings.ToLower(t[0]) {
	case "simple":
		headerSimple = true
	case "relaxed":
	default:
		return false, false, fmt.Errorf("unknown header canonicalization %q", c)
	}
	canon := "simple"
	if len(t) == 2 {
		canon = t[1]
	}
	switch strings.ToLower(canon) {
	case "simple":
		bodySimple = true
	case "relaxed":
	default:
		return false, false, fmt.Errorf("unknown body canonicalization %q", c)
	}
	return
}
