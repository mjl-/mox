package arc

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var timeNow = time.Now // Replaced during tests.

// SealSelector holds key material for ARC sealing.
type SealSelector struct {
	Hash           string        // "sha256".
	PrivateKey     crypto.Signer // RSA or Ed25519.
	Domain         dns.Domain    // Signing domain (d=).
	SelectorDomain dns.Domain    // Selector name (s=).
	HeaderRelaxed  bool          // Use relaxed header canonicalization.
	BodyRelaxed    bool          // Use relaxed body canonicalization.
	Headers        []string      // Headers to include in AMS h=.
}

// Seal generates a new ARC set (AAR + AMS + AS headers) to prepend to a message.
//
// authResults is the Authentication-Results from this hop's verification.
// hostname is this server's hostname for the AAR authserv-id.
// msg is the message to sign (including any prior ARC headers).
//
// Returns the three headers (AAR + AMS + AS) as a string to prepend to the
// message.
func Seal(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, sel SealSelector, authResults message.AuthResults, hostname string, smtputf8 bool, msg io.ReaderAt) (string, error) {
	log := mlog.New("arc", elog)

	// Parse existing headers to collect existing ARC sets.
	hdrs, bodyOffset, err := dkim.ParseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	if err != nil {
		return "", fmt.Errorf("parsing headers: %w", err)
	}

	// Collect existing ARC sets.
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

	for _, h := range hdrs {
		switch h.LKey {
		case "arc-authentication-results":
			aar, err := ParseAAR(h.Raw, smtputf8)
			if err != nil {
				continue
			}
			s := ensureSet(aar.Instance)
			if s.aar == nil {
				s.aar = aar
			}
		case "arc-message-signature":
			ams, err := ParseAMS(h.Raw, smtputf8)
			if err != nil {
				continue
			}
			s := ensureSet(ams.Instance)
			if s.ams == nil {
				s.ams = ams
			}
		case "arc-seal":
			as, err := ParseAS(h.Raw, smtputf8)
			if err != nil {
				continue
			}
			s := ensureSet(as.Instance)
			if s.as == nil {
				s.as = as
			}
		}
	}

	// Determine highest existing instance.
	n := 0
	for i := range setMap {
		if i > n {
			n = i
		}
	}
	newInstance := n + 1
	if newInstance > 50 {
		return "", fmt.Errorf("too many ARC sets, already at %d", n)
	}

	// Build existing sets for seal hash computation.
	var existingSets []Set
	for i := 1; i <= n; i++ {
		ps, ok := setMap[i]
		if !ok || ps.aar == nil || ps.ams == nil || ps.as == nil {
			break
		}
		existingSets = append(existingSets, Set{
			Instance: i,
			AAR:      ps.aar,
			AMS:      ps.ams,
			AS:       ps.as,
		})
	}

	// Determine cv value.
	var cv ChainStatus
	if newInstance == 1 {
		cv = ChainStatusNone
	} else {
		// Verify existing chain.
		result, err := Verify(ctx, elog, resolver, smtputf8, msg)
		if err != nil {
			cv = ChainStatusFail
		} else if result.Status == ChainStatusPass {
			cv = ChainStatusPass
		} else {
			cv = ChainStatusFail
		}
	}

	// Generate AAR.
	aarPayload := authResults.Header()
	// Strip the "Authentication-Results: " prefix from the header and trailing CRLF.
	aarPayload = strings.TrimPrefix(aarPayload, "Authentication-Results:")
	aarPayload = strings.TrimSpace(strings.TrimSuffix(aarPayload, "\r\n"))
	aarStr := fmt.Sprintf("ARC-Authentication-Results: i=%d; %s\r\n", newInstance, aarPayload)

	aarParsed := &AAR{
		Instance:   newInstance,
		AuthServID: hostname,
		Raw:        []byte(aarStr),
	}

	// Determine hash algorithm.
	h, ok := dkim.AlgHash(sel.Hash)
	if !ok {
		return "", fmt.Errorf("unknown hash algorithm %q", sel.Hash)
	}

	// Determine canonicalization.
	canon := "simple"
	if sel.HeaderRelaxed {
		canon = "relaxed"
	}
	canon += "/"
	if sel.BodyRelaxed {
		canon += "relaxed"
	} else {
		canon += "simple"
	}

	// Compute body hash.
	br := bufio.NewReader(&moxio.AtReader{R: msg, Offset: int64(bodyOffset)})
	bh, err := dkim.BodyHash(h.New(), !sel.BodyRelaxed, br)
	if err != nil {
		return "", fmt.Errorf("computing body hash: %w", err)
	}

	// Determine algorithm name.
	var algSign string
	switch sel.PrivateKey.(type) {
	case *rsa.PrivateKey:
		algSign = "rsa"
	case ed25519.PrivateKey:
		algSign = "ed25519"
	default:
		return "", fmt.Errorf("unsupported private key type %T", sel.PrivateKey)
	}

	now := timeNow().Unix()

	// Generate AMS header (without signature first, for computing data hash).
	amsHdrNoSig := amsHeader(newInstance, algSign+"-"+sel.Hash, sel.Domain.ASCII,
		sel.SelectorDomain.ASCII, canon, sel.Headers, bh, nil, now)

	// The AMS verify sig is the header without trailing CRLF.
	amsVerifySig := []byte(strings.TrimSuffix(amsHdrNoSig, "\r\n"))

	// Build fake Sig for DataHash.
	sig := &dkim.Sig{
		SignedHeaders: sel.Headers,
	}

	// Compute data hash over signed headers + AMS header.
	dh, err := dkim.DataHash(h.New(), !sel.HeaderRelaxed, sig, hdrs, amsVerifySig)
	if err != nil {
		return "", fmt.Errorf("computing AMS data hash: %w", err)
	}

	// Sign AMS.
	amsSigBytes, err := signData(sel.PrivateKey, h, dh)
	if err != nil {
		return "", fmt.Errorf("signing AMS: %w", err)
	}

	// Generate final AMS header with signature.
	amsStr := amsHeader(newInstance, algSign+"-"+sel.Hash, sel.Domain.ASCII,
		sel.SelectorDomain.ASCII, canon, sel.Headers, bh, amsSigBytes, now)

	amsParsed := &AMS{
		Instance:      newInstance,
		AlgorithmSign: algSign,
		AlgorithmHash: sel.Hash,
		Signature:     amsSigBytes,
		BodyHash:      bh,
		Domain:        sel.Domain,
		Selector:      sel.SelectorDomain,
		SignedHeaders: sel.Headers,
		SignTime:      now,
		Raw:           []byte(amsStr),
		VerifySig:     amsVerifySig,
	}

	// Generate AS header (without signature first for computing seal hash).
	asHdrNoSig := asHeaderStr(newInstance, algSign+"-"+sel.Hash, sel.Domain.ASCII,
		sel.SelectorDomain.ASCII, cv, nil, now)
	asVerifySig := []byte(strings.TrimSuffix(asHdrNoSig, "\r\n"))

	// Build all sets for seal hash: existing sets + new set.
	allSets := make([]Set, len(existingSets)+1)
	copy(allSets, existingSets)
	allSets[len(allSets)-1] = Set{
		Instance: newInstance,
		AAR:      aarParsed,
		AMS:      amsParsed,
		AS: &AS{
			Instance:        newInstance,
			AlgorithmSign:   algSign,
			AlgorithmHash:   sel.Hash,
			Domain:          sel.Domain,
			Selector:        sel.SelectorDomain,
			ChainValidation: cv,
			SignTime:        now,
			Raw:             []byte(asHdrNoSig),
			VerifySig:       asVerifySig,
		},
	}

	// Compute seal data hash.
	sdh, err := sealDataHash(h.New(), allSets, newInstance)
	if err != nil {
		return "", fmt.Errorf("computing seal data hash: %w", err)
	}

	// Sign AS.
	asSigBytes, err := signData(sel.PrivateKey, h, sdh)
	if err != nil {
		return "", fmt.Errorf("signing AS: %w", err)
	}

	// Generate final AS header with signature.
	asStr := asHeaderStr(newInstance, algSign+"-"+sel.Hash, sel.Domain.ASCII,
		sel.SelectorDomain.ASCII, cv, asSigBytes, now)

	log.Debug("arc seal complete",
		slog.Int("instance", newInstance),
		slog.String("cv", string(cv)),
		slog.String("domain", sel.Domain.ASCII),
		slog.String("selector", sel.SelectorDomain.ASCII))

	// Return headers in order: AAR, AMS, AS.
	return aarStr + amsStr + asStr, nil
}

// amsHeader generates an ARC-Message-Signature header string.
func amsHeader(instance int, algorithm, domain, selector, canon string, signedHeaders []string, bodyHash, signature []byte, signTime int64) string {
	w := &message.HeaderWriter{}
	w.Addf("", "ARC-Message-Signature: i=%d;", instance)
	w.Addf(" ", "a=%s;", algorithm)
	w.Addf(" ", "d=%s;", domain)
	w.Addf(" ", "s=%s;", selector)

	if canon != "" && !strings.EqualFold(canon, "simple") && !strings.EqualFold(canon, "simple/simple") {
		w.Addf(" ", "c=%s;", canon)
	}

	if signTime >= 0 {
		w.Addf(" ", "t=%d;", signTime)
	}

	if len(signedHeaders) > 0 {
		for i, v := range signedHeaders {
			sep := ""
			if i == 0 {
				v = "h=" + v
				sep = " "
			}
			if i < len(signedHeaders)-1 {
				v += ":"
			} else {
				v += ";"
			}
			w.Addf(sep, "%s", v)
		}
	}

	w.Addf(" ", "bh=%s;", base64.StdEncoding.EncodeToString(bodyHash))

	w.Addf(" ", "b=")
	if len(signature) > 0 {
		w.AddWrap([]byte(base64.StdEncoding.EncodeToString(signature)), false)
	}
	w.Add("\r\n")
	return w.String()
}

// asHeaderStr generates an ARC-Seal header string.
func asHeaderStr(instance int, algorithm, domain, selector string, cv ChainStatus, signature []byte, signTime int64) string {
	w := &message.HeaderWriter{}
	w.Addf("", "ARC-Seal: i=%d;", instance)
	w.Addf(" ", "a=%s;", algorithm)
	w.Addf(" ", "d=%s;", domain)
	w.Addf(" ", "s=%s;", selector)
	w.Addf(" ", "cv=%s;", string(cv))

	if signTime >= 0 {
		w.Addf(" ", "t=%d;", signTime)
	}

	w.Addf(" ", "b=")
	if len(signature) > 0 {
		w.AddWrap([]byte(base64.StdEncoding.EncodeToString(signature)), false)
	}
	w.Add("\r\n")
	return w.String()
}

// signData signs a data hash with the given private key.
func signData(key crypto.Signer, hash crypto.Hash, dataHash []byte) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Sign(cryptorand.Reader, dataHash, hash)
	case ed25519.PrivateKey:
		// PureEdDSA: sign the hash, not prehashed. crypto.Hash(0) indicates this.
		return k.Sign(cryptorand.Reader, dataHash, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}
