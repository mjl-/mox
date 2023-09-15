// Package dkim (DomainKeys Identified Mail signatures, RFC 6376) signs and
// verifies DKIM signatures.
//
// Signatures are added to email messages in DKIM-Signature headers. By signing a
// message, a domain takes responsibility for the message. A message can have
// signatures for multiple domains, and the domain does not necessarily have to
// match a domain in a From header. Receiving mail servers can build a spaminess
// reputation based on domains that signed the message, along with other
// mechanisms.
package dkim

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/smtp"
)

var xlog = mlog.New("dkim")

var (
	metricDKIMSign = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_dkim_sign_total",
			Help: "DKIM messages signings, label key is the type of key, rsa or ed25519.",
		},
		[]string{
			"key",
		},
	)
	metricDKIMVerify = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_dkim_verify_duration_seconds",
			Help:    "DKIM verify, including lookup, duration and result.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20},
		},
		[]string{
			"algorithm",
			"status",
		},
	)
)

var timeNow = time.Now // Replaced during tests.

// Status is the result of verifying a DKIM-Signature as described by RFC 8601,
// "Message Header Field for Indicating Message Authentication Status".
type Status string

// ../rfc/8601:959 ../rfc/6376:1770 ../rfc/6376:2459

const (
	StatusNone      Status = "none"      // Message was not signed.
	StatusPass      Status = "pass"      // Message was signed and signature was verified.
	StatusFail      Status = "fail"      // Message was signed, but signature was invalid.
	StatusPolicy    Status = "policy"    // Message was signed, but signature is not accepted by policy.
	StatusNeutral   Status = "neutral"   // Message was signed, but the signature contains an error or could not be processed. This status is also used for errors not covered by other statuses.
	StatusTemperror Status = "temperror" // Message could not be verified. E.g. because of DNS resolve error. A later attempt may succeed. A missing DNS record is treated as temporary error, a new key may not have propagated through DNS shortly after it was taken into use.
	StatusPermerror Status = "permerror" // Message cannot be verified. E.g. when a required header field is absent or for invalid (combination of) parameters. Typically set if a DNS record does not allow the signature, e.g. due to algorithm mismatch or expiry.
)

// Lookup errors.
var (
	ErrNoRecord        = errors.New("dkim: no dkim dns record for selector and domain")
	ErrMultipleRecords = errors.New("dkim: multiple dkim dns record for selector and domain")
	ErrDNS             = errors.New("dkim: lookup of dkim dns record")
	ErrSyntax          = errors.New("dkim: syntax error in dkim dns record")
)

// Signature verification errors.
var (
	ErrSigAlgMismatch          = errors.New("dkim: signature algorithm mismatch with dns record")
	ErrHashAlgNotAllowed       = errors.New("dkim: hash algorithm not allowed by dns record")
	ErrKeyNotForEmail          = errors.New("dkim: dns record not allowed for use with email")
	ErrDomainIdentityMismatch  = errors.New("dkim: dns record disallows mismatch of domain (d=) and identity (i=)")
	ErrSigExpired              = errors.New("dkim: signature has expired")
	ErrHashAlgorithmUnknown    = errors.New("dkim: unknown hash algorithm")
	ErrBodyhashMismatch        = errors.New("dkim: body hash does not match")
	ErrSigVerify               = errors.New("dkim: signature verification failed")
	ErrSigAlgorithmUnknown     = errors.New("dkim: unknown signature algorithm")
	ErrCanonicalizationUnknown = errors.New("dkim: unknown canonicalization")
	ErrHeaderMalformed         = errors.New("dkim: mail message header is malformed")
	ErrFrom                    = errors.New("dkim: bad from headers")
	ErrQueryMethod             = errors.New("dkim: no recognized query method")
	ErrKeyRevoked              = errors.New("dkim: key has been revoked")
	ErrTLD                     = errors.New("dkim: signed domain is top-level domain, above organizational domain")
	ErrPolicy                  = errors.New("dkim: signature rejected by policy")
	ErrWeakKey                 = errors.New("dkim: key is too weak, need at least 1024 bits for rsa")
)

// Result is the conclusion of verifying one DKIM-Signature header. An email can
// have multiple signatures, each with different parameters.
//
// To decide what to do with a message, both the signature parameters and the DNS
// TXT record have to be consulted.
type Result struct {
	Status Status
	Sig    *Sig    // Parsed form of DKIM-Signature header. Can be nil for invalid DKIM-Signature header.
	Record *Record // Parsed form of DKIM DNS record for selector and domain in Sig. Optional.
	Err    error   // If Status is not StatusPass, this error holds the details and can be checked using errors.Is.
}

// todo: use some io.Writer to hash the body and the header.

// Sign returns line(s) with DKIM-Signature headers, generated according to the configuration.
func Sign(ctx context.Context, localpart smtp.Localpart, domain dns.Domain, c config.DKIM, smtputf8 bool, msg io.ReaderAt) (headers string, rerr error) {
	log := xlog.WithContext(ctx)
	start := timeNow()
	defer func() {
		log.Debugx("dkim sign result", rerr, mlog.Field("localpart", localpart), mlog.Field("domain", domain), mlog.Field("smtputf8", smtputf8), mlog.Field("duration", time.Since(start)))
	}()

	hdrs, bodyOffset, err := parseHeaders(bufio.NewReader(&moxio.AtReader{R: msg}))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrHeaderMalformed, err)
	}
	nfrom := 0
	for _, h := range hdrs {
		if h.lkey == "from" {
			nfrom++
		}
	}
	if nfrom != 1 {
		return "", fmt.Errorf("%w: message has %d from headers, need exactly 1", ErrFrom, nfrom)
	}

	type hashKey struct {
		simple bool   // Canonicalization.
		hash   string // lower-case hash.
	}

	var bodyHashes = map[hashKey][]byte{}

	for _, sign := range c.Sign {
		sel := c.Selectors[sign]
		sig := newSigWithDefaults()
		sig.Version = 1
		switch sel.Key.(type) {
		case *rsa.PrivateKey:
			sig.AlgorithmSign = "rsa"
			metricDKIMSign.WithLabelValues("rsa").Inc()
		case ed25519.PrivateKey:
			sig.AlgorithmSign = "ed25519"
			metricDKIMSign.WithLabelValues("ed25519").Inc()
		default:
			return "", fmt.Errorf("internal error, unknown pivate key %T", sel.Key)
		}
		sig.AlgorithmHash = sel.HashEffective
		sig.Domain = domain
		sig.Selector = sel.Domain
		sig.Identity = &Identity{&localpart, domain}
		sig.SignedHeaders = append([]string{}, sel.HeadersEffective...)
		if !sel.DontSealHeaders {
			// ../rfc/6376:2156
			// Each time a header name is added to the signature, the next unused value is
			// signed (in reverse order as they occur in the message). So we can add each
			// header name as often as it occurs. But now we'll add the header names one
			// additional time, preventing someone from adding one more header later on.
			counts := map[string]int{}
			for _, h := range hdrs {
				counts[h.lkey]++
			}
			for _, h := range sel.HeadersEffective {
				for j := counts[strings.ToLower(h)]; j > 0; j-- {
					sig.SignedHeaders = append(sig.SignedHeaders, h)
				}
			}
		}
		sig.SignTime = timeNow().Unix()
		if sel.ExpirationSeconds > 0 {
			sig.ExpireTime = sig.SignTime + int64(sel.ExpirationSeconds)
		}

		sig.Canonicalization = "simple"
		if sel.Canonicalization.HeaderRelaxed {
			sig.Canonicalization = "relaxed"
		}
		sig.Canonicalization += "/"
		if sel.Canonicalization.BodyRelaxed {
			sig.Canonicalization += "relaxed"
		} else {
			sig.Canonicalization += "simple"
		}

		h, hok := algHash(sig.AlgorithmHash)
		if !hok {
			return "", fmt.Errorf("unrecognized hash algorithm %q", sig.AlgorithmHash)
		}

		// We must now first calculate the hash over the body. Then include that hash in a
		// new DKIM-Signature header. Then hash that and the signed headers into a data
		// hash. Then that hash is finally signed and the signature included in the new
		// DKIM-Signature header.
		// ../rfc/6376:1700

		hk := hashKey{!sel.Canonicalization.BodyRelaxed, strings.ToLower(sig.AlgorithmHash)}
		if bh, ok := bodyHashes[hk]; ok {
			sig.BodyHash = bh
		} else {
			br := bufio.NewReader(&moxio.AtReader{R: msg, Offset: int64(bodyOffset)})
			bh, err = bodyHash(h.New(), !sel.Canonicalization.BodyRelaxed, br)
			if err != nil {
				return "", err
			}
			sig.BodyHash = bh
			bodyHashes[hk] = bh
		}

		sigh, err := sig.Header()
		if err != nil {
			return "", err
		}
		verifySig := []byte(strings.TrimSuffix(sigh, "\r\n"))

		dh, err := dataHash(h.New(), !sel.Canonicalization.HeaderRelaxed, sig, hdrs, verifySig)
		if err != nil {
			return "", err
		}

		switch key := sel.Key.(type) {
		case *rsa.PrivateKey:
			sig.Signature, err = key.Sign(cryptorand.Reader, dh, h)
			if err != nil {
				return "", fmt.Errorf("signing data: %v", err)
			}
		case ed25519.PrivateKey:
			// crypto.Hash(0) indicates data isn't prehashed (ed25519ph). We are using
			// PureEdDSA to sign the sha256 hash. ../rfc/8463:123 ../rfc/8032:427
			sig.Signature, err = key.Sign(cryptorand.Reader, dh, crypto.Hash(0))
			if err != nil {
				return "", fmt.Errorf("signing data: %v", err)
			}
		default:
			return "", fmt.Errorf("unsupported private key type: %s", err)
		}

		sigh, err = sig.Header()
		if err != nil {
			return "", err
		}
		headers += sigh
	}

	return headers, nil
}

// Lookup looks up the DKIM TXT record and parses it.
//
// A requested record is <selector>._domainkey.<domain>. Exactly one valid DKIM
// record should be present.
func Lookup(ctx context.Context, resolver dns.Resolver, selector, domain dns.Domain) (rstatus Status, rrecord *Record, rtxt string, rerr error) {
	log := xlog.WithContext(ctx)
	start := timeNow()
	defer func() {
		log.Debugx("dkim lookup result", rerr, mlog.Field("selector", selector), mlog.Field("domain", domain), mlog.Field("status", rstatus), mlog.Field("record", rrecord), mlog.Field("duration", time.Since(start)))
	}()

	name := selector.ASCII + "._domainkey." + domain.ASCII + "."
	records, err := dns.WithPackage(resolver, "dkim").LookupTXT(ctx, name)
	if dns.IsNotFound(err) {
		// ../rfc/6376:2608
		// We must return StatusPermerror. We may want to return StatusTemperror because in
		// practice someone will start using a new key before DNS changes have propagated.
		return StatusPermerror, nil, "", fmt.Errorf("%w: dns name %q", ErrNoRecord, name)
	} else if err != nil {
		return StatusTemperror, nil, "", fmt.Errorf("%w: dns name %q: %s", ErrDNS, name, err)
	}

	// ../rfc/6376:2612
	var status = StatusTemperror
	var record *Record
	var txt string
	err = nil
	for _, s := range records {
		// We interpret ../rfc/6376:2621 to mean that a record that claims to be v=DKIM1,
		// but isn't actually valid, results in a StatusPermFail. But a record that isn't
		// claiming to be DKIM1 is ignored.
		var r *Record
		var isdkim bool
		r, isdkim, err = ParseRecord(s)
		if err != nil && isdkim {
			return StatusPermerror, nil, txt, fmt.Errorf("%w: %s", ErrSyntax, err)
		} else if err != nil {
			// Hopefully the remote MTA admin discovers the configuration error and fix it for
			// an upcoming delivery attempt, in case we rejected with temporary status.
			status = StatusTemperror
			err = fmt.Errorf("%w: not a dkim record: %s", ErrSyntax, err)
			continue
		}
		// If there are multiple valid records, return a temporary error. Perhaps the error is fixed soon.
		// ../rfc/6376:1609
		// ../rfc/6376:2584
		if record != nil {
			return StatusTemperror, nil, "", fmt.Errorf("%w: dns name %q", ErrMultipleRecords, name)
		}
		record = r
		txt = s
		err = nil
	}

	if record == nil {
		return status, nil, "", err
	}
	return StatusNeutral, record, txt, nil
}

// Verify parses the DKIM-Signature headers in a message and verifies each of them.
//
// If the headers of the message cannot be found, an error is returned.
// Otherwise, each DKIM-Signature header is reflected in the returned results.
//
// NOTE: Verify does not check if the domain (d=) that signed the message is
// the domain of the sender. The caller, e.g. through DMARC, should do this.
//
// If ignoreTestMode is true and the DKIM record is in test mode (t=y), a
// verification failure is treated as actual failure. With ignoreTestMode
// false, such verification failures are treated as if there is no signature by
// returning StatusNone.
func Verify(ctx context.Context, resolver dns.Resolver, smtputf8 bool, policy func(*Sig) error, r io.ReaderAt, ignoreTestMode bool) (results []Result, rerr error) {
	log := xlog.WithContext(ctx)
	start := timeNow()
	defer func() {
		duration := float64(time.Since(start)) / float64(time.Second)
		for _, r := range results {
			var alg string
			if r.Sig != nil {
				alg = r.Sig.Algorithm()
			}
			status := string(r.Status)
			metricDKIMVerify.WithLabelValues(alg, status).Observe(duration)
		}

		if len(results) == 0 {
			log.Debugx("dkim verify result", rerr, mlog.Field("smtputf8", smtputf8), mlog.Field("duration", time.Since(start)))
		}
		for _, result := range results {
			log.Debugx("dkim verify result", result.Err, mlog.Field("smtputf8", smtputf8), mlog.Field("status", result.Status), mlog.Field("sig", result.Sig), mlog.Field("record", result.Record), mlog.Field("duration", time.Since(start)))
		}
	}()

	hdrs, bodyOffset, err := parseHeaders(bufio.NewReader(&moxio.AtReader{R: r}))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrHeaderMalformed, err)
	}

	// todo: reuse body hashes and possibly verify signatures in parallel. and start the dns lookup immediately. ../rfc/6376:2697

	for _, h := range hdrs {
		if h.lkey != "dkim-signature" {
			continue
		}

		sig, verifySig, err := parseSignature(h.raw, smtputf8)
		if err != nil {
			// ../rfc/6376:2503
			err := fmt.Errorf("parsing DKIM-Signature header: %w", err)
			results = append(results, Result{StatusPermerror, nil, nil, err})
			continue
		}

		h, canonHeaderSimple, canonDataSimple, err := checkSignatureParams(ctx, sig)
		if err != nil {
			results = append(results, Result{StatusPermerror, nil, nil, err})
			continue
		}

		// ../rfc/6376:2560
		if err := policy(sig); err != nil {
			err := fmt.Errorf("%w: %s", ErrPolicy, err)
			results = append(results, Result{StatusPolicy, nil, nil, err})
			continue
		}

		br := bufio.NewReader(&moxio.AtReader{R: r, Offset: int64(bodyOffset)})
		status, txt, err := verifySignature(ctx, resolver, sig, h, canonHeaderSimple, canonDataSimple, hdrs, verifySig, br, ignoreTestMode)
		results = append(results, Result{status, sig, txt, err})
	}
	return results, nil
}

// check if signature is acceptable.
// Only looks at the signature parameters, not at the DNS record.
func checkSignatureParams(ctx context.Context, sig *Sig) (hash crypto.Hash, canonHeaderSimple, canonBodySimple bool, rerr error) {
	// "From" header is required, ../rfc/6376:2122 ../rfc/6376:2546
	var from bool
	for _, h := range sig.SignedHeaders {
		if strings.EqualFold(h, "from") {
			from = true
			break
		}
	}
	if !from {
		return 0, false, false, fmt.Errorf(`%w: required "from" header not signed`, ErrFrom)
	}

	// ../rfc/6376:2550
	if sig.ExpireTime >= 0 && sig.ExpireTime < timeNow().Unix() {
		return 0, false, false, fmt.Errorf("%w: expiration time %q", ErrSigExpired, time.Unix(sig.ExpireTime, 0).Format(time.RFC3339))
	}

	// ../rfc/6376:2554
	// ../rfc/6376:3284
	// Refuse signatures that reach beyond declared scope. We use the existing
	// publicsuffix.Lookup to lookup a fake subdomain of the signing domain. If this
	// supposed subdomain is actually an organizational domain, the signing domain
	// shouldn't be signing for its organizational domain.
	subdom := sig.Domain
	subdom.ASCII = "x." + subdom.ASCII
	if subdom.Unicode != "" {
		subdom.Unicode = "x." + subdom.Unicode
	}
	if orgDom := publicsuffix.Lookup(ctx, subdom); subdom.ASCII == orgDom.ASCII {
		return 0, false, false, fmt.Errorf("%w: %s", ErrTLD, sig.Domain)
	}

	h, hok := algHash(sig.AlgorithmHash)
	if !hok {
		return 0, false, false, fmt.Errorf("%w: %q", ErrHashAlgorithmUnknown, sig.AlgorithmHash)
	}

	t := strings.SplitN(sig.Canonicalization, "/", 2)

	switch strings.ToLower(t[0]) {
	case "simple":
		canonHeaderSimple = true
	case "relaxed":
	default:
		return 0, false, false, fmt.Errorf("%w: header canonicalization %q", ErrCanonicalizationUnknown, sig.Canonicalization)
	}

	canon := "simple"
	if len(t) == 2 {
		canon = t[1]
	}
	switch strings.ToLower(canon) {
	case "simple":
		canonBodySimple = true
	case "relaxed":
	default:
		return 0, false, false, fmt.Errorf("%w: body canonicalization %q", ErrCanonicalizationUnknown, sig.Canonicalization)
	}

	// We only recognize query method dns/txt, which is the default. ../rfc/6376:1268
	if len(sig.QueryMethods) > 0 {
		var dnstxt bool
		for _, m := range sig.QueryMethods {
			if strings.EqualFold(m, "dns/txt") {
				dnstxt = true
				break
			}
		}
		if !dnstxt {
			return 0, false, false, fmt.Errorf("%w: need dns/txt", ErrQueryMethod)
		}
	}

	return h, canonHeaderSimple, canonBodySimple, nil
}

// lookup the public key in the DNS and verify the signature.
func verifySignature(ctx context.Context, resolver dns.Resolver, sig *Sig, hash crypto.Hash, canonHeaderSimple, canonDataSimple bool, hdrs []header, verifySig []byte, body *bufio.Reader, ignoreTestMode bool) (Status, *Record, error) {
	// ../rfc/6376:2604
	status, record, _, err := Lookup(ctx, resolver, sig.Selector, sig.Domain)
	if err != nil {
		// todo: for temporary errors, we could pass on information so caller returns a 4.7.5 ecode, ../rfc/6376:2777
		return status, nil, err
	}
	status, err = verifySignatureRecord(record, sig, hash, canonHeaderSimple, canonDataSimple, hdrs, verifySig, body, ignoreTestMode)
	return status, record, err
}

// verify a DKIM signature given the record from dns and signature from the email message.
func verifySignatureRecord(r *Record, sig *Sig, hash crypto.Hash, canonHeaderSimple, canonDataSimple bool, hdrs []header, verifySig []byte, body *bufio.Reader, ignoreTestMode bool) (rstatus Status, rerr error) {
	if !ignoreTestMode {
		// ../rfc/6376:1558
		y := false
		for _, f := range r.Flags {
			if strings.EqualFold(f, "y") {
				y = true
				break
			}
		}
		if y {
			defer func() {
				if rstatus != StatusPass {
					rstatus = StatusNone
				}
			}()
		}
	}

	// ../rfc/6376:2639
	if len(r.Hashes) > 0 {
		ok := false
		for _, h := range r.Hashes {
			if strings.EqualFold(h, sig.AlgorithmHash) {
				ok = true
				break
			}
		}
		if !ok {
			return StatusPermerror, fmt.Errorf("%w: dkim dns record expects one of %q, message uses %q", ErrHashAlgNotAllowed, strings.Join(r.Hashes, ","), sig.AlgorithmHash)
		}
	}

	// ../rfc/6376:2651
	if !strings.EqualFold(r.Key, sig.AlgorithmSign) {
		return StatusPermerror, fmt.Errorf("%w: dkim dns record requires algorithm %q, message has %q", ErrSigAlgMismatch, r.Key, sig.AlgorithmSign)
	}

	// ../rfc/6376:2645
	if r.PublicKey == nil {
		return StatusPermerror, ErrKeyRevoked
	} else if rsaKey, ok := r.PublicKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 1024 {
		// todo: find a reference that supports this.
		return StatusPermerror, ErrWeakKey
	}

	// ../rfc/6376:1541
	if !r.ServiceAllowed("email") {
		return StatusPermerror, ErrKeyNotForEmail
	}
	for _, t := range r.Flags {
		// ../rfc/6376:1575
		// ../rfc/6376:1805
		if strings.EqualFold(t, "s") && sig.Identity != nil {
			if sig.Identity.Domain.ASCII != sig.Domain.ASCII {
				return StatusPermerror, fmt.Errorf("%w: i= identity domain %q must match d= domain %q", ErrDomainIdentityMismatch, sig.Domain.ASCII, sig.Identity.Domain.ASCII)
			}
		}
	}

	if sig.Length >= 0 {
		// todo future: implement l= parameter in signatures. we don't currently allow this through policy check.
		return StatusPermerror, fmt.Errorf("l= (length) parameter in signature not yet implemented")
	}

	// We first check the signature is with the claimed body hash is valid. Then we
	// verify the body hash. In case of invalid signatures, we won't read the entire
	// body.
	// ../rfc/6376:1700
	// ../rfc/6376:2656

	dh, err := dataHash(hash.New(), canonHeaderSimple, sig, hdrs, verifySig)
	if err != nil {
		// Any error is likely an invalid header field in the message, hence permanent error.
		return StatusPermerror, fmt.Errorf("calculating data hash: %w", err)
	}

	switch k := r.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, hash, dh, sig.Signature); err != nil {
			return StatusFail, fmt.Errorf("%w: rsa verification: %s", ErrSigVerify, err)
		}
	case ed25519.PublicKey:
		if ok := ed25519.Verify(k, dh, sig.Signature); !ok {
			return StatusFail, fmt.Errorf("%w: ed25519 verification", ErrSigVerify)
		}
	default:
		return StatusPermerror, fmt.Errorf("%w: unrecognized signature algorithm %q", ErrSigAlgorithmUnknown, r.Key)
	}

	bh, err := bodyHash(hash.New(), canonDataSimple, body)
	if err != nil {
		// Any error is likely some internal error, hence temporary error.
		return StatusTemperror, fmt.Errorf("calculating body hash: %w", err)
	}
	if !bytes.Equal(sig.BodyHash, bh) {
		return StatusFail, fmt.Errorf("%w: signature bodyhash %x != calculated bodyhash %x", ErrBodyhashMismatch, sig.BodyHash, bh)
	}

	return StatusPass, nil
}

func algHash(s string) (crypto.Hash, bool) {
	if strings.EqualFold(s, "sha1") {
		return crypto.SHA1, true
	} else if strings.EqualFold(s, "sha256") {
		return crypto.SHA256, true
	}
	return 0, false
}

// bodyHash calculates the hash over the body.
func bodyHash(h hash.Hash, canonSimple bool, body *bufio.Reader) ([]byte, error) {
	// todo: take l= into account. we don't currently allow it for policy reasons.

	var crlf = []byte("\r\n")

	if canonSimple {
		// ../rfc/6376:864, ensure body ends with exactly one trailing crlf.
		ncrlf := 0
		for {
			buf, err := body.ReadBytes('\n')
			if len(buf) == 0 && err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			hascrlf := bytes.HasSuffix(buf, crlf)
			if hascrlf {
				buf = buf[:len(buf)-2]
			}
			if len(buf) > 0 {
				for ; ncrlf > 0; ncrlf-- {
					h.Write(crlf)
				}
				h.Write(buf)
			}
			if hascrlf {
				ncrlf++
			}
		}
		h.Write(crlf)
	} else {
		hb := bufio.NewWriter(h)

		// We go through the body line by line, replacing WSP with a single space and removing whitespace at the end of lines.
		// We stash "empty" lines. If they turn out to be at the end of the file, we must drop them.
		stash := &bytes.Buffer{}
		var line bool         // Whether buffer read is for continuation of line.
		var prev byte         // Previous byte read for line.
		linesEmpty := true    // Whether stash contains only empty lines and may need to be dropped.
		var bodynonempty bool // Whether body is non-empty, for adding missing crlf.
		var hascrlf bool      // Whether current/last line ends with crlf, for adding missing crlf.
		for {
			// todo: should not read line at a time, count empty lines. reduces max memory usage. a message with lots of empty lines can cause high memory use.
			buf, err := body.ReadBytes('\n')
			if len(buf) == 0 && err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			bodynonempty = true

			hascrlf = bytes.HasSuffix(buf, crlf)
			if hascrlf {
				buf = buf[:len(buf)-2]

				// ../rfc/6376:893, "ignore all whitespace at the end of lines".
				// todo: what is "whitespace"? it isn't WSP (space and tab), the next line mentions WSP explicitly for another rule. should we drop trailing \r, \n, \v, more?
				buf = bytes.TrimRight(buf, " \t")
			}

			// Replace one or more WSP to a single SP.
			for i, c := range buf {
				wsp := c == ' ' || c == '\t'
				if (i >= 0 || line) && wsp {
					if prev == ' ' {
						continue
					}
					prev = ' '
					c = ' '
				} else {
					prev = c
				}
				if !wsp {
					linesEmpty = false
				}
				stash.WriteByte(c)
			}
			if hascrlf {
				stash.Write(crlf)
			}
			line = !hascrlf
			if !linesEmpty {
				hb.Write(stash.Bytes())
				stash.Reset()
				linesEmpty = true
			}
		}
		// ../rfc/6376:886
		// Only for non-empty bodies without trailing crlf do we add the missing crlf.
		if bodynonempty && !hascrlf {
			hb.Write(crlf)
		}

		hb.Flush()
	}
	return h.Sum(nil), nil
}

func dataHash(h hash.Hash, canonSimple bool, sig *Sig, hdrs []header, verifySig []byte) ([]byte, error) {
	headers := ""
	revHdrs := map[string][]header{}
	for _, h := range hdrs {
		revHdrs[h.lkey] = append([]header{h}, revHdrs[h.lkey]...)
	}

	for _, key := range sig.SignedHeaders {
		lkey := strings.ToLower(key)
		h := revHdrs[lkey]
		if len(h) == 0 {
			continue
		}
		revHdrs[lkey] = h[1:]
		s := string(h[0].raw)
		if canonSimple {
			// ../rfc/6376:823
			// Add unmodified.
			headers += s
		} else {
			ch, err := relaxedCanonicalHeaderWithoutCRLF(s)
			if err != nil {
				return nil, fmt.Errorf("canonicalizing header: %w", err)
			}
			headers += ch + "\r\n"
		}
	}
	// ../rfc/6376:2377, canonicalization does not apply to the dkim-signature header.
	h.Write([]byte(headers))
	dkimSig := verifySig
	if !canonSimple {
		ch, err := relaxedCanonicalHeaderWithoutCRLF(string(verifySig))
		if err != nil {
			return nil, fmt.Errorf("canonicalizing DKIM-Signature header: %w", err)
		}
		dkimSig = []byte(ch)
	}
	h.Write(dkimSig)
	return h.Sum(nil), nil
}

// a single header, can be multiline.
func relaxedCanonicalHeaderWithoutCRLF(s string) (string, error) {
	// ../rfc/6376:831
	t := strings.SplitN(s, ":", 2)
	if len(t) != 2 {
		return "", fmt.Errorf("%w: invalid header %q", ErrHeaderMalformed, s)
	}

	// Unfold, we keep the leading WSP on continuation lines and fix it up below.
	v := strings.ReplaceAll(t[1], "\r\n", "")

	// Replace one or more WSP to a single SP.
	var nv []byte
	var prev byte
	for i, c := range []byte(v) {
		if i >= 0 && c == ' ' || c == '\t' {
			if prev == ' ' {
				continue
			}
			prev = ' '
			c = ' '
		} else {
			prev = c
		}
		nv = append(nv, c)
	}

	ch := strings.ToLower(strings.TrimRight(t[0], " \t")) + ":" + strings.Trim(string(nv), " \t")
	return ch, nil
}

type header struct {
	key   string // Key in original case.
	lkey  string // Key in lower-case, for canonical case.
	value []byte // Literal header value, possibly spanning multiple lines, not modified in any way, including crlf, excluding leading key and colon.
	raw   []byte // Like value, but including original leading key and colon. Ready for use as simple header canonicalized use.
}

func parseHeaders(br *bufio.Reader) ([]header, int, error) {
	var o int
	var l []header
	var key, lkey string
	var value []byte
	var raw []byte
	for {
		line, err := readline(br)
		if err != nil {
			return nil, 0, err
		}
		o += len(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(l) == 0 && key == "" {
				return nil, 0, fmt.Errorf("malformed message, starts with space/tab")
			}
			value = append(value, line...)
			raw = append(raw, line...)
			continue
		}
		if key != "" {
			l = append(l, header{key, lkey, value, raw})
		}
		t := bytes.SplitN(line, []byte(":"), 2)
		if len(t) != 2 {
			return nil, 0, fmt.Errorf("malformed message, header without colon")
		}

		key = strings.TrimRight(string(t[0]), " \t") // todo: where is this specified?
		// Check for valid characters. ../rfc/5322:1689 ../rfc/6532:193
		for _, c := range key {
			if c <= ' ' || c >= 0x7f {
				return nil, 0, fmt.Errorf("invalid header field name")
			}
		}
		if key == "" {
			return nil, 0, fmt.Errorf("empty header key")
		}
		lkey = strings.ToLower(key)
		value = append([]byte{}, t[1]...)
		raw = append([]byte{}, line...)
	}
	if key != "" {
		l = append(l, header{key, lkey, value, raw})
	}
	return l, o, nil
}

func readline(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if bytes.HasSuffix(line, []byte("\r\n")) {
			if len(buf) == 0 {
				return line, nil
			}
			return append(buf, line...), nil
		}
		buf = append(buf, line...)
	}
}
