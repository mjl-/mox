// Package dmarc implements DMARC (Domain-based Message Authentication,
// Reporting, and Conformance; RFC 7489) verification.
//
// DMARC is a mechanism for verifying ("authenticating") the address in the "From"
// message header, since users will look at that header to identify the sender of a
// message. DMARC compares the "From"-(sub)domain against the SPF and/or
// DKIM-validated domains, based on the DMARC policy that a domain has published in
// DNS as TXT record under "_dmarc.<domain>". A DMARC policy can also ask for
// feedback about evaluations by other email servers, for monitoring/debugging
// problems with email delivery.
package dmarc

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/stub"

	"golang.org/x/exp/slog"
)

var (
	MetricVerify stub.HistogramVec = stub.HistogramVecIgnore{}
)

// link errata:
// ../rfc/7489-eid5440 ../rfc/7489:1585

// Lookup errors.
var (
	ErrNoRecord        = errors.New("dmarc: no dmarc dns record")
	ErrMultipleRecords = errors.New("dmarc: multiple dmarc dns records") // Must also be treated as if domain does not implement DMARC.
	ErrDNS             = errors.New("dmarc: dns lookup")
	ErrSyntax          = errors.New("dmarc: malformed dmarc dns record")
)

// Status is the result of DMARC policy evaluation, for use in an Authentication-Results header.
type Status string

// ../rfc/7489:2339

const (
	StatusNone      Status = "none"      // No DMARC TXT DNS record found.
	StatusPass      Status = "pass"      // SPF and/or DKIM pass with identifier alignment.
	StatusFail      Status = "fail"      // Either both SPF and DKIM failed or identifier did not align with a pass.
	StatusTemperror Status = "temperror" // Typically a DNS lookup. A later attempt may results in a conclusion.
	StatusPermerror Status = "permerror" // Typically a malformed DMARC DNS record.
)

// Result is a DMARC policy evaluation.
type Result struct {
	// Whether to reject the message based on policies. If false, the message should
	// not necessarily be accepted: other checks such as reputation-based and
	// content-based analysis may lead to reject the message.
	Reject bool
	// Result of DMARC validation. A message can fail validation, but still
	// not be rejected, e.g. if the policy is "none".
	Status          Status
	AlignedSPFPass  bool
	AlignedDKIMPass bool
	// Domain with the DMARC DNS record. May be the organizational domain instead of
	// the domain in the From-header.
	Domain dns.Domain
	// Parsed DMARC record.
	Record *Record
	// Whether DMARC DNS response was DNSSEC-signed, regardless of whether SPF/DKIM records were DNSSEC-signed.
	RecordAuthentic bool
	// Details about possible error condition, e.g. when parsing the DMARC record failed.
	Err error
}

// Lookup looks up the DMARC TXT record at "_dmarc.<domain>" for the domain in the
// "From"-header of a message.
//
// If no DMARC record is found for the "From"-domain, another lookup is done at
// the organizational domain of the domain (if different). The organizational
// domain is determined using the public suffix list. E.g. for
// "sub.example.com", the organizational domain is "example.com". The returned
// domain is the domain with the DMARC record.
//
// rauthentic indicates if the DNS results were DNSSEC-verified.
func Lookup(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, msgFrom dns.Domain) (status Status, domain dns.Domain, record *Record, txt string, rauthentic bool, rerr error) {
	log := mlog.New("dmarc", elog)
	start := time.Now()
	defer func() {
		log.Debugx("dmarc lookup result", rerr,
			slog.Any("fromdomain", msgFrom),
			slog.Any("status", status),
			slog.Any("domain", domain),
			slog.Any("record", record),
			slog.Duration("duration", time.Since(start)))
	}()

	// ../rfc/7489:859 ../rfc/7489:1370
	domain = msgFrom
	status, record, txt, authentic, err := lookupRecord(ctx, resolver, domain)
	if status != StatusNone {
		return status, domain, record, txt, authentic, err
	}
	if record == nil {
		// ../rfc/7489:761 ../rfc/7489:1377
		domain = publicsuffix.Lookup(ctx, log.Logger, msgFrom)
		if domain == msgFrom {
			return StatusNone, domain, nil, txt, authentic, err
		}

		var xauth bool
		status, record, txt, xauth, err = lookupRecord(ctx, resolver, domain)
		authentic = authentic && xauth
	}
	return status, domain, record, txt, authentic, err
}

func lookupRecord(ctx context.Context, resolver dns.Resolver, domain dns.Domain) (Status, *Record, string, bool, error) {
	name := "_dmarc." + domain.ASCII + "."
	txts, result, err := dns.WithPackage(resolver, "dmarc").LookupTXT(ctx, name)
	if err != nil && !dns.IsNotFound(err) {
		return StatusTemperror, nil, "", result.Authentic, fmt.Errorf("%w: %s", ErrDNS, err)
	}
	var record *Record
	var text string
	var rerr error = ErrNoRecord
	for _, txt := range txts {
		r, isdmarc, err := ParseRecord(txt)
		if !isdmarc {
			// ../rfc/7489:1374
			continue
		} else if err != nil {
			return StatusPermerror, nil, text, result.Authentic, fmt.Errorf("%w: %s", ErrSyntax, err)
		}
		if record != nil {
			// ../rfc/7489:1388
			return StatusNone, nil, "", result.Authentic, ErrMultipleRecords
		}
		text = txt
		record = r
		rerr = nil
	}
	return StatusNone, record, text, result.Authentic, rerr
}

func lookupReportsRecord(ctx context.Context, resolver dns.Resolver, dmarcDomain, extDestDomain dns.Domain) (Status, []*Record, []string, bool, error) {
	// ../rfc/7489:1566
	name := dmarcDomain.ASCII + "._report._dmarc." + extDestDomain.ASCII + "."
	txts, result, err := dns.WithPackage(resolver, "dmarc").LookupTXT(ctx, name)
	if err != nil && !dns.IsNotFound(err) {
		return StatusTemperror, nil, nil, result.Authentic, fmt.Errorf("%w: %s", ErrDNS, err)
	}
	var records []*Record
	var texts []string
	var rerr error = ErrNoRecord
	for _, txt := range txts {
		r, isdmarc, err := ParseRecordNoRequired(txt)
		// Examples in the RFC use "v=DMARC1", even though it isn't a valid DMARC record.
		// Accept the specific example.
		// ../rfc/7489-eid5440
		if !isdmarc && txt == "v=DMARC1" {
			xr := DefaultRecord
			r, isdmarc, err = &xr, true, nil
		}
		if !isdmarc {
			// ../rfc/7489:1586
			continue
		}
		texts = append(texts, txt)
		records = append(records, r)
		if err != nil {
			return StatusPermerror, records, texts, result.Authentic, fmt.Errorf("%w: %s", ErrSyntax, err)
		}
		// Multiple records are allowed for the _report record, unlike for policies. ../rfc/7489:1593
		rerr = nil
	}
	return StatusNone, records, texts, result.Authentic, rerr
}

// LookupExternalReportsAccepted returns whether the extDestDomain has opted in
// to receiving dmarc reports for dmarcDomain (where the dmarc record was found),
// through a "._report._dmarc." DNS TXT DMARC record.
//
// accepts is true if the external domain has opted in.
// If a temporary error occurred, the returned status is StatusTemperror, and a
// later retry may give an authoritative result.
// The returned error is ErrNoRecord if no opt-in DNS record exists, which is
// not a failure condition.
//
// The normally invalid "v=DMARC1" record is accepted since it is used as
// example in RFC 7489.
//
// authentic indicates if the DNS results were DNSSEC-verified.
func LookupExternalReportsAccepted(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, dmarcDomain dns.Domain, extDestDomain dns.Domain) (accepts bool, status Status, records []*Record, txts []string, authentic bool, rerr error) {
	log := mlog.New("dmarc", elog)
	start := time.Now()
	defer func() {
		log.Debugx("dmarc externalreports result", rerr,
			slog.Bool("accepts", accepts),
			slog.Any("dmarcdomain", dmarcDomain),
			slog.Any("extdestdomain", extDestDomain),
			slog.Any("records", records),
			slog.Duration("duration", time.Since(start)))
	}()

	status, records, txts, authentic, rerr = lookupReportsRecord(ctx, resolver, dmarcDomain, extDestDomain)
	accepts = rerr == nil
	return accepts, status, records, txts, authentic, rerr
}

// Verify evaluates the DMARC policy for the domain in the From-header of a
// message given the DKIM and SPF evaluation results.
//
// applyRandomPercentage determines whether the records "pct" is honored. This
// field specifies the percentage of messages the DMARC policy is applied to. It
// is used for slow rollout of DMARC policies and should be honored during normal
// email processing
//
// Verify always returns the result of verifying the DMARC policy
// against the message (for inclusion in Authentication-Result headers).
//
// useResult indicates if the result should be applied in a policy decision,
// based on the "pct" field in the DMARC record.
func Verify(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, msgFrom dns.Domain, dkimResults []dkim.Result, spfResult spf.Status, spfIdentity *dns.Domain, applyRandomPercentage bool) (useResult bool, result Result) {
	log := mlog.New("dmarc", elog)
	start := time.Now()
	defer func() {
		use := "no"
		if useResult {
			use = "yes"
		}
		reject := "no"
		if result.Reject {
			reject = "yes"
		}
		MetricVerify.ObserveLabels(float64(time.Since(start))/float64(time.Second), string(result.Status), reject, use)
		log.Debugx("dmarc verify result", result.Err,
			slog.Any("fromdomain", msgFrom),
			slog.Any("dkimresults", dkimResults),
			slog.Any("spfresult", spfResult),
			slog.Any("status", result.Status),
			slog.Bool("reject", result.Reject),
			slog.Bool("use", useResult),
			slog.Duration("duration", time.Since(start)))
	}()

	status, recordDomain, record, _, authentic, err := Lookup(ctx, log.Logger, resolver, msgFrom)
	if record == nil {
		return false, Result{false, status, false, false, recordDomain, record, authentic, err}
	}
	result.Domain = recordDomain
	result.Record = record
	result.RecordAuthentic = authentic

	// Record can request sampling of messages to apply policy.
	// See ../rfc/7489:1432
	useResult = !applyRandomPercentage || record.Percentage == 100 || mathrand.Intn(100) < record.Percentage

	// We treat "quarantine" and "reject" the same. Thus, we also don't "downgrade"
	// from reject to quarantine if this message was sampled out.
	// ../rfc/7489:1446 ../rfc/7489:1024
	if recordDomain != msgFrom && record.SubdomainPolicy != PolicyEmpty {
		result.Reject = record.SubdomainPolicy != PolicyNone
	} else {
		result.Reject = record.Policy != PolicyNone
	}

	// ../rfc/7489:1338
	result.Status = StatusFail
	if spfResult == spf.StatusTemperror {
		result.Status = StatusTemperror
		result.Reject = false
	}

	// Below we can do a bunch of publicsuffix lookups. Cache the results, mostly to
	// reduce log pollution.
	pubsuffixes := map[dns.Domain]dns.Domain{}
	pubsuffix := func(name dns.Domain) dns.Domain {
		if r, ok := pubsuffixes[name]; ok {
			return r
		}
		r := publicsuffix.Lookup(ctx, log.Logger, name)
		pubsuffixes[name] = r
		return r
	}

	// ../rfc/7489:1319
	// ../rfc/7489:544
	if spfResult == spf.StatusPass && spfIdentity != nil && (*spfIdentity == msgFrom || result.Record.ASPF == "r" && pubsuffix(msgFrom) == pubsuffix(*spfIdentity)) {
		result.AlignedSPFPass = true
	}

	for _, dkimResult := range dkimResults {
		if dkimResult.Status == dkim.StatusTemperror {
			result.Reject = false
			result.Status = StatusTemperror
			continue
		}
		// ../rfc/7489:511
		if dkimResult.Status == dkim.StatusPass && dkimResult.Sig != nil && (dkimResult.Sig.Domain == msgFrom || result.Record.ADKIM == "r" && pubsuffix(msgFrom) == pubsuffix(dkimResult.Sig.Domain)) {
			// ../rfc/7489:535
			result.AlignedDKIMPass = true
			break
		}
	}

	if result.AlignedSPFPass || result.AlignedDKIMPass {
		result.Reject = false
		result.Status = StatusPass
	}
	return
}
