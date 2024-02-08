package tlsrpt

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var ErrNoReport = errors.New("no tlsrpt report found")

// ../rfc/8460:628

// Report is a TLSRPT report.
type Report struct {
	OrganizationName string
	DateRange        TLSRPTDateRange
	ContactInfo      string
	ReportID         string
	Policies         []Result
}

// ReportJSON is a TLS report with field names as used in the specification. These field names are inconvenient to use in JavaScript, so after parsing a ReportJSON is turned into a Report.
type ReportJSON struct {
	OrganizationName string              `json:"organization-name"`
	DateRange        TLSRPTDateRangeJSON `json:"date-range"`
	ContactInfo      string              `json:"contact-info"` // Email address.
	ReportID         string              `json:"report-id"`
	Policies         []ResultJSON        `json:"policies"`
}

func convertSlice[T interface{ Convert() S }, S any](l []T) []S {
	if l == nil {
		return nil
	}
	r := make([]S, len(l))
	for i, e := range l {
		r[i] = e.Convert()
	}
	return r
}

func (v Report) Convert() ReportJSON {
	return ReportJSON{v.OrganizationName, v.DateRange.Convert(), v.ContactInfo, v.ReportID, convertSlice[Result, ResultJSON](v.Policies)}
}

func (v ReportJSON) Convert() Report {
	return Report{v.OrganizationName, v.DateRange.Convert(), v.ContactInfo, v.ReportID, convertSlice[ResultJSON, Result](v.Policies)}
}

// Merge combines the counts and failure details of results into the report.
// Policies are merged if identical and added otherwise. Same for failure details
// within a result.
func (r *Report) Merge(results ...Result) {
Merge:
	for _, nr := range results {
		for i, p := range r.Policies {
			if !p.Policy.equal(nr.Policy) {
				continue
			}

			r.Policies[i].Add(nr.Summary.TotalSuccessfulSessionCount, nr.Summary.TotalFailureSessionCount, nr.FailureDetails...)
			continue Merge
		}

		r.Policies = append(r.Policies, nr)
	}
}

// Add increases the success/failure counts of a result, and adds any failure
// details.
func (r *Result) Add(success, failure int64, fds ...FailureDetails) {
	r.Summary.TotalSuccessfulSessionCount += success
	r.Summary.TotalFailureSessionCount += failure

	// In smtpclient we can compensate with a negative success, after failed read after
	// successful handshake. Sanity check that we never get negative counts.
	if r.Summary.TotalSuccessfulSessionCount < 0 {
		r.Summary.TotalSuccessfulSessionCount = 0
	}
	if r.Summary.TotalFailureSessionCount < 0 {
		r.Summary.TotalFailureSessionCount = 0
	}

Merge:
	for _, nfd := range fds {
		for i, fd := range r.FailureDetails {
			if !fd.equalKey(nfd) {
				continue
			}

			fd.FailedSessionCount += nfd.FailedSessionCount
			r.FailureDetails[i] = fd
			continue Merge
		}
		r.FailureDetails = append(r.FailureDetails, nfd)
	}
}

// Add is a convenience function for merging making a Result and merging it into
// the report.
func (r *Report) Add(policy ResultPolicy, success, failure int64, fds ...FailureDetails) {
	r.Merge(Result{policy, Summary{success, failure}, fds})
}

// TLSAPolicy returns a policy for DANE.
func TLSAPolicy(records []adns.TLSA, tlsaBaseDomain dns.Domain) ResultPolicy {
	// The policy domain is the TLSA base domain. ../rfc/8460:251

	l := make([]string, len(records))
	for i, r := range records {
		l[i] = r.Record()
	}
	sort.Strings(l) // For consistent equals.
	return ResultPolicy{
		Type:   TLSA,
		String: l,
		Domain: tlsaBaseDomain.ASCII,
		MXHost: []string{},
	}
}

func MakeResult(policyType PolicyType, domain dns.Domain, fds ...FailureDetails) Result {
	if fds == nil {
		fds = []FailureDetails{}
	}
	return Result{
		Policy:         ResultPolicy{Type: policyType, Domain: domain.ASCII, String: []string{}, MXHost: []string{}},
		FailureDetails: fds,
	}
}

// note: with TLSRPT prefix to prevent clash in sherpadoc types.
type TLSRPTDateRange struct {
	Start time.Time
	End   time.Time
}

func (v TLSRPTDateRange) Convert() TLSRPTDateRangeJSON {
	return TLSRPTDateRangeJSON(v)
}

type TLSRPTDateRangeJSON struct {
	Start time.Time `json:"start-datetime"`
	End   time.Time `json:"end-datetime"`
}

func (v TLSRPTDateRangeJSON) Convert() TLSRPTDateRange {
	return TLSRPTDateRange(v)
}

// UnmarshalJSON is defined on the date range, not the individual time.Time fields
// because it is easier to keep the unmodified time.Time fields stored in the
// database.
func (dr *TLSRPTDateRangeJSON) UnmarshalJSON(buf []byte) error {
	var v struct {
		Start xtime `json:"start-datetime"`
		End   xtime `json:"end-datetime"`
	}
	if err := json.Unmarshal(buf, &v); err != nil {
		return err
	}
	dr.Start = time.Time(v.Start)
	dr.End = time.Time(v.End)
	return nil
}

// xtime and its UnmarshalJSON exists to work around a specific invalid date-time encoding seen in the wild.
type xtime time.Time

func (x *xtime) UnmarshalJSON(buf []byte) error {
	var t time.Time
	err := t.UnmarshalJSON(buf)
	if err == nil {
		*x = xtime(t)
		return nil
	}

	// Microsoft is sending reports with invalid start-datetime/end-datetime (missing
	// timezone, ../rfc/8460:682 ../rfc/3339:415). We compensate.
	var s string
	if err := json.Unmarshal(buf, &s); err != nil {
		return err
	}
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		return err
	}
	*x = xtime(t)
	return nil
}

type Result struct {
	Policy         ResultPolicy
	Summary        Summary
	FailureDetails []FailureDetails
}

func (r Result) Convert() ResultJSON {
	return ResultJSON{ResultPolicyJSON(r.Policy), SummaryJSON(r.Summary), convertSlice[FailureDetails, FailureDetailsJSON](r.FailureDetails)}
}

type ResultJSON struct {
	Policy         ResultPolicyJSON     `json:"policy"`
	Summary        SummaryJSON          `json:"summary"`
	FailureDetails []FailureDetailsJSON `json:"failure-details"`
}

func (r ResultJSON) Convert() Result {
	return Result{ResultPolicy(r.Policy), Summary(r.Summary), convertSlice[FailureDetailsJSON, FailureDetails](r.FailureDetails)}
}

// todo spec: ../rfc/8460:437 says policy is a string, with rules for turning dane records into a single string. perhaps a remnant of an earlier version (for mtasts a single string would have made more sense). i doubt the intention is to always have a single element in policy-string (though the field name is singular).

type ResultPolicy struct {
	Type   PolicyType
	String []string
	Domain string // ASCII/A-labels, ../rfc/8460:704
	MXHost []string
}

type ResultPolicyJSON struct {
	Type   PolicyType `json:"policy-type"`
	String []string   `json:"policy-string"`
	Domain string     `json:"policy-domain"`
	MXHost []string   `json:"mx-host"` // Example in RFC has errata, it originally was a single string. ../rfc/8460-eid6241 ../rfc/8460:1779
}

// PolicyType indicates the policy success/failure results are for.
type PolicyType string

const (
	// For DANE, against a mail host (not recipient domain).
	TLSA PolicyType = "tlsa"

	// For MTA-STS, against a recipient domain (not a mail host).
	STS PolicyType = "sts"

	// Recipient domain did not have MTA-STS policy, or mail host (TSLA base domain)
	// did not have DANE TLSA records.
	NoPolicyFound PolicyType = "no-policy-found"
	// todo spec: ../rfc/8460:440 ../rfc/8460:697 suggest to replace with values like "no-sts-found" and "no-tlsa-found" to make it explicit which policy isn't found. also easier to implement, because you don't have to handle leaving out an sts no-policy-found result for a mail host when a tlsa policy is present.
)

func (rp ResultPolicy) equal(orp ResultPolicy) bool {
	return rp.Type == orp.Type && slices.Equal(rp.String, orp.String) && rp.Domain == orp.Domain && slices.Equal(rp.MXHost, orp.MXHost)
}

type Summary struct {
	TotalSuccessfulSessionCount int64
	TotalFailureSessionCount    int64
}

type SummaryJSON struct {
	TotalSuccessfulSessionCount int64 `json:"total-successful-session-count"`
	TotalFailureSessionCount    int64 `json:"total-failure-session-count"`
}

// ResultType represents a TLS error.
type ResultType string

// ../rfc/8460:1377
// https://www.iana.org/assignments/starttls-validation-result-types/starttls-validation-result-types.xhtml

const (
	ResultSTARTTLSNotSupported    ResultType = "starttls-not-supported"
	ResultCertificateHostMismatch ResultType = "certificate-host-mismatch"
	ResultCertificateExpired      ResultType = "certificate-expired"
	ResultTLSAInvalid             ResultType = "tlsa-invalid"
	ResultDNSSECInvalid           ResultType = "dnssec-invalid"
	ResultDANERequired            ResultType = "dane-required"
	ResultCertificateNotTrusted   ResultType = "certificate-not-trusted"
	ResultSTSPolicyInvalid        ResultType = "sts-policy-invalid"
	ResultSTSWebPKIInvalid        ResultType = "sts-webpki-invalid"
	ResultValidationFailure       ResultType = "validation-failure" // Other error.
	ResultSTSPolicyFetch          ResultType = "sts-policy-fetch-error"
)

// todo spec: ../rfc/8460:719 more of these fields should be optional. some sts failure details, like failed policy fetches, won't have an ip or mx, the failure happens earlier in the delivery process.

type FailureDetails struct {
	ResultType            ResultType
	SendingMTAIP          string
	ReceivingMXHostname   string
	ReceivingMXHelo       string
	ReceivingIP           string
	FailedSessionCount    int64
	AdditionalInformation string
	FailureReasonCode     string
}

func (v FailureDetails) Convert() FailureDetailsJSON { return FailureDetailsJSON(v) }

type FailureDetailsJSON struct {
	ResultType            ResultType `json:"result-type"`
	SendingMTAIP          string     `json:"sending-mta-ip"`
	ReceivingMXHostname   string     `json:"receiving-mx-hostname"`
	ReceivingMXHelo       string     `json:"receiving-mx-helo,omitempty"`
	ReceivingIP           string     `json:"receiving-ip"`
	FailedSessionCount    int64      `json:"failed-session-count"`
	AdditionalInformation string     `json:"additional-information"`
	FailureReasonCode     string     `json:"failure-reason-code"`
}

func (v FailureDetailsJSON) Convert() FailureDetails { return FailureDetails(v) }

// equalKey returns whether FailureDetails have the same values, expect for
// FailedSessionCount. Useful for aggregating FailureDetails.
func (fd FailureDetails) equalKey(ofd FailureDetails) bool {
	fd.FailedSessionCount = 0
	ofd.FailedSessionCount = 0
	return fd == ofd
}

// Details is a convenience function to compose a FailureDetails.
func Details(t ResultType, r string) FailureDetails {
	return FailureDetails{ResultType: t, FailedSessionCount: 1, FailureReasonCode: r}
}

var invalidReasons = map[x509.InvalidReason]string{
	x509.NotAuthorizedToSign:           "not-authorized-to-sign",
	x509.Expired:                       "certificate-expired",
	x509.CANotAuthorizedForThisName:    "ca-not-authorized-for-this-name",
	x509.TooManyIntermediates:          "too-many-intermediates",
	x509.IncompatibleUsage:             "incompatible-key-usage",
	x509.NameMismatch:                  "parent-subject-child-issuer-mismatch",
	x509.NameConstraintsWithoutSANs:    "name-constraint-without-sans",
	x509.UnconstrainedName:             "unconstrained-name",
	x509.TooManyConstraints:            "too-many-constraints",
	x509.CANotAuthorizedForExtKeyUsage: "ca-not-authorized-for-ext-key-usage",
}

// TLSFailureDetails turns errors encountered during TLS handshakes into a result
// type and failure reason code for use with FailureDetails.
//
// Errors from crypto/tls, including local and remote alerts, from crypto/x509,
// and generic i/o and timeout errors are recognized.
func TLSFailureDetails(err error) (ResultType, string) {
	var invalidErr x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var unknownAuthErr x509.UnknownAuthorityError
	var rootsErr x509.SystemRootsError
	var verifyErr *tls.CertificateVerificationError
	var netErr *net.OpError
	var recordHdrErr tls.RecordHeaderError
	if errors.As(err, &invalidErr) {
		if invalidErr.Reason == x509.Expired {
			// Result: ../rfc/8460:546
			return ResultCertificateExpired, ""
		}
		s, ok := invalidReasons[invalidErr.Reason]
		if !ok {
			s = fmt.Sprintf("go-x509-invalid-reason-%d", invalidErr.Reason)
		}
		// Result: ../rfc/8460:549
		return ResultCertificateNotTrusted, s
	} else if errors.As(err, &hostErr) {
		// Result: ../rfc/8460:541
		return ResultCertificateHostMismatch, ""
	} else if errors.As(err, &unknownAuthErr) {
		// Result: ../rfc/8460:549
		return ResultCertificateNotTrusted, ""
	} else if errors.As(err, &rootsErr) {
		// Result: ../rfc/8460:549
		return ResultCertificateNotTrusted, "no-system-roots"
	} else if errors.As(err, &verifyErr) {
		// We don't know a more specific error. ../rfc/8460:610
		// Result: ../rfc/8460:567
		return ResultValidationFailure, "unknown-go-certificate-verification-error"
	} else if errors.As(err, &netErr) && netErr.Op == "remote error" {
		// This is how TLS errors from the server (through an alert) are represented by
		// crypto/tls. Err will usually be tls.alert error that is a type around uint8.
		reasonCode := "tls-remote-error"
		if netErr.Err != nil {
			// todo: ideally, crypto/tls would let us check if this is an alert. it could be another uint8-typed error.
			v := reflect.ValueOf(netErr.Err)
			if v.Kind() == reflect.Uint8 && v.Type().Name() == "alert" {
				reasonCode = "tls-remote-" + formatAlert(uint8(v.Uint()))
			}
		}
		return ResultValidationFailure, reasonCode
	} else if errors.As(err, &recordHdrErr) {
		// Like for AlertError, not a lot of details, but better than nothing.
		// Result: ../rfc/8460:567
		return ResultValidationFailure, "tls-record-header-error"
	}

	// Consider not adding failure details at all for transient errors? It probably
	// isn't very common to have an accidental connection failure during STARTTL setup
	// after having completed SMTP TCP setup and having exchanged commands. Seems best
	// to report on them. ../rfc/8460:625
	// Could be any other kind of error, we try to report on i/o errors, but best not to claim any
	// other reason we don't know about. ../rfc/8460:610
	// Result: ../rfc/8460:567
	var reasonCode string
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		reasonCode = "io-timeout-during-handshake"
	} else if moxio.IsClosed(err) || errors.Is(err, io.ErrClosedPipe) {
		reasonCode = "connection-closed-during-handshake"
	} else {
		// Attempt to get a local, outgoing TLS alert.
		// We unwrap the error to the end (not multiple errors), and check for uint8 of a
		// type named "alert".
		for {
			uerr := errors.Unwrap(err)
			if uerr == nil {
				break
			}
			err = uerr
		}
		v := reflect.ValueOf(err)
		if v.Kind() == reflect.Uint8 && v.Type().Name() == "alert" {
			reasonCode = "tls-local-" + formatAlert(uint8(v.Uint()))
		}
	}
	return ResultValidationFailure, reasonCode
}

// Parse parses a Report.
// The maximum size is 20MB.
func Parse(r io.Reader) (*ReportJSON, error) {
	r = &moxio.LimitReader{R: r, Limit: 20 * 1024 * 1024}
	var report ReportJSON
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}
	// note: there may be leftover data, we ignore it.
	return &report, nil
}

// ParseMessage parses a Report from a mail message.
// The maximum size of the message is 15MB, the maximum size of the
// decompressed report is 20MB.
func ParseMessage(elog *slog.Logger, r io.ReaderAt) (*ReportJSON, error) {
	log := mlog.New("tlsrpt", elog)

	// ../rfc/8460:905
	p, err := message.Parse(log.Logger, true, &moxio.LimitAtReader{R: r, Limit: 15 * 1024 * 1024})
	if err != nil {
		return nil, fmt.Errorf("parsing mail message: %s", err)
	}

	// Using multipart appears optional, and similar to DMARC someone may decide to
	// send it like that, so accept a report if it's the entire message.
	const allow = true
	return parseMessageReport(log, p, allow)
}

func parseMessageReport(log mlog.Log, p message.Part, allow bool) (*ReportJSON, error) {
	if p.MediaType != "MULTIPART" {
		if !allow {
			return nil, ErrNoReport
		}
		return parseReport(p)
	}

	for {
		sp, err := p.ParseNextPart(log.Logger)
		if err == io.EOF {
			return nil, ErrNoReport
		}
		if err != nil {
			return nil, err
		}
		if p.MediaSubType == "REPORT" && p.ContentTypeParams["report-type"] != "tlsrpt" {
			return nil, fmt.Errorf("unknown report-type parameter %q", p.ContentTypeParams["report-type"])
		}
		report, err := parseMessageReport(log, *sp, p.MediaSubType == "REPORT")
		if err == ErrNoReport {
			continue
		} else if err != nil || report != nil {
			return report, err
		}
	}
}

func parseReport(p message.Part) (*ReportJSON, error) {
	mt := strings.ToLower(p.MediaType + "/" + p.MediaSubType)
	switch mt {
	case "application/tlsrpt+json":
		return Parse(p.Reader())
	case "application/tlsrpt+gzip":
		gzr, err := gzip.NewReader(p.Reader())
		if err != nil {
			return nil, fmt.Errorf("decoding gzip TLSRPT report: %s", err)
		}
		return Parse(gzr)
	}
	return nil, ErrNoReport
}
