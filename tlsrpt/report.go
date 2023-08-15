package tlsrpt

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var ErrNoReport = errors.New("no tlsrpt report found")

// ../rfc/8460:628

// Report is a TLSRPT report, transmitted in JSON format.
type Report struct {
	OrganizationName string          `json:"organization-name"`
	DateRange        TLSRPTDateRange `json:"date-range"`
	ContactInfo      string          `json:"contact-info"` // Email address.
	ReportID         string          `json:"report-id"`
	Policies         []Result        `json:"policies"`
}

// note: with TLSRPT prefix to prevent clash in sherpadoc types.
type TLSRPTDateRange struct {
	Start time.Time `json:"start-datetime"`
	End   time.Time `json:"end-datetime"`
}

// UnmarshalJSON is defined on the date range, not the individual time.Time fields
// because it is easier to keep the unmodified time.Time fields stored in the
// database.
func (dr *TLSRPTDateRange) UnmarshalJSON(buf []byte) error {
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
	Policy         ResultPolicy     `json:"policy"`
	Summary        Summary          `json:"summary"`
	FailureDetails []FailureDetails `json:"failure-details"`
}

type ResultPolicy struct {
	Type   string   `json:"policy-type"`
	String []string `json:"policy-string"`
	Domain string   `json:"policy-domain"`
	MXHost []string `json:"mx-host"` // Example in RFC has errata, it originally was a single string. ../rfc/8460-eid6241 ../rfc/8460:1779
}

type Summary struct {
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

type FailureDetails struct {
	ResultType            ResultType `json:"result-type"`
	SendingMTAIP          string     `json:"sending-mta-ip"`
	ReceivingMXHostname   string     `json:"receiving-mx-hostname"`
	ReceivingMXHelo       string     `json:"receiving-mx-helo"`
	ReceivingIP           string     `json:"receiving-ip"`
	FailedSessionCount    int64      `json:"failed-session-count"`
	AdditionalInformation string     `json:"additional-information"`
	FailureReasonCode     string     `json:"failure-reason-code"`
}

// Parse parses a Report.
// The maximum size is 20MB.
func Parse(r io.Reader) (*Report, error) {
	r = &moxio.LimitReader{R: r, Limit: 20 * 1024 * 1024}
	var report Report
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}
	// note: there may be leftover data, we ignore it.
	return &report, nil
}

// ParseMessage parses a Report from a mail message.
// The maximum size of the message is 15MB, the maximum size of the
// decompressed report is 20MB.
func ParseMessage(log *mlog.Log, r io.ReaderAt) (*Report, error) {
	// ../rfc/8460:905
	p, err := message.Parse(log, true, &moxio.LimitAtReader{R: r, Limit: 15 * 1024 * 1024})
	if err != nil {
		return nil, fmt.Errorf("parsing mail message: %s", err)
	}

	// Using multipart appears optional, and similar to DMARC someone may decide to
	// send it like that, so accept a report if it's the entire message.
	const allow = true
	return parseMessageReport(log, p, allow)
}

func parseMessageReport(log *mlog.Log, p message.Part, allow bool) (*Report, error) {
	if p.MediaType != "MULTIPART" {
		if !allow {
			return nil, ErrNoReport
		}
		return parseReport(p)
	}

	for {
		sp, err := p.ParseNextPart(log)
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

func parseReport(p message.Part) (*Report, error) {
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
