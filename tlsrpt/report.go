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
func ParseMessage(r io.ReaderAt) (*Report, error) {
	// ../rfc/8460:905
	p, err := message.Parse(&moxio.LimitAtReader{R: r, Limit: 15 * 1024 * 1024})
	if err != nil {
		return nil, fmt.Errorf("parsing mail message: %s", err)
	}

	// Using multipart appears optional, and similar to DMARC someone may decide to
	// send it like that, so accept a report if it's the entire message.
	const allow = true
	return parseMessageReport(p, allow)
}

func parseMessageReport(p message.Part, allow bool) (*Report, error) {
	if p.MediaType != "MULTIPART" {
		if !allow {
			return nil, ErrNoReport
		}
		return parseReport(p)
	}

	for {
		sp, err := p.ParseNextPart()
		if err == io.EOF {
			return nil, ErrNoReport
		}
		if err != nil {
			return nil, err
		}
		if p.MediaSubType == "REPORT" && p.ContentTypeParams["report-type"] != "tlsrpt" {
			return nil, fmt.Errorf("unknown report-type parameter %q", p.ContentTypeParams["report-type"])
		}
		report, err := parseMessageReport(*sp, p.MediaSubType == "REPORT")
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
