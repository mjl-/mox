package dmarc

import (
	"fmt"
	"strings"
)

// todo: DMARCPolicy should be named just Policy, but this is causing conflicting types in sherpadoc output. should somehow get the dmarc-prefix only in the sherpadoc.

// Policy as used in DMARC DNS record for "p=" or "sp=".
type DMARCPolicy string

// ../rfc/7489:1157

const (
	PolicyEmpty      DMARCPolicy = "" // Only for the optional Record.SubdomainPolicy.
	PolicyNone       DMARCPolicy = "none"
	PolicyQuarantine DMARCPolicy = "quarantine"
	PolicyReject     DMARCPolicy = "reject"
)

// URI is a destination address for reporting.
type URI struct {
	Address string // Should start with "mailto:".
	MaxSize uint64 // Optional maximum message size, subject to Unit.
	Unit    string // "" (b), "k", "m", "g", "t" (case insensitive), unit size, where k is 2^10 etc.
}

// String returns a string representation of the URI for inclusion in a DMARC
// record.
func (u URI) String() string {
	s := u.Address
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, "!", "%21")
	if u.MaxSize > 0 {
		s += fmt.Sprintf("!%d", u.MaxSize)
	}
	s += u.Unit
	return s
}

// ../rfc/7489:1127

// Align specifies the required alignment of a domain name.
type Align string

const (
	AlignStrict  Align = "s" // Strict requires an exact domain name match.
	AlignRelaxed Align = "r" // Relaxed requires either an exact or subdomain name match.
)

// Record is a DNS policy or reporting record.
//
// Example:
//
//	v=DMARC1; p=reject; rua=mailto:postmaster@mox.example
type Record struct {
	Version                    string      // "v=DMARC1"
	Policy                     DMARCPolicy // Required, for "p=".
	SubdomainPolicy            DMARCPolicy // Like policy but for subdomains. Optional, for "sp=".
	AggregateReportAddresses   []URI       // Optional, for "rua=".
	FailureReportAddresses     []URI       // Optional, for "ruf="
	ADKIM                      Align       // "r" (default) for relaxed or "s" for simple. For "adkim=".
	ASPF                       Align       // "r" (default) for relaxed or "s" for simple. For "aspf=".
	AggregateReportingInterval int         // Default 86400. For "ri="
	FailureReportingOptions    []string    // "0" (default), "1", "d", "s". For "fo=".
	ReportingFormat            []string    // "afrf" (default). Ffor "rf=".
	Percentage                 int         // Between 0 and 100, default 100. For "pct=".
}

// DefaultRecord holds the defaults for a DMARC record.
var DefaultRecord = Record{
	Version:                    "DMARC1",
	ADKIM:                      "r",
	ASPF:                       "r",
	AggregateReportingInterval: 86400,
	FailureReportingOptions:    []string{"0"},
	ReportingFormat:            []string{"afrf"},
	Percentage:                 100,
}

// String returns the DMARC record for use as DNS TXT record.
func (r Record) String() string {
	b := &strings.Builder{}
	b.WriteString("v=" + r.Version)

	wrote := false
	write := func(do bool, tag, value string) {
		if do {
			fmt.Fprintf(b, ";%s=%s", tag, value)
			wrote = true
		}
	}
	write(r.Policy != "", "p", string(r.Policy))
	write(r.SubdomainPolicy != "", "sp", string(r.SubdomainPolicy))
	if len(r.AggregateReportAddresses) > 0 {
		l := make([]string, len(r.AggregateReportAddresses))
		for i, a := range r.AggregateReportAddresses {
			l[i] = a.String()
		}
		s := strings.Join(l, ",")
		write(true, "rua", s)
	}
	if len(r.FailureReportAddresses) > 0 {
		l := make([]string, len(r.FailureReportAddresses))
		for i, a := range r.FailureReportAddresses {
			l[i] = a.String()
		}
		s := strings.Join(l, ",")
		write(true, "ruf", s)
	}
	write(r.ADKIM != "" && r.ADKIM != "r", "adkim", string(r.ADKIM))
	write(r.ASPF != "" && r.ASPF != "r", "aspf", string(r.ASPF))
	write(r.AggregateReportingInterval != DefaultRecord.AggregateReportingInterval, "ri", fmt.Sprintf("%d", r.AggregateReportingInterval))
	if len(r.FailureReportingOptions) > 1 || len(r.FailureReportingOptions) == 1 && r.FailureReportingOptions[0] != "0" {
		write(true, "fo", strings.Join(r.FailureReportingOptions, ":"))
	}
	if len(r.ReportingFormat) > 1 || len(r.ReportingFormat) == 1 && !strings.EqualFold(r.ReportingFormat[0], "afrf") {
		write(true, "rf", strings.Join(r.FailureReportingOptions, ":"))
	}
	write(r.Percentage != 100, "pct", fmt.Sprintf("%d", r.Percentage))

	if !wrote {
		b.WriteString(";")
	}
	return b.String()
}
