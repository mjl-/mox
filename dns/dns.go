// Package dns helps parse internationalized domain names (IDNA), canonicalize
// names and provides a strict and metrics-keeping logging DNS resolver.
package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

var errTrailingDot = errors.New("dns name has trailing dot")

// Domain is a domain name, with one or more labels, with at least an ASCII
// representation, and for IDNA non-ASCII domains a unicode representation.
// The ASCII string must be used for DNS lookups.
type Domain struct {
	// A non-unicode domain, e.g. with A-labels (xn--...) or NR-LDH (non-reserved
	// letters/digits/hyphens) labels. Always in lower case.
	ASCII string

	// Name as U-labels. Empty if this is an ASCII-only domain.
	Unicode string
}

// Name returns the unicode name if set, otherwise the ASCII name.
func (d Domain) Name() string {
	if d.Unicode != "" {
		return d.Unicode
	}
	return d.ASCII
}

// XName is like Name, but only returns a unicode name when utf8 is true.
func (d Domain) XName(utf8 bool) string {
	if utf8 && d.Unicode != "" {
		return d.Unicode
	}
	return d.ASCII
}

// ASCIIExtra returns the ASCII version of the domain name if smtputf8 is true and
// this is a unicode domain name. Otherwise it returns an empty string.
//
// This function is used to add the punycode name in a comment to SMTP message
// headers, e.g. Received and Authentication-Results.
func (d Domain) ASCIIExtra(smtputf8 bool) string {
	if smtputf8 && d.Unicode != "" {
		return d.ASCII
	}
	return ""
}

// Strings returns a human-readable string.
// For IDNA names, the string contains both the unicode and ASCII name.
func (d Domain) String() string {
	return d.LogString()
}

// LogString returns a domain for logging.
// For IDNA names, the string contains both the unicode and ASCII name.
func (d Domain) LogString() string {
	if d.Unicode == "" {
		return d.ASCII
	}
	return d.Unicode + "/" + d.ASCII
}

// IsZero returns if this is an empty Domain.
func (d Domain) IsZero() bool {
	return d == Domain{}
}

// ParseDomain parses a domain name that can consist of ASCII-only labels or U
// labels (unicode).
// Names are IDN-canonicalized and lower-cased.
// Characters in unicode can be replaced by equivalents. E.g. "Ⓡ" to "r". This
// means you should only compare parsed domain names, never strings directly.
func ParseDomain(s string) (Domain, error) {
	if strings.HasSuffix(s, ".") {
		return Domain{}, errTrailingDot
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return Domain{}, fmt.Errorf("to ascii: %w", err)
	}
	unicode, err := idna.Lookup.ToUnicode(s)
	if err != nil {
		return Domain{}, fmt.Errorf("to unicode: %w", err)
	}
	// todo: should we cause errors for unicode domains that were not in
	// canonical form? we are now accepting all kinds of obscure spellings
	// for even a basic ASCII domain name.
	// Also see https://daniel.haxx.se/blog/2022/12/14/idn-is-crazy/
	if ascii == unicode {
		return Domain{ascii, ""}, nil
	}
	return Domain{ascii, unicode}, nil
}

// IsNotFound returns whether an error is a net.DNSError with IsNotFound set.
// IsNotFound means the requested type does not exist for the given domain (a
// nodata or nxdomain response). It doesn't not necessarily mean no other types
// for that name exist.
//
// A DNS server can respond to a lookup with an error "nxdomain" to indicate a
// name does not exist (at all), or with a success status with an empty list.
// The Go resolver returns an IsNotFound error for both cases, there is no need
// to explicitly check for zero entries.
func IsNotFound(err error) bool {
	var dnsErr *net.DNSError
	return err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
