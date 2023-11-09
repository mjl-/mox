package adns

import (
	"fmt"
)

// ExtendedError is an RFC 8914 Extended DNS Error (EDE).
type ExtendedError struct {
	InfoCode  ErrorCode
	ExtraText string // Human-readable error message, optional.
}

// IsTemporary indicates whether an error is a temporary server error, and
// retries might give a different result.
func (e ExtendedError) IsTemporary() bool {
	return e.InfoCode.IsTemporary()
}

// Unwrap returns the underlying ErrorCode error.
func (e ExtendedError) Unwrap() error {
	return e.InfoCode
}

// Error returns a string representing the InfoCode, and either the extra text or
// more details for the info code.
func (e ExtendedError) Error() string {
	s := e.InfoCode.Error()
	if e.ExtraText != "" {
		return s + ": " + e.ExtraText
	}
	if int(e.InfoCode) >= len(errorCodeDetails) {
		return s
	}
	return s + ": " + errorCodeDetails[e.InfoCode]
}

// ErrorCode is an InfoCode from Extended DNS Errors, RFC 8914.
type ErrorCode uint16

const (
	ErrOtherErrorCode             ErrorCode = 0
	ErrUnsupportedDNSKEYAlgorithm ErrorCode = 1
	ErrUnsupportedDSDigestType    ErrorCode = 2
	ErrStaleAnswer                ErrorCode = 3
	ErrForgedAnswer               ErrorCode = 4
	ErrDNSSECIndeterminate        ErrorCode = 5
	ErrDNSSECBogus                ErrorCode = 6
	ErrSignatureExpired           ErrorCode = 7
	ErrSignatureNotYetValid       ErrorCode = 8
	ErrDNSKEYMissing              ErrorCode = 9
	ErrRRSIGMissing               ErrorCode = 10
	ErrNoZoneKeyBitSet            ErrorCode = 11
	ErrNSECMissing                ErrorCode = 12
	ErrCachedError                ErrorCode = 13
	ErrNotReady                   ErrorCode = 14
	ErrBlocked                    ErrorCode = 15
	ErrCensored                   ErrorCode = 16
	ErrFiltered                   ErrorCode = 17
	ErrProhibited                 ErrorCode = 18
	ErrStaleNXDOMAINAnswer        ErrorCode = 19
	ErrNotAuthoritative           ErrorCode = 20
	ErrNotSupported               ErrorCode = 21
	ErrNoReachableAuthority       ErrorCode = 22
	ErrNetworkError               ErrorCode = 23
	ErrInvalidData                ErrorCode = 24
)

// IsTemporary returns whether the error is temporary and has a chance of
// succeeding on a retry.
func (e ErrorCode) IsTemporary() bool {
	switch e {
	case ErrOtherErrorCode,
		ErrStaleAnswer,
		ErrCachedError,
		ErrNotReady,
		ErrStaleNXDOMAINAnswer,
		ErrNoReachableAuthority,
		ErrNetworkError:
		return true
	}
	return false
}

// IsAuthentication returns whether the error is related to authentication,
// e.g. bogus DNSSEC, missing DS/DNSKEY/RRSIG records, etc, or an other
// DNSSEC-related error.
func (e ErrorCode) IsAuthentication() bool {
	switch e {
	case ErrUnsupportedDNSKEYAlgorithm,
		ErrUnsupportedDSDigestType,
		ErrDNSSECIndeterminate,
		ErrDNSSECBogus,
		ErrSignatureExpired,
		ErrSignatureNotYetValid,
		ErrDNSKEYMissing,
		ErrRRSIGMissing,
		ErrNoZoneKeyBitSet,
		ErrNSECMissing:
		return true
	}
	return false
}

// Error includes a human-readable short string for the info code.
func (e ErrorCode) Error() string {
	if int(e) >= len(errorCodeStrings) {
		return fmt.Sprintf("unknown error code from name server: %d", e)
	}
	return fmt.Sprintf("error from name server: %s", errorCodeStrings[e])
}

// String returns a short text string for known error codes, or "unknown".
func (e ErrorCode) String() string {
	if int(e) >= 0 && int(e) < len(errorCodeStrings) {
		return errorCodeStrings[e]
	}
	return "unknown"
}

// short strings, always included in error messages.
var errorCodeStrings = []string{
	"other",
	"unsupported dnskey algorithm",
	"unsupported ds digest type",
	"stale answer",
	"forged answer",
	"dnssec indeterminate",
	"dnssec bogus",
	"signature expired",
	"signature not yet valid",
	"dnskey missing",
	"rrsigs missing",
	"no zone key bit set",
	"nsec missing",
	"cached error",
	"not ready",
	"blocked",
	"censored",
	"filtered",
	"prohibited",
	"stale nxdomain answer",
	"not authoritative",
	"not supported",
	"no reachable authority",
	"network error",
	"invalid data",
}

// more detailed string, only included if there is no detail text in the response.
var errorCodeDetails = []string{
	"unspecified error",
	"only found unsupported algorithms in DNSKEY records",
	"only found unsupported types in DS records",
	"unable to resolve within deadline, stale data served",
	"answer was forged for policy reason",
	"dnssec validation ended in interderminate state",
	"dnssec validation ended in bogus status",
	"only expired dnssec signatures found",
	"only signatures found that are not yet valid",
	"ds key exists at a parent, but no supported matching dnskey found",
	"dnssec validation attempted, but no rrsig found",
	"no zone key bit found in a dnskey",
	"dnssec validation found missing data without nsec/nsec3 record",
	"failure served from cache",
	"not yet fully functional to resolve query",
	"domain is on blocklist due to internal security policy",
	"domain is on blocklist due to external entity",
	"domain is on client-requested blocklist",
	"refusing to serve request",
	"stale nxdomain served from cache",
	"unexpected authoritativeness of query",
	"query or operation not supported",
	"no authoritative name server could be reached",
	"unrecoverable network error",
	"zone data not valid",
}
