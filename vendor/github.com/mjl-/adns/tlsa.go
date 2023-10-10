package adns

import (
	"fmt"
)

// TLSAUsage indicates which certificate/public key verification must be done.
type TLSAUsage uint8

const (
	// PKIX/WebPKI, certificate must be valid (name, expiry, signed by CA, etc) and
	// signed by the trusted-anchor (TA) in this record.
	TLSAUsagePKIXTA TLSAUsage = 0
	// PKIX/WebPKI, certificate must be valid (name, expiry, signed by CA, etc) and
	// match the certificate in the record.
	TLSAUsagePKIXEE TLSAUsage = 1
	// Certificate must be signed by trusted-anchor referenced in record, with matching
	// name, non-expired, etc.
	TLSAUsageDANETA TLSAUsage = 2
	// Certificate must match the record. No further requirements on name, expiration
	// or who signed it.
	TLSAUsageDANEEE TLSAUsage = 3
)

// String returns the lower-case acronym of a usage, or "(unknown)" for
// unrecognized values.
func (u TLSAUsage) String() string {
	switch u {
	case TLSAUsagePKIXTA:
		return "pkix-ta"
	case TLSAUsagePKIXEE:
		return "pkix-ee"
	case TLSAUsageDANETA:
		return "dane-ta"
	case TLSAUsageDANEEE:
		return "dane-ee"
	}
	return "(unknown)"
}

// TLSASelecter indicates the data the "certificate association" field is based on.
type TLSASelector uint8

const (
	// DER-encoded x509 certificate.
	TLSASelectorCert TLSASelector = 0
	// DER-encoded subject public key info (SPKI), so only the public key and its type.
	TLSASelectorSPKI TLSASelector = 1
)

// String returns the lower-case acronym of a selector, or "(unknown)" for
// unrecognized values.
func (s TLSASelector) String() string {
	switch s {
	case TLSASelectorCert:
		return "cert"
	case TLSASelectorSPKI:
		return "spki"
	}
	return "(unknown)"
}

// TLSAMatchType indicates in which form the data as indicated by the selector
// is stored in the record as certificate association.
type TLSAMatchType uint8

const (
	// Full data, e.g. a full DER-encoded SPKI or even certificate.
	TLSAMatchTypeFull TLSAMatchType = 0
	// SHA2-256-hashed data, either SPKI or certificate.
	TLSAMatchTypeSHA256 TLSAMatchType = 1
	// SHA2-512-hashed data.
	TLSAMatchTypeSHA512 TLSAMatchType = 2
)

// String returns the lower-case acronym of a match type, or "(unknown)" for
// unrecognized values.
func (mt TLSAMatchType) String() string {
	switch mt {
	case TLSAMatchTypeFull:
		return "full"
	case TLSAMatchTypeSHA256:
		return "sha2-256"
	case TLSAMatchTypeSHA512:
		return "sha2-512"
	}
	return "(unknown)"
}

// TLSA represents a TLSA DNS record.
type TLSA struct {
	Usage     TLSAUsage     // Which validations must be performed.
	Selector  TLSASelector  // What needs to be validated (full certificate or only public key).
	MatchType TLSAMatchType // In which form the certificate/public key is stored in CertAssoc.
	CertAssoc []byte        // Certificate association data.
}

// Record returns a TLSA record value for inclusion in DNS. For example:
//
//	3 1 1 133b919c9d65d8b1488157315327334ead8d83372db57465ecabf53ee5748aee
//
// A full record in a zone file may look like this:
//
//	_25._tcp.example.com. IN TLSA 3 1 1 133b919c9d65d8b1488157315327334ead8d83372db57465ecabf53ee5748aee
//
// This record is dane-ee (3), spki (1), sha2-256 (1), and the hexadecimal data
// is the sha2-256 hash.
func (r TLSA) Record() string {
	return fmt.Sprintf("%d %d %d %x", r.Usage, r.Selector, r.MatchType, r.CertAssoc)
}

// String is like Record but prints both the acronym and code for each field.
func (r TLSA) String() string {
	return fmt.Sprintf("%s(%d) %s(%d) %s(%d) %x", r.Usage, r.Usage, r.Selector, r.Selector, r.MatchType, r.MatchType, r.CertAssoc)
}
