package dkim

import (
	"fmt"
	"strings"
)

// DefaultPolicy is the default DKIM policy.
//
// Signatures with a length restriction are rejected because it is hard to decide
// how many signed bytes should be required (none? at least half? all except
// max N bytes?). Also, it isn't likely email applications (MUAs) will be
// displaying the signed vs unsigned (partial) content differently, mostly
// because the encoded data is signed. E.g.  half a base64 image could be
// signed, and the rest unsigned.
//
// Signatures without Subject field are rejected. The From header field is
// always required and does not need to be checked in the policy.
// Other signatures are accepted.
func DefaultPolicy(sig *Sig) error {
	// ../rfc/6376:2088
	// ../rfc/6376:2307
	// ../rfc/6376:2706
	// ../rfc/6376:1558
	if sig.Length >= 0 {
		return fmt.Errorf("l= for length not acceptable")
	}

	// ../rfc/6376:2139
	// We require at least the following headers: From, Subject.
	// You would expect To, Cc and Message-ID to also always be present.
	// Microsoft appears to leave out To.
	// Yahoo appears to leave out Message-ID.
	// Multiple leave out Cc and other address headers.
	// At least one newsletter did not sign Date.
	var subject bool
	for _, h := range sig.SignedHeaders {
		subject = subject || strings.EqualFold(h, "subject")
	}
	var missing []string
	if !subject {
		missing = append(missing, "subject")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required header fields missing from signature: %s", strings.Join(missing, ", "))
	}

	return nil
}
