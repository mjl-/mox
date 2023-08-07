package message

import (
	"github.com/mjl-/mox/dns"
)

// HeaderCommentDomain returns domain name optionally followed by a message
// header comment with ascii-only name.
//
// The comment is only present when smtputf8 is true and the domain name is unicode.
//
// Caller should make sure the comment is allowed in the syntax. E.g. for Received,
// it is often allowed before the next field, so make sure such a next field is
// present.
func HeaderCommentDomain(domain dns.Domain, smtputf8 bool) string {
	s := domain.XName(smtputf8)
	if smtputf8 && domain.Unicode != "" {
		s += " (" + domain.ASCII + ")"
	}
	return s
}
