package message

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/smtp"
)

var errBadMessageID = errors.New("not a message-id")

// MessageIDCanonical parses the Message-ID, returning a canonical value that is
// lower-cased, without <>, and no unneeded quoting. For matching in threading,
// with References/In-Reply-To. If the message-id is invalid (e.g. no <>), an error
// is returned. If the message-id could not be parsed as address (localpart "@"
// domain), the raw value and the bool return parameter true is returned. It is
// quite common that message-id's don't adhere to the localpart @ domain
// syntax.
func MessageIDCanonical(s string) (string, bool, error) {
	// ../rfc/5322:1383

	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "<") {
		return "", false, fmt.Errorf("%w: missing <", errBadMessageID)
	}
	s = s[1:]
	// Seen in practice: Message-ID: <valid@valid.example> (added by postmaster@some.example)
	// Doesn't seem valid, but we allow it.
	s, rem, have := strings.Cut(s, ">")
	if !have || (rem != "" && (moxvar.Pedantic || !strings.HasPrefix(rem, " "))) {
		return "", false, fmt.Errorf("%w: missing >", errBadMessageID)
	}
	// We canonicalize the Message-ID: lower-case, no unneeded quoting.
	s = strings.ToLower(s)
	if s == "" {
		return "", false, fmt.Errorf("%w: empty message-id", errBadMessageID)
	}
	addr, err := smtp.ParseAddress(s)
	if err != nil {
		// Common reasons for not being an address:
		// 1. underscore in hostname.
		// 2. ip literal instead of domain.
		// 3. two @'s, perhaps intended as time-separator
		// 4. no @'s, so no domain/host
		return s, true, nil
	}
	// We preserve the unicode-ness of domain.
	t := strings.Split(s, "@")
	s = addr.Localpart.String() + "@" + t[len(t)-1]
	return s, false, nil
}
