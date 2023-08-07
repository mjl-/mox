package message

import (
	"strings"
)

// NeedsQuotedPrintable returns whether text should be encoded with
// quoted-printable. If not, it can be included as 7bit or 8bit encoding.
func NeedsQuotedPrintable(text string) bool {
	// ../rfc/2045:1025
	for _, line := range strings.Split(text, "\r\n") {
		if len(line) > 78 || strings.Contains(line, "\r") || strings.Contains(line, "\n") {
			return true
		}
	}
	return false
}
