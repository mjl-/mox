package message

import (
	"strings"
)

// NeedsQuotedPrintable returns whether text, with crlf-separated lines, should be
// encoded with quoted-printable, based on line lengths and any bare carriage
// return or bare newline. If not, it can be included as 7bit or 8bit encoding in a
// new message.
func NeedsQuotedPrintable(text string) bool {
	// ../rfc/2045:1025
	for _, line := range strings.Split(text, "\r\n") {
		// 78 should be fine too, qp itself has a requirement of 76 bytes on a line, but
		// using qp for anything longer than 76 is safer.
		if len(line) > 76 || strings.Contains(line, "\r") || strings.Contains(line, "\n") {
			return true
		}
	}
	return false
}
