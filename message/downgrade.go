package message

import (
	"bytes"
	"fmt"
	"net/mail"
	"strings"
)

// addressHeaders are headers that contain email addresses and should be
// re-encoded using mail.Address.String() which MIME-encodes display names.
var addressHeaders = map[string]bool{
	"from":       true,
	"to":         true,
	"cc":         true,
	"bcc":        true,
	"reply-to":   true,
	"sender":     true,
	"resent-to":  true,
	"resent-cc":  true,
	"resent-bcc": true,
}

// DowngradeSMTPUTF8 re-encodes message headers from raw UTF-8 to RFC 2047 MIME
// encoding, producing a message suitable for delivery to non-SMTPUTF8 servers.
// Only headers are modified; the body is passed through unchanged.
//
// This should only be called for messages that need SMTPUTF8 due to headers (not
// due to envelope addresses — those cannot be downgraded).
func DowngradeSMTPUTF8(msg []byte) ([]byte, error) {
	// Find the blank line separating headers from body.
	headerEnd := bytes.Index(msg, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		// No body, entire message is headers.
		headerEnd = len(msg)
	}

	headerBytes := msg[:headerEnd]
	var body []byte
	if headerEnd+4 <= len(msg) {
		body = msg[headerEnd:] // Includes the \r\n\r\n separator.
	} else {
		body = msg[headerEnd:]
	}

	// Parse individual header fields. Each field starts at the beginning of a line
	// and may continue on subsequent lines starting with whitespace (folding).
	var result bytes.Buffer
	lines := splitHeaderFields(headerBytes)
	for _, line := range lines {
		if isASCII(string(line)) {
			// ASCII-only header, pass through unchanged.
			result.Write(line)
			continue
		}

		// Header has non-ASCII content. Re-encode based on header type.
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			// Shouldn't happen for valid headers, pass through.
			result.Write(line)
			continue
		}
		name := string(line[:colonIdx])
		// Value includes the space after colon through end including \r\n.
		value := string(line[colonIdx+1:])
		// Trim the trailing \r\n for processing, we'll add it back.
		value = strings.TrimRight(value, "\r\n")
		// Unfold continuation lines for processing.
		value = unfoldHeader(value)

		nameLower := strings.ToLower(name)
		var encoded string
		if addressHeaders[nameLower] {
			encoded = encodeAddressHeader(value)
		} else if nameLower == "subject" {
			encoded = encodeSubjectHeader(value)
		} else {
			encoded = encodeGenericHeader(value)
		}

		fmt.Fprintf(&result, "%s:%s\r\n", name, encoded)
	}

	result.Write(body)
	return result.Bytes(), nil
}

// splitHeaderFields splits raw header bytes into individual header fields.
// Each returned slice includes the header name, value, continuation lines, and
// the trailing \r\n. The input should not include the blank line separator.
func splitHeaderFields(header []byte) [][]byte {
	var fields [][]byte
	start := 0
	for i := 0; i < len(header); {
		// Find the end of this line.
		nlIdx := bytes.Index(header[i:], []byte("\r\n"))
		if nlIdx < 0 {
			// No more CRLF, rest is the last field.
			fields = append(fields, header[start:])
			break
		}
		lineEnd := i + nlIdx + 2 // Past the \r\n.

		// Check if the next line is a continuation (starts with space or tab).
		if lineEnd < len(header) && (header[lineEnd] == ' ' || header[lineEnd] == '\t') {
			// Continuation line, keep going.
			i = lineEnd
			continue
		}

		// End of this header field.
		fields = append(fields, header[start:lineEnd])
		start = lineEnd
		i = lineEnd
	}
	if start < len(header) && len(fields) == 0 {
		fields = append(fields, header[start:])
	}
	return fields
}

// unfoldHeader removes RFC 5322 header folding (CRLF followed by WSP).
func unfoldHeader(s string) string {
	s = strings.ReplaceAll(s, "\r\n\t", " ")
	s = strings.ReplaceAll(s, "\r\n ", " ")
	return s
}

// encodeAddressHeader parses and re-encodes an address header value.
// Display names with non-ASCII are MIME-encoded by mail.Address.String().
func encodeAddressHeader(value string) string {
	value = strings.TrimSpace(value)
	// mail.ParseAddressList handles RFC 5322 address lists.
	addrs, err := mail.ParseAddressList(value)
	if err != nil {
		// If parsing fails, fall back to generic encoding.
		return encodeGenericHeader(" " + value)
	}

	var parts []string
	for _, addr := range addrs {
		// mail.Address.String() automatically MIME-encodes the display name
		// if it contains non-ASCII characters.
		parts = append(parts, addr.String())
	}
	return " " + strings.Join(parts, ", ")
}

// encodeSubjectHeader re-encodes a subject value for use in a header.
func encodeSubjectHeader(value string) string {
	value = strings.TrimSpace(value)
	if isASCII(value) {
		return " " + value
	}
	return " " + qencode(value)
}

// encodeGenericHeader Q-encodes non-ASCII portions of a header value.
func encodeGenericHeader(value string) string {
	if isASCII(value) {
		return value
	}

	// Encode the entire non-ASCII value. We keep leading whitespace.
	trimmed := strings.TrimLeft(value, " \t")
	prefix := value[:len(value)-len(trimmed)]
	if prefix == "" {
		prefix = " "
	}
	return prefix + qencode(trimmed)
}
