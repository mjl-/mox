package message

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	"github.com/mjl-/mox/smtp"
)

var (
	ErrMessageSize = errors.New("message too large")
	ErrCompose     = errors.New("compose")
)

// Composer helps compose a message. Operations that fail call panic, which should
// be caught with recover(), checking for ErrCompose and optionally ErrMessageSize.
// Writes are buffered.
type Composer struct {
	Has8bit  bool  // Whether message contains 8bit data.
	SMTPUTF8 bool  // Whether message needs to be sent with SMTPUTF8 extension.
	Size     int64 // Total bytes written.

	bw      *bufio.Writer
	maxSize int64 // If greater than zero, writes beyond maximum size raise ErrMessageSize.
}

// NewComposer initializes a new composer with a buffered writer around w, and
// with a maximum message size if maxSize is greater than zero.
//
// smtputf8 must be set when the message must be delivered with smtputf8: if any
// email address localpart has non-ascii (utf-8).
//
// Operations on a Composer do not return an error. Caller must use recover() to
// catch ErrCompose and optionally ErrMessageSize errors.
func NewComposer(w io.Writer, maxSize int64, smtputf8 bool) *Composer {
	return &Composer{bw: bufio.NewWriter(w), maxSize: maxSize, SMTPUTF8: smtputf8, Has8bit: smtputf8}
}

// Write implements io.Writer, but calls panic (that is handled higher up) on
// i/o errors.
func (xc *Composer) Write(buf []byte) (int, error) {
	if xc.maxSize > 0 && xc.Size+int64(len(buf)) > xc.maxSize {
		xc.Checkf(ErrMessageSize, "writing message")
	}
	n, err := xc.bw.Write(buf)
	if n > 0 {
		xc.Size += int64(n)
	}
	xc.Checkf(err, "write")
	return n, nil
}

// Checkf checks err, panicing with sentinel error value.
func (xc *Composer) Checkf(err error, format string, args ...any) {
	if err != nil {
		// We expose the original error too, needed at least for ErrMessageSize.
		panic(fmt.Errorf("%w: %w: %v", ErrCompose, err, fmt.Sprintf(format, args...)))
	}
}

// Flush writes any buffered output.
func (xc *Composer) Flush() {
	err := xc.bw.Flush()
	xc.Checkf(err, "flush")
}

// Header writes a message header.
func (xc *Composer) Header(k, v string) {
	fmt.Fprintf(xc, "%s: %s\r\n", k, v)
}

// NameAddress holds both an address display name, and an SMTP path address.
type NameAddress struct {
	DisplayName string
	Address     smtp.Address
}

// HeaderAddrs writes a message header with addresses.
func (xc *Composer) HeaderAddrs(k string, l []NameAddress) {
	if len(l) == 0 {
		return
	}
	v := ""
	linelen := len(k) + len(": ")
	for _, a := range l {
		if v != "" {
			v += ","
			linelen++
		}
		addr := mail.Address{Name: a.DisplayName, Address: a.Address.Pack(xc.SMTPUTF8)}
		s := addr.String()
		if v != "" && linelen+1+len(s) > 77 {
			v += "\r\n\t"
			linelen = 1
		} else if v != "" {
			v += " "
			linelen++
		}
		v += s
		linelen += len(s)
	}
	fmt.Fprintf(xc, "%s: %s\r\n", k, v)
}

// Subject writes a subject message header.
func (xc *Composer) Subject(subject string) {
	if xc.SMTPUTF8 {
		xc.Header("Subject", subject)
		return
	}

	var result strings.Builder
	lineLen := len("Subject: ")
	words := strings.Split(subject, " ")

	addSpace := func() {
		if lineLen+1 > 77 {
			result.WriteString("\r\n\t")
			lineLen = 1
		} else {
			result.WriteString(" ")
			lineLen++
		}
	}

	addText := func(text string) {
		if lineLen+len(text) > 77 {
			result.WriteString("\r\n\t")
			lineLen = 1
		}
		result.WriteString(text)
		lineLen += len(text)
	}

	i := 0
	for i < len(words) {
		if i > 0 {
			addSpace()
		}

		word := words[i]
		if word == "" {
			i++
			continue
		}

		if isASCII(word) {
			addText(word)
			i++
		} else {
			// Group consecutive non-ASCII words
			var phrase strings.Builder
			phrase.WriteString(word)
			i++

			for i < len(words) && words[i] != "" && !isASCII(words[i]) {
				phrase.WriteString(" ")
				phrase.WriteString(words[i])
				i++
			}

			// Encode and add with line folding
			encoded := mime.BEncoding.Encode("utf-8", phrase.String())
			for j, encWord := range strings.Split(encoded, " ") {
				if j > 0 {
					addSpace()
				}
				addText(encWord)
			}
		}
	}

	xc.Header("Subject", result.String())
}

// Line writes an empty line.
func (xc *Composer) Line() {
	_, _ = xc.Write([]byte("\r\n"))
}

// TextPart prepares a text part to be added. Text should contain lines terminated
// with newlines (lf), which are replaced with crlf. The returned text may be
// quotedprintable, if needed. The returned ct and cte headers are for use with
// Content-Type and Content-Transfer-Encoding headers.
func (xc *Composer) TextPart(subtype, text string) (textBody []byte, ct, cte string) {
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text = strings.ReplaceAll(text, "\n", "\r\n")
	charset := "us-ascii"
	if !isASCII(text) {
		charset = "utf-8"
	}
	if NeedsQuotedPrintable(text) {
		var sb strings.Builder
		_, err := io.Copy(quotedprintable.NewWriter(&sb), strings.NewReader(text))
		xc.Checkf(err, "converting text to quoted printable")
		text = sb.String()
		cte = "quoted-printable"
	} else if xc.Has8bit || charset == "utf-8" {
		cte = "8bit"
	} else {
		cte = "7bit"
	}

	ct = mime.FormatMediaType("text/"+subtype, map[string]string{"charset": charset})
	return []byte(text), ct, cte
}

func isASCII(s string) bool {
	for _, c := range s {
		if c >= 0x80 {
			return false
		}
	}
	return true
}
