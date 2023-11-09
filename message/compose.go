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

var errCompose = errors.New("compose")

// Composer helps compose a message. Operations that fail call panic, which can be
// caught with Composer.Recover. Writes are buffered.
type Composer struct {
	Has8bit  bool // Whether message contains 8bit data.
	SMTPUTF8 bool // Whether message needs to be sent with SMTPUTF8 extension.

	bw *bufio.Writer
}

func NewComposer(w io.Writer) *Composer {
	return &Composer{bw: bufio.NewWriter(w)}
}

// Write implements io.Writer, but calls panic (that is handled higher up) on
// i/o errors.
func (c *Composer) Write(buf []byte) (int, error) {
	n, err := c.bw.Write(buf)
	c.Checkf(err, "write")
	return n, nil
}

// Recover recovers the sentinel panic error value, storing it into rerr.
func (c *Composer) Recover(rerr *error) {
	x := recover()
	if x == nil {
		return
	}
	if err, ok := x.(error); ok && errors.Is(err, errCompose) {
		*rerr = err
	} else {
		panic(x)
	}
}

// Checkf checks err, panicing with sentinel error value.
func (c *Composer) Checkf(err error, format string, args ...any) {
	if err != nil {
		panic(fmt.Errorf("%w: %s: %v", errCompose, err, fmt.Sprintf(format, args...)))
	}
}

// Flush writes any buffered output.
func (c *Composer) Flush() {
	err := c.bw.Flush()
	c.Checkf(err, "flush")
}

// Header writes a message header.
func (c *Composer) Header(k, v string) {
	fmt.Fprintf(c, "%s: %s\r\n", k, v)
}

// HeaderAddrs writes a message header with addresses.
func (c *Composer) HeaderAddrs(k string, l []smtp.Address) {
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
		addr := mail.Address{Address: a.Pack(c.SMTPUTF8)}
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
	fmt.Fprintf(c, "%s: %s\r\n", k, v)
}

// Subject writes a subject message header.
func (c *Composer) Subject(subject string) {
	var subjectValue string
	subjectLineLen := len("Subject: ")
	subjectWord := false
	for i, word := range strings.Split(subject, " ") {
		if !c.SMTPUTF8 && !isASCII(word) {
			word = mime.QEncoding.Encode("utf-8", word)
		}
		if i > 0 {
			subjectValue += " "
			subjectLineLen++
		}
		if subjectWord && subjectLineLen+len(word) > 77 {
			subjectValue += "\r\n\t"
			subjectLineLen = 1
		}
		subjectValue += word
		subjectLineLen += len(word)
		subjectWord = true
	}
	c.Header("Subject", subjectValue)
}

// Line writes an empty line.
func (c *Composer) Line() {
	_, _ = c.Write([]byte("\r\n"))
}

// TextPart prepares a text part to be added. Text should contain lines terminated
// with newlines (lf), which are replaced with crlf. The returned text may be
// quotedprintable, if needed. The returned ct and cte headers are for use with
// Content-Type and Content-Transfer-Encoding headers.
func (c *Composer) TextPart(text string) (textBody []byte, ct, cte string) {
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
		c.Checkf(err, "converting text to quoted printable")
		text = sb.String()
		cte = "quoted-printable"
	} else if c.Has8bit || charset == "utf-8" {
		cte = "8bit"
	} else {
		cte = "7bit"
	}

	ct = mime.FormatMediaType("text/plain", map[string]string{"charset": charset})
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
