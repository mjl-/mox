package imapserver

import (
	"fmt"
	"io"

	"github.com/mjl-/mox/mlog"
)

type token interface {
	pack(c *conn) string
	xwriteTo(c *conn, xw io.Writer) // Writes to xw panic on error.
}

type bare string

func (t bare) pack(c *conn) string {
	return string(t)
}

func (t bare) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

type niltoken struct{}

var nilt niltoken

func (t niltoken) pack(c *conn) string {
	return "NIL"
}

func (t niltoken) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

func nilOrString(s *string) token {
	if s == nil {
		return nilt
	}
	return string0(*s)
}

type string0 string

// ../rfc/9051:7081
// ../rfc/9051:6856 ../rfc/6855:153
func (t string0) pack(c *conn) string {
	r := `"`
	for _, ch := range t {
		if ch == '\x00' || ch == '\r' || ch == '\n' || ch > 0x7f && !c.utf8strings() {
			return syncliteral(t).pack(c)
		}
		if ch == '\\' || ch == '"' {
			r += `\`
		}
		r += string(ch)
	}
	r += `"`
	return r
}

func (t string0) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

type dquote string

func (t dquote) pack(c *conn) string {
	r := `"`
	for _, c := range t {
		if c == '\\' || c == '"' {
			r += `\`
		}
		r += string(c)
	}
	r += `"`
	return r
}

func (t dquote) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

type syncliteral string

func (t syncliteral) pack(c *conn) string {
	return fmt.Sprintf("{%d}\r\n", len(t)) + string(t)
}

func (t syncliteral) xwriteTo(c *conn, xw io.Writer) {
	fmt.Fprintf(xw, "{%d}\r\n", len(t))
	xw.Write([]byte(t))
}

// data from reader with known size.
type readerSizeSyncliteral struct {
	r    io.Reader
	size int64
	lit8 bool
}

func (t readerSizeSyncliteral) pack(c *conn) string {
	buf, err := io.ReadAll(t.r)
	if err != nil {
		panic(err)
	}
	var lit string
	if t.lit8 {
		lit = "~"
	}
	return fmt.Sprintf("%s{%d}\r\n", lit, t.size) + string(buf)
}

func (t readerSizeSyncliteral) xwriteTo(c *conn, xw io.Writer) {
	var lit string
	if t.lit8 {
		lit = "~"
	}
	fmt.Fprintf(xw, "%s{%d}\r\n", lit, t.size)
	defer c.xtracewrite(mlog.LevelTracedata)()
	if _, err := io.Copy(xw, io.LimitReader(t.r, t.size)); err != nil {
		panic(err)
	}
}

// data from reader without known size.
type readerSyncliteral struct {
	r io.Reader
}

func (t readerSyncliteral) pack(c *conn) string {
	buf, err := io.ReadAll(t.r)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("{%d}\r\n", len(buf)) + string(buf)
}

func (t readerSyncliteral) xwriteTo(c *conn, xw io.Writer) {
	buf, err := io.ReadAll(t.r)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(xw, "{%d}\r\n", len(buf))
	defer c.xtracewrite(mlog.LevelTracedata)()
	xw.Write(buf)
}

// list with tokens space-separated
type listspace []token

func (t listspace) pack(c *conn) string {
	s := "("
	for i, e := range t {
		if i > 0 {
			s += " "
		}
		s += e.pack(c)
	}
	s += ")"
	return s
}

func (t listspace) xwriteTo(c *conn, xw io.Writer) {
	fmt.Fprint(xw, "(")
	for i, e := range t {
		if i > 0 {
			fmt.Fprint(xw, " ")
		}
		e.xwriteTo(c, xw)
	}
	fmt.Fprint(xw, ")")
}

// concatenate tokens space-separated
type concatspace []token

func (t concatspace) pack(c *conn) string {
	var s string
	for i, e := range t {
		if i > 0 {
			s += " "
		}
		s += e.pack(c)
	}
	return s
}

func (t concatspace) xwriteTo(c *conn, xw io.Writer) {
	for i, e := range t {
		if i > 0 {
			fmt.Fprint(xw, " ")
		}
		e.xwriteTo(c, xw)
	}
}

// Concatenated tokens, no spaces or list syntax.
type concat []token

func (t concat) pack(c *conn) string {
	var s string
	for _, e := range t {
		s += e.pack(c)
	}
	return s
}

func (t concat) xwriteTo(c *conn, xw io.Writer) {
	for _, e := range t {
		e.xwriteTo(c, xw)
	}
}

type astring string

func (t astring) pack(c *conn) string {
	if len(t) == 0 {
		return string0(t).pack(c)
	}
next:
	for _, ch := range t {
		for _, x := range atomChar {
			if ch == x {
				continue next
			}
		}
		return string0(t).pack(c)
	}
	return string(t)
}

func (t astring) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

// mailbox with utf7 encoding if connection requires it, or utf8 otherwise.
type mailboxt string

func (t mailboxt) pack(c *conn) string {
	s := string(t)
	if !c.utf8strings() {
		s = utf7encode(s)
	}
	return astring(s).pack(c)
}

func (t mailboxt) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}

type number uint32

func (t number) pack(c *conn) string {
	return fmt.Sprintf("%d", t)
}

func (t number) xwriteTo(c *conn, xw io.Writer) {
	xw.Write([]byte(t.pack(c)))
}
