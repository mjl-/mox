package tlsrpt

import (
	"fmt"
	"net/url"
	"strings"
)

// Extension is an additional key/value pair for a TLSRPT record.
type Extension struct {
	Key   string
	Value string
}

// Record is a parsed TLSRPT record, to be served under "_smtp._tls.<domain>".
//
// Example:
//
//	v=TLSRPTv1; rua=mailto:tlsrpt@mox.example;
type Record struct {
	Version string // "TLSRPTv1", for "v=".

	// Aggregate reporting URI, for "rua=". "rua=" can occur multiple times, each can
	// be a list.
	RUAs [][]RUA
	// ../rfc/8460:383

	Extensions []Extension
}

// RUA is a reporting address with scheme and special characters ",", "!" and
// ";" not encoded.
type RUA string

// String returns the RUA with special characters encoded, for inclusion in a
// TLSRPT record.
func (rua RUA) String() string {
	s := string(rua)
	s = strings.ReplaceAll(s, ",", "%2C")
	s = strings.ReplaceAll(s, "!", "%21")
	s = strings.ReplaceAll(s, ";", "%3B")
	return s
}

// URI parses a RUA as URI, with either a mailto or https scheme.
func (rua RUA) URI() (*url.URL, error) {
	return url.Parse(string(rua))
}

// String returns a string or use as a TLSRPT DNS TXT record.
func (r Record) String() string {
	b := &strings.Builder{}
	fmt.Fprint(b, "v="+r.Version)
	for _, ruas := range r.RUAs {
		l := make([]string, len(ruas))
		for i, rua := range ruas {
			l[i] = rua.String()
		}
		fmt.Fprint(b, "; rua="+strings.Join(l, ","))
	}
	for _, p := range r.Extensions {
		fmt.Fprint(b, "; "+p.Key+"="+p.Value)
	}
	return b.String()
}

type parseErr string

func (e parseErr) Error() string {
	return string(e)
}

var _ error = parseErr("")

// ParseRecord parses a TLSRPT record.
func ParseRecord(txt string) (record *Record, istlsrpt bool, err error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if xerr, ok := x.(parseErr); ok {
			record = nil
			err = fmt.Errorf("%w: %s", ErrRecordSyntax, xerr)
			return
		}
		panic(x)
	}()

	p := newParser(txt)

	record = &Record{
		Version: "TLSRPTv1",
	}

	p.xtake("v=TLSRPTv1")
	p.xdelim()
	istlsrpt = true
	for {
		k := p.xkey()
		p.xtake("=")
		// note: duplicates are allowed.
		switch k {
		case "rua":
			record.RUAs = append(record.RUAs, p.xruas())
		default:
			v := p.xvalue()
			record.Extensions = append(record.Extensions, Extension{k, v})
		}
		if !p.delim() || p.empty() {
			break
		}
	}
	if !p.empty() {
		p.xerrorf("leftover chars")
	}
	if record.RUAs == nil {
		p.xerrorf("missing rua")
	}
	return
}

type parser struct {
	s string
	o int
}

func newParser(s string) *parser {
	return &parser{s: s}
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.o < len(p.s) {
		msg += fmt.Sprintf(" (remain %q)", p.s[p.o:])
	}
	panic(parseErr(msg))
}

func (p *parser) xtake(s string) string {
	if !p.prefix(s) {
		p.xerrorf("expected %q", s)
	}
	p.o += len(s)
	return s
}

func (p *parser) xdelim() {
	if !p.delim() {
		p.xerrorf("expected semicolon")
	}
}

func (p *parser) xtaken(n int) string {
	r := p.s[p.o : p.o+n]
	p.o += n
	return r
}

func (p *parser) prefix(s string) bool {
	return strings.HasPrefix(p.s[p.o:], s)
}

func (p *parser) take(s string) bool {
	if p.prefix(s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtakefn1(fn func(rune, int) bool) string {
	for i, b := range p.s[p.o:] {
		if !fn(b, i) {
			if i == 0 {
				p.xerrorf("expected at least one char")
			}
			return p.xtaken(i)
		}
	}
	if p.empty() {
		p.xerrorf("expected at least 1 char")
	}
	return p.xtaken(len(p.s) - p.o)
}

// ../rfc/8460:368
func (p *parser) xkey() string {
	return p.xtakefn1(func(b rune, i int) bool {
		return i < 32 && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || (i > 0 && b == '_' || b == '-' || b == '.'))
	})
}

// ../rfc/8460:371
func (p *parser) xvalue() string {
	return p.xtakefn1(func(b rune, i int) bool {
		return b > ' ' && b < 0x7f && b != '=' && b != ';'
	})
}

// ../rfc/8460:399
func (p *parser) delim() bool {
	o := p.o
	e := len(p.s)
	for o < e && (p.s[o] == ' ' || p.s[o] == '\t') {
		o++
	}
	if o >= e || p.s[o] != ';' {
		return false
	}
	o++
	for o < e && (p.s[o] == ' ' || p.s[o] == '\t') {
		o++
	}
	p.o = o
	return true
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) wsp() {
	for p.o < len(p.s) && (p.s[p.o] == ' ' || p.s[p.o] == '\t') {
		p.o++
	}
}

// ../rfc/8460:358
func (p *parser) xruas() []RUA {
	l := []RUA{p.xuri()}
	p.wsp()
	for p.take(",") {
		p.wsp()
		l = append(l, p.xuri())
		p.wsp()
	}
	return l
}

// ../rfc/8460:360
func (p *parser) xuri() RUA {
	v := p.xtakefn1(func(b rune, i int) bool {
		return b != ',' && b != '!' && b != ' ' && b != '\t' && b != ';'
	})
	u, err := url.Parse(v)
	if err != nil {
		p.xerrorf("parsing uri %q: %s", v, err)
	}
	if u.Scheme == "" {
		p.xerrorf("missing scheme in uri")
	}
	return RUA(v)
}
