package mtasts

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
)

type parseErr string

func (e parseErr) Error() string {
	return string(e)
}

var _ error = parseErr("")

// ParseRecord parses an MTA-STS record.
func ParseRecord(txt string) (record *Record, ismtasts bool, err error) {
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

	// Parsing is mostly case-sensitive.
	// ../rfc/8461:306
	p := newParser(txt)
	record = &Record{
		Version: "STSv1",
	}
	seen := map[string]struct{}{}
	p.xtake("v=STSv1")
	p.xdelim()
	ismtasts = true
	for {
		k := p.xkey()
		p.xtake("=")

		// Section 3.1 about the TXT record does not say anything about duplicate fields.
		// But section 3.2 about (parsing) policies has a paragraph that starts
		// requirements on both TXT and policy records. That paragraph ends with a note
		// about handling duplicate fields. Let's assume that note also applies to TXT
		// records. ../rfc/8461:517
		_, dup := seen[k]
		seen[k] = struct{}{}

		switch k {
		case "id":
			if !dup {
				record.ID = p.xid()
			}
		default:
			v := p.xvalue()
			record.Extensions = append(record.Extensions, Pair{k, v})
		}
		if !p.delim() || p.empty() {
			break
		}
	}
	if !p.empty() {
		p.xerrorf("leftover characters")
	}
	if record.ID == "" {
		p.xerrorf("missing id")
	}
	return
}

// ParsePolicy parses an MTA-STS policy.
func ParsePolicy(s string) (policy *Policy, err error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if xerr, ok := x.(parseErr); ok {
			policy = nil
			err = fmt.Errorf("%w: %s", ErrPolicySyntax, xerr)
			return
		}
		panic(x)
	}()

	// ../rfc/8461:426
	p := newParser(s)
	policy = &Policy{
		Version: "STSv1",
	}
	seen := map[string]struct{}{}
	for {
		k := p.xkey()
		// For fields except "mx", only the first must be used. ../rfc/8461:517
		_, dup := seen[k]
		seen[k] = struct{}{}
		p.xtake(":")
		p.wsp()
		switch k {
		case "version":
			policy.Version = p.xtake("STSv1")
		case "mode":
			mode := Mode(p.xtakelist("testing", "enforce", "none"))
			if !dup {
				policy.Mode = mode
			}
		case "max_age":
			maxage := p.xmaxage()
			if !dup {
				policy.MaxAgeSeconds = maxage
			}
		case "mx":
			policy.MX = append(policy.MX, p.xmx())
		default:
			v := p.xpolicyvalue()
			policy.Extensions = append(policy.Extensions, Pair{k, v})
		}
		p.wsp()
		if !p.eol() || p.empty() {
			break
		}
	}
	if !p.empty() {
		p.xerrorf("leftover characters")
	}
	required := []string{"version", "mode", "max_age"}
	for _, req := range required {
		if _, ok := seen[req]; !ok {
			p.xerrorf("missing field %q", req)
		}
	}
	if _, ok := seen["mx"]; !ok && policy.Mode != ModeNone {
		// ../rfc/8461:437
		p.xerrorf("missing mx given mode")
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

func (p *parser) prefix(s string) bool {
	return strings.HasPrefix(p.s[p.o:], s)
}

// File name, the known values match this syntax.
// ../rfc/8461:482
func (p *parser) xkey() string {
	return p.xtakefn1(func(b rune, i int) bool {
		return i < 32 && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || (i > 0 && b == '_' || b == '-' || b == '.'))
	})
}

// ../rfc/8461:319
func (p *parser) xid() string {
	return p.xtakefn1(func(b rune, i int) bool {
		return i < 32 && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9')
	})
}

// ../rfc/8461:326
func (p *parser) xvalue() string {
	return p.xtakefn1(func(b rune, i int) bool {
		return b > ' ' && b < 0x7f && b != '=' && b != ';'
	})
}

// ../rfc/8461:315
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

// ../rfc/8461:485
func (p *parser) eol() bool {
	return p.take("\n") || p.take("\r\n")
}

func (p *parser) xtakelist(l ...string) string {
	for _, s := range l {
		if p.prefix(s) {
			return p.xtaken(len(s))
		}
	}
	p.xerrorf("expected one of %s", strings.Join(l, ", "))
	return "" // not reached
}

// ../rfc/8461:476
func (p *parser) xmaxage() int {
	digits := p.xtakefn1(func(b rune, i int) bool {
		return b >= '0' && b <= '9' && i < 10
	})
	v, err := strconv.ParseInt(digits, 10, 32)
	if err != nil {
		p.xerrorf("parsing int: %s", err)
	}
	return int(v)
}

func (p *parser) take(s string) bool {
	if p.prefix(s) {
		p.o += len(s)
		return true
	}
	return false
}

// ../rfc/8461:469
func (p *parser) xmx() (mx MX) {
	if p.prefix("*.") {
		mx.Wildcard = true
		p.o += 2
	}
	mx.Domain = p.xdomain()
	return mx
}

// ../rfc/5321:2291
func (p *parser) xdomain() dns.Domain {
	s := p.xsubdomain()
	for p.take(".") {
		s += "." + p.xsubdomain()
	}
	d, err := dns.ParseDomain(s)
	if err != nil {
		p.xerrorf("parsing domain %q: %s", s, err)
	}
	return d
}

// ../rfc/8461:487
func (p *parser) xsubdomain() string {
	// note: utf-8 is valid, but U-labels are explicitly not allowed. ../rfc/8461:411 ../rfc/5321:2303
	unicode := false
	s := p.xtakefn1(func(c rune, i int) bool {
		if c > 0x7f {
			unicode = true
		}
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (i > 0 && c == '-') || c > 0x7f
	})
	if unicode {
		p.xerrorf("domain must be specified in A labels, not U labels (unicode)")
	}
	return s
}

// ../rfc/8461:487
func (p *parser) xpolicyvalue() string {
	e := len(p.s)
	for i, c := range p.s[p.o:] {
		if c > ' ' && c < 0x7f || c >= 0x80 || (c == ' ' && i > 0) {
			continue
		}
		e = p.o + i
		break
	}
	// Walk back on trailing spaces.
	for e > p.o && p.s[e-1] == ' ' {
		e--
	}
	n := e - p.o
	if n <= 0 {
		p.xerrorf("empty extension value")
	}
	return p.xtaken(n)
}

// "*WSP"
func (p *parser) wsp() {
	n := len(p.s)
	for p.o < n && (p.s[p.o] == ' ' || p.s[p.o] == '\t') {
		p.o++
	}
}
