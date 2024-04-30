package scram

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type parser struct {
	s     string // Original casing.
	lower string // Lower casing, for case-insensitive token consumption.
	o     int    // Offset in s/lower.
}

type parseError struct{ err error }

func (e parseError) Error() string {
	return e.err.Error()
}

func (e parseError) Unwrap() error {
	return e.err
}

// toLower lower cases bytes that are A-Z. strings.ToLower does too much. and
// would replace invalid bytes with unicode replacement characters, which would
// break our requirement that offsets into the original and upper case strings
// point to the same character.
func toLower(s string) string {
	r := []byte(s)
	for i, c := range r {
		if c >= 'A' && c <= 'Z' {
			r[i] = c + 0x20
		}
	}
	return string(r)
}

func newParser(buf []byte) *parser {
	s := string(buf)
	return &parser{s, toLower(s), 0}
}

// Turn panics of parseError into a descriptive ErrInvalidEncoding. Called with
// defer by functions that parse.
func (p *parser) recover(rerr *error) {
	x := recover()
	if x == nil {
		return
	}
	err, ok := x.(error)
	if !ok {
		panic(x)
	}
	var xerr Error
	if errors.As(err, &xerr) {
		*rerr = err
		return
	}
	*rerr = fmt.Errorf("%w: %s", ErrInvalidEncoding, err)
}

func (p *parser) xerrorf(format string, args ...any) {
	panic(parseError{fmt.Errorf(format, args...)})
}

func (p *parser) xcheckf(err error, format string, args ...any) {
	if err != nil {
		panic(parseError{fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)})
	}
}

func (p *parser) xempty() {
	if p.o != len(p.s) {
		p.xerrorf("leftover data")
	}
}

func (p *parser) xnonempty() {
	if p.o >= len(p.s) {
		p.xerrorf("unexpected end")
	}
}

func (p *parser) xbyte() byte {
	p.xnonempty()
	c := p.lower[p.o]
	p.o++
	return c
}

func (p *parser) peek(s string) bool {
	return strings.HasPrefix(p.lower[p.o:], s)
}

func (p *parser) take(s string) bool {
	if p.peek(s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtake(s string) {
	if !p.take(s) {
		p.xerrorf("expected %q", s)
	}
}

func (p *parser) xauthzid() string {
	p.xtake("a=")
	return p.xsaslname()
}

func (p *parser) xusername() string {
	p.xtake("n=")
	return p.xsaslname()
}

func (p *parser) xnonce() string {
	p.xtake("r=")
	o := p.o
	for ; o < len(p.s); o++ {
		c := p.s[o]
		if c <= ' ' || c >= 0x7f || c == ',' {
			break
		}
	}
	if o == p.o {
		p.xerrorf("empty nonce")
	}
	r := p.s[p.o:o]
	p.o = o
	return r
}

func (p *parser) xattrval() {
	c := p.xbyte()
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		p.xerrorf("expected alpha for attr-val")
	}
	p.xtake("=")
	p.xvalue()
}

func (p *parser) xvalue() string {
	for o, c := range p.s[p.o:] {
		if c == 0 || c == ',' {
			if o == 0 {
				p.xerrorf("invalid empty value")
			}
			r := p.s[p.o : p.o+o]
			p.o = o
			return r
		}
	}
	p.xnonempty()
	r := p.s[p.o:]
	p.o = len(p.s)
	return r
}

func (p *parser) xbase64() []byte {
	o := p.o
	for ; o < len(p.s); o++ {
		c := p.s[o]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '+' || c == '=') {
			break
		}
	}
	buf, err := base64.StdEncoding.DecodeString(p.s[p.o:o])
	p.xcheckf(err, "decoding base64")
	p.o = o
	return buf
}

func (p *parser) xsaslname() string {
	var esc string
	var is bool
	var r string
	for o, c := range p.s[p.o:] {
		if c == 0 || c == ',' {
			if is {
				p.xerrorf("saslname unexpected end")
			}
			if o == 0 {
				p.xerrorf("saslname cannot be empty")
			}
			p.o += o
			return r
		}
		if is {
			esc += string(c)
			if len(esc) < 2 {
				continue
			}
			switch esc {
			case "2c", "2C":
				r += ","
			case "3d", "3D":
				r += "="
			default:
				p.xerrorf("bad escape %q in saslanem", esc)
			}
			is = false
			esc = ""
			continue
		} else if c == '=' {
			is = true
			continue
		}
		r += string(c)
	}
	if is {
		p.xerrorf("saslname unexpected end")
	}
	if r == "" {
		p.xerrorf("saslname cannot be empty")
	}
	p.o = len(p.s)
	return r
}

// ../rfc/5802:889
func (p *parser) xcbname() string {
	o := p.o
	for ; o < len(p.s); o++ {
		c := p.s[o]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' {
			continue
		}
		break
	}
	if o == p.o {
		p.xerrorf("empty channel binding name")
	}
	r := p.s[p.o:o]
	p.o = o
	return string(r)
}

func (p *parser) xchannelBinding() []byte {
	p.xtake("c=")
	return p.xbase64()
}

func (p *parser) xproof() []byte {
	p.xtake("p=")
	return p.xbase64()
}

func (p *parser) xsalt() []byte {
	p.xtake("s=")
	return p.xbase64()
}

func (p *parser) xtakefn1(fn func(rune, int) bool) string {
	for o, c := range p.s[p.o:] {
		if !fn(c, o) {
			if o == 0 {
				p.xerrorf("non-empty match required")
			}
			r := p.s[p.o : p.o+o]
			p.o += o
			return r
		}
	}
	p.xnonempty()
	r := p.s[p.o:]
	p.o = len(p.s)
	return r
}

func (p *parser) xiterations() int {
	p.xtake("i=")
	digits := p.xtakefn1(func(c rune, i int) bool {
		return c >= '1' && c <= '9' || i > 0 && c == '0'
	})
	v, err := strconv.ParseInt(digits, 10, 32)
	p.xcheckf(err, "parsing int")
	return int(v)
}
