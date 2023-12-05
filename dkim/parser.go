package dkim

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// Pedantic enables stricter parsing.
var Pedantic bool

type parseErr string

func (e parseErr) Error() string {
	return string(e)
}

var _ error = parseErr("")

type parser struct {
	s        string
	o        int    // Offset into s.
	tracked  string // All data consumed, except when "drop" is true. To be set by caller when parsing the value for "b=".
	drop     bool
	smtputf8 bool // If set, allow characters > 0x7f.
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.o < len(p.s) {
		msg = fmt.Sprintf("%s (leftover %q)", msg, p.s[p.o:])
	}
	panic(parseErr(msg))
}

func (p *parser) track(s string) {
	if !p.drop {
		p.tracked += s
	}
}

func (p *parser) hasPrefix(s string) bool {
	return strings.HasPrefix(p.s[p.o:], s)
}

func (p *parser) xtaken(n int) string {
	r := p.s[p.o : p.o+n]
	p.o += n
	p.track(r)
	return r
}

func (p *parser) xtakefn(ignoreFWS bool, fn func(c rune, i int) bool) string {
	var r string
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			switch c {
			case ' ', '\t', '\r', '\n':
				continue
			}
			p.xtaken(i)
			return r
		}
		r += string(c)
	}
	p.xtaken(len(p.s) - p.o)
	return r
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) xnonempty() {
	if p.o >= len(p.s) {
		p.xerrorf("expected at least 1 more char")
	}
}

func (p *parser) xtakefn1(ignoreFWS bool, fn func(c rune, i int) bool) string {
	var r string
	p.xnonempty()
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			switch c {
			case ' ', '\t', '\r', '\n':
				continue
			}
			if i == 0 {
				p.xerrorf("expected at least 1 char")
			}
			p.xtaken(i)
			return r
		}
		r += string(c)
	}
	return p.xtaken(len(p.s) - p.o)
}

func (p *parser) wsp() {
	p.xtakefn(false, func(c rune, i int) bool {
		return c == ' ' || c == '\t'
	})
}

func (p *parser) fws() {
	p.wsp()
	if p.hasPrefix("\r\n ") || p.hasPrefix("\r\n\t") {
		p.xtaken(3)
		p.wsp()
	}
}

// peekfws returns whether remaining text starts with s, optionally prefix with fws.
func (p *parser) peekfws(s string) bool {
	o := p.o
	p.fws()
	r := p.hasPrefix(s)
	p.o = o
	return r
}

func (p *parser) xtake(s string) string {
	if !strings.HasPrefix(p.s[p.o:], s) {
		p.xerrorf("expected %q", s)
	}
	return p.xtaken(len(s))
}

func (p *parser) take(s string) bool {
	if strings.HasPrefix(p.s[p.o:], s) {
		p.o += len(s)
		p.track(s)
		return true
	}
	return false
}

// ../rfc/6376:657
func (p *parser) xtagName() string {
	return p.xtakefn1(false, func(c rune, i int) bool {
		return isalpha(c) || i > 0 && (isdigit(c) || c == '_')
	})
}

func (p *parser) xalgorithm() (string, string) {
	// ../rfc/6376:1046
	xtagx := func(c rune, i int) bool {
		return isalpha(c) || i > 0 && isdigit(c)
	}
	algk := p.xtakefn1(false, xtagx)
	p.xtake("-")
	algv := p.xtakefn1(false, xtagx)
	return algk, algv
}

// fws in value is ignored. empty/no base64 characters is valid.
// ../rfc/6376:1021
// ../rfc/6376:1076
func (p *parser) xbase64() []byte {
	s := ""
	p.xtakefn(false, func(c rune, i int) bool {
		if isalphadigit(c) || c == '+' || c == '/' || c == '=' {
			s += string(c)
			return true
		}
		if c == ' ' || c == '\t' {
			return true
		}
		rem := p.s[p.o+i:]
		if strings.HasPrefix(rem, "\r\n ") || strings.HasPrefix(rem, "\r\n\t") {
			return true
		}
		if (strings.HasPrefix(rem, "\n ") || strings.HasPrefix(rem, "\n\t")) && p.o+i-1 > 0 && p.s[p.o+i-1] == '\r' {
			return true
		}
		return false
	})
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		p.xerrorf("decoding base64: %v", err)
	}
	return buf
}

// parses canonicalization in original case.
func (p *parser) xcanonical() string {
	// ../rfc/6376:1100
	s := p.xhyphenatedWord()
	if p.take("/") {
		return s + "/" + p.xhyphenatedWord()
	}
	return s
}

func (p *parser) xdomainselector(isselector bool) dns.Domain {
	subdomain := func(c rune, i int) bool {
		// domain names must always be a-labels, ../rfc/6376:1115 ../rfc/6376:1187 ../rfc/6376:1303
		// dkim selectors with underscores happen in the wild, accept them when not in
		// pedantic mode. ../rfc/6376:581 ../rfc/5321:2303
		return isalphadigit(c) || (i > 0 && (c == '-' || isselector && !Pedantic && c == '_') && p.o+1 < len(p.s))
	}
	s := p.xtakefn1(false, subdomain)
	for p.hasPrefix(".") {
		s += p.xtake(".") + p.xtakefn1(false, subdomain)
	}
	if isselector {
		// Not to be interpreted as IDNA.
		return dns.Domain{ASCII: strings.ToLower(s)}
	}
	d, err := dns.ParseDomain(s)
	if err != nil {
		p.xerrorf("parsing domain %q: %s", s, err)
	}
	return d
}

func (p *parser) xdomain() dns.Domain {
	return p.xdomainselector(false)
}

func (p *parser) xselector() dns.Domain {
	return p.xdomainselector(true)
}

func (p *parser) xhdrName(ignoreFWS bool) string {
	// ../rfc/6376:473
	// ../rfc/5322:1689
	// BNF for hdr-name (field-name) allows ";", but DKIM disallows unencoded semicolons. ../rfc/6376:643
	// ignoreFWS is needed for "z=", which can have FWS anywhere. ../rfc/6376:1372
	return p.xtakefn1(ignoreFWS, func(c rune, i int) bool {
		return c > ' ' && c < 0x7f && c != ':' && c != ';'
	})
}

func (p *parser) xsignedHeaderFields() []string {
	// ../rfc/6376:1157
	l := []string{p.xhdrName(false)}
	for p.peekfws(":") {
		p.fws()
		p.xtake(":")
		p.fws()
		l = append(l, p.xhdrName(false))
	}
	return l
}

func (p *parser) xauid() Identity {
	// ../rfc/6376:1192
	// Localpart is optional.
	if p.take("@") {
		return Identity{Domain: p.xdomain()}
	}
	lp := p.xlocalpart()
	p.xtake("@")
	dom := p.xdomain()
	return Identity{&lp, dom}
}

// todo: reduce duplication between implementations: ../smtp/address.go:/xlocalpart ../dkim/parser.go:/xlocalpart ../smtpserver/parse.go:/xlocalpart
func (p *parser) xlocalpart() smtp.Localpart {
	// ../rfc/6376:434
	// ../rfc/5321:2316
	var s string
	if p.hasPrefix(`"`) {
		s = p.xquotedString()
	} else {
		s = p.xatom()
		for p.take(".") {
			s += "." + p.xatom()
		}
	}
	// In the wild, some services use large localparts for generated (bounce) addresses.
	if Pedantic && len(s) > 64 || len(s) > 128 {
		// ../rfc/5321:3486
		p.xerrorf("localpart longer than 64 octets")
	}
	return smtp.Localpart(s)
}

func (p *parser) xquotedString() string {
	p.xtake(`"`)
	var s string
	var esc bool
	for {
		c := p.xchar()
		if esc {
			if c >= ' ' && c < 0x7f {
				s += string(c)
				esc = false
				continue
			}
			p.xerrorf("invalid localpart, bad escaped char %c", c)
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			return s
		}
		if c >= ' ' && c < 0x7f && c != '\\' && c != '"' || (c > 0x7f && p.smtputf8) {
			s += string(c)
			continue
		}
		p.xerrorf("invalid localpart, invalid character %c", c)
	}
}

func (p *parser) xchar() rune {
	// We are careful to track invalid utf-8 properly.
	if p.empty() {
		p.xerrorf("need another character")
	}
	var r rune
	var o int
	for i, c := range p.s[p.o:] {
		if i > 0 {
			o = i
			break
		}
		r = c
	}
	if o == 0 {
		p.track(p.s[p.o:])
		p.o = len(p.s)
	} else {
		p.track(p.s[p.o : p.o+o])
		p.o += o
	}
	return r
}

func (p *parser) xatom() string {
	return p.xtakefn1(false, func(c rune, i int) bool {
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
			return true
		}
		return isalphadigit(c) || (c > 0x7f && p.smtputf8)
	})
}

func (p *parser) xbodyLength() int64 {
	// ../rfc/6376:1265
	return p.xnumber(76)
}

func (p *parser) xnumber(maxdigits int) int64 {
	o := -1
	for i, c := range p.s[p.o:] {
		if c >= '0' && c <= '9' {
			o = i
		} else {
			break
		}
	}
	if o == -1 {
		p.xerrorf("expected digits")
	}
	if o+1 > maxdigits {
		p.xerrorf("too many digits")
	}
	v, err := strconv.ParseInt(p.xtaken(o+1), 10, 64)
	if err != nil {
		p.xerrorf("parsing digits: %s", err)
	}
	return v
}

func (p *parser) xqueryMethods() []string {
	// ../rfc/6376:1285
	l := []string{p.xqtagmethod()}
	for p.peekfws(":") {
		p.fws()
		p.xtake(":")
		l = append(l, p.xqtagmethod())
	}
	return l
}

func (p *parser) xqtagmethod() string {
	// ../rfc/6376:1295 ../rfc/6376-eid4810
	s := p.xhyphenatedWord()
	// ABNF production "x-sig-q-tag-args" should probably just have been
	// "hyphenated-word". As qp-hdr-value, it will consume ":". A similar problem does
	// not occur for "z" because it is also "|"-delimited. We work around the potential
	// issue by parsing "dns/txt" explicitly.
	rem := p.s[p.o:]
	if strings.EqualFold(s, "dns") && len(rem) >= len("/txt") && strings.EqualFold(rem[:len("/txt")], "/txt") {
		s += p.xtaken(4)
	} else if p.take("/") {
		s += "/" + p.xqp(true, true, false)
	}
	return s
}

func isalpha(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isdigit(c rune) bool {
	return c >= '0' && c <= '9'
}

func isalphadigit(c rune) bool {
	return isalpha(c) || isdigit(c)
}

// ../rfc/6376:469
func (p *parser) xhyphenatedWord() string {
	return p.xtakefn1(false, func(c rune, i int) bool {
		return isalpha(c) || i > 0 && isdigit(c) || i > 0 && c == '-' && p.o+i+1 < len(p.s) && isalphadigit(rune(p.s[p.o+i+1]))
	})
}

// ../rfc/6376:474
func (p *parser) xqphdrvalue(ignoreFWS bool) string {
	return p.xqp(true, false, ignoreFWS)
}

func (p *parser) xqpSection() string {
	return p.xqp(false, false, false)
}

// dkim-quoted-printable (pipeEncoded true) or qp-section.
//
// It is described in terms of (lots of) modifications to MIME quoted-printable,
// but it may be simpler to just ignore that reference.
//
// ignoreFWS is required for "z=", which can have FWS anywhere.
func (p *parser) xqp(pipeEncoded, colonEncoded, ignoreFWS bool) string {
	// ../rfc/6376:494 ../rfc/2045:1260

	hex := func(c byte) rune {
		if c >= '0' && c <= '9' {
			return rune(c - '0')
		}
		return rune(10 + c - 'A')
	}

	s := ""
	for !p.empty() {
		p.fws()
		if pipeEncoded && p.hasPrefix("|") {
			break
		}
		if colonEncoded && p.hasPrefix(":") {
			break
		}
		if p.take("=") {
			h := p.xtakefn(ignoreFWS, func(c rune, i int) bool {
				return i < 2 && (c >= '0' && c <= '9' || c >= 'A' && c <= 'Z')
			})
			if len(h) != 2 {
				p.xerrorf("expected qp-hdr-value")
			}
			c := (hex(h[0]) << 4) | hex(h[1])
			s += string(c)
			continue
		}
		x := p.xtakefn(ignoreFWS, func(c rune, i int) bool {
			return c > ' ' && c < 0x7f && c != ';' && c != '=' && !(pipeEncoded && c == '|')
		})
		if x == "" {
			break
		}
		s += x
	}
	return s
}

func (p *parser) xtimestamp() int64 {
	// ../rfc/6376:1325 ../rfc/6376:1358
	return p.xnumber(12)
}

func (p *parser) xcopiedHeaderFields() []string {
	// ../rfc/6376:1384
	l := []string{p.xztagcopy()}
	for p.hasPrefix("|") {
		p.xtake("|")
		p.fws()
		l = append(l, p.xztagcopy())
	}
	return l
}

func (p *parser) xztagcopy() string {
	// ABNF does not mention FWS (unlike for other fields), but FWS is allowed everywhere in the value...
	// ../rfc/6376:1386 ../rfc/6376:1372
	f := p.xhdrName(true)
	p.fws()
	p.xtake(":")
	v := p.xqphdrvalue(true)
	return f + ":" + v
}
