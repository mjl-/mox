package smtp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/moxvar"
)

var ErrBadAddress = errors.New("invalid email address")

// Localpart is a decoded local part of an email address, before the "@".
// For quoted strings, values do not hold the double quote or escaping backslashes.
// An empty string can be a valid localpart.
type Localpart string

// String returns a packed representation of an address, with proper escaping/quoting, for use in SMTP.
func (lp Localpart) String() string {
	// See ../rfc/5321:2322 ../rfc/6531:414
	// First we try as dot-string. If not possible we make a quoted-string.
	dotstr := true
	t := strings.Split(string(lp), ".")
	for _, e := range t {
		for _, c := range e {
			if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c > 0x7f {
				continue
			}
			switch c {
			case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
				continue
			}
			dotstr = false
			break
		}
		dotstr = dotstr && len(e) > 0
	}
	dotstr = dotstr && len(t) > 0
	if dotstr {
		return string(lp)
	}

	// Make quoted-string.
	r := `"`
	for _, b := range lp {
		if b == '"' || b == '\\' {
			r += "\\" + string(b)
		} else {
			r += string(b)
		}
	}
	r += `"`
	return r
}

// LogString returns the localpart as string for use in smtp, and an escaped
// representation if it has non-ascii characters.
func (lp Localpart) LogString() string {
	s := lp.String()
	qs := strconv.QuoteToASCII(s)
	if qs != `"`+s+`"` {
		s = "/" + qs
	}
	return s
}

// DSNString returns the localpart as string for use in a DSN.
// utf8 indicates if the remote MTA supports utf8 messaging. If not, the 7bit DSN
// encoding for "utf-8-addr-xtext" from RFC 6533 is used.
func (lp Localpart) DSNString(utf8 bool) string {
	if utf8 {
		return lp.String()
	}
	// ../rfc/6533:259
	r := ""
	for _, c := range lp {
		if c > 0x20 && c < 0x7f && c != '\\' && c != '+' && c != '=' {
			r += string(c)
		} else {
			r += fmt.Sprintf(`\x{%x}`, c)
		}
	}
	return r
}

// IsInternational returns if this is an internationalized local part, i.e. has
// non-ASCII characters.
func (lp Localpart) IsInternational() bool {
	for _, c := range lp {
		if c > 0x7f {
			return true
		}
	}
	return false
}

// Address is a parsed email address.
type Address struct {
	Localpart Localpart
	Domain    dns.Domain // todo: shouldn't we accept an ip address here too? and merge this type into smtp.Path.
}

// NewAddress returns an address.
func NewAddress(localpart Localpart, domain dns.Domain) Address {
	return Address{localpart, domain}
}

func (a Address) Path() Path {
	return Path{Localpart: a.Localpart, IPDomain: dns.IPDomain{Domain: a.Domain}}
}

func (a Address) IsZero() bool {
	return a == Address{}
}

// Pack returns the address in string form. If smtputf8 is true, the domain is
// formatted with non-ASCII characters. If localpart has non-ASCII characters,
// they are returned regardless of smtputf8.
func (a Address) Pack(smtputf8 bool) string {
	if a.IsZero() {
		return ""
	}
	return a.Localpart.String() + "@" + a.Domain.XName(smtputf8)
}

// String returns the address in string form with non-ASCII characters.
func (a Address) String() string {
	if a.IsZero() {
		return ""
	}
	return a.Localpart.String() + "@" + a.Domain.Name()
}

// LogString returns the address with with utf-8 in localpart and/or domain. In
// case of an IDNA domain and/or quotable characters in the localpart, an address
// with quoted/escaped localpart and ASCII domain is also returned.
func (a Address) LogString() string {
	if a.IsZero() {
		return ""
	}
	s := a.Pack(true)
	lp := a.Localpart.String()
	qlp := strconv.QuoteToASCII(lp)
	escaped := qlp != `"`+lp+`"`
	if a.Domain.Unicode != "" || escaped {
		if escaped {
			lp = qlp
		}
		s += "/" + lp + "@" + a.Domain.ASCII
	}
	return s
}

// ParseAddress parses an email address. UTF-8 is allowed.
// Returns ErrBadAddress for invalid addresses.
func ParseAddress(s string) (address Address, err error) {
	lp, rem, err := parseLocalPart(s)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %s", ErrBadAddress, err)
	}
	if !strings.HasPrefix(rem, "@") {
		return Address{}, fmt.Errorf("%w: expected @", ErrBadAddress)
	}
	rem = rem[1:]
	d, err := dns.ParseDomain(rem)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %s", ErrBadAddress, err)
	}
	return Address{lp, d}, err
}

var ErrBadLocalpart = errors.New("invalid localpart")

// ParseLocalpart parses the local part.
// UTF-8 is allowed.
// Returns ErrBadAddress for invalid addresses.
func ParseLocalpart(s string) (localpart Localpart, err error) {
	lp, rem, err := parseLocalPart(s)
	if err != nil {
		return "", err
	}
	if rem != "" {
		return "", fmt.Errorf("%w: remaining after localpart: %q", ErrBadLocalpart, rem)
	}
	return lp, nil
}

func parseLocalPart(s string) (localpart Localpart, remain string, err error) {
	p := &parser{s, 0}

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		e, ok := x.(error)
		if !ok {
			panic(x)
		}
		err = fmt.Errorf("%w: %s", ErrBadLocalpart, e)
	}()

	lp := p.xlocalpart()
	return lp, p.remainder(), nil
}

type parser struct {
	s string
	o int
}

func (p *parser) xerrorf(format string, args ...any) {
	panic(fmt.Errorf(format, args...))
}

func (p *parser) hasPrefix(s string) bool {
	return strings.HasPrefix(p.s[p.o:], s)
}

func (p *parser) take(s string) bool {
	if p.hasPrefix(s) {
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

func (p *parser) empty() bool {
	return p.o == len(p.s)
}

func (p *parser) xtaken(n int) string {
	r := p.s[p.o : p.o+n]
	p.o += n
	return r
}

func (p *parser) remainder() string {
	r := p.s[p.o:]
	p.o = len(p.s)
	return r
}

// todo: reduce duplication between implementations: ../smtp/address.go:/xlocalpart ../dkim/parser.go:/xlocalpart ../smtpserver/parse.go:/xlocalpart
func (p *parser) xlocalpart() Localpart {
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
	if moxvar.Pedantic && len(s) > 64 || len(s) > 128 {
		// ../rfc/5321:3486
		p.xerrorf("localpart longer than 64 octets")
	}
	return Localpart(s)
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
		// todo: should we be accepting utf8 for quoted strings?
		if c >= ' ' && c < 0x7f && c != '\\' && c != '"' || c > 0x7f {
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
		p.o = len(p.s)
	} else {
		p.o += o
	}
	return r
}

func (p *parser) takefn1(what string, fn func(c rune, i int) bool) string {
	if p.empty() {
		p.xerrorf("need at least one char for %s", what)
	}
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			if i == 0 {
				p.xerrorf("expected at least one char for %s, got char %c", what, c)
			}
			return p.xtaken(i)
		}
	}
	return p.remainder()
}

func (p *parser) xatom() string {
	return p.takefn1("atom", func(c rune, i int) bool {
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
			return true
		}
		return isalphadigit(c) || c > 0x7f
	})
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
