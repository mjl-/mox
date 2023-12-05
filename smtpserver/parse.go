package smtpserver

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

// Parser holds the original string and string with ascii a-z upper-cased for easy
// case-insensitive parsing.
type parser struct {
	orig              string
	upper             string
	o                 int  // Offset into orig/upper.
	smtputf8          bool // Whether SMTPUTF8 extension is enabled, making IDNA domains and utf8 localparts valid.
	conn              *conn
	utf8LocalpartCode int // If non-zero, error for utf-8 localpart when smtputf8 not enabled.
}

// toUpper upper cases bytes that are a-z. strings.ToUpper does too much. and
// would replace invalid bytes with unicode replacement characters, which would
// break our requirement that offsets into the original and upper case strings
// point to the same character.
func toUpper(s string) string {
	r := []byte(s)
	for i, c := range r {
		if c >= 'a' && c <= 'z' {
			r[i] = c - 0x20
		}
	}
	return string(r)
}

func newParser(s string, smtputf8 bool, conn *conn) *parser {
	return &parser{orig: s, upper: toUpper(s), smtputf8: smtputf8, conn: conn}
}

func (p *parser) xerrorf(format string, args ...any) {
	// For submission, send the remaining unparsed line. Otherwise, only log it.
	var err error
	errmsg := "bad syntax: " + fmt.Sprintf(format, args...)
	remaining := fmt.Sprintf(" (remaining %q)", p.orig[p.o:])
	if p.conn.account != nil {
		errmsg += remaining
		err = errors.New(errmsg)
	} else {
		err = errors.New(errmsg + remaining)
	}

	// ../rfc/5321:2377
	panic(smtpError{smtp.C501BadParamSyntax, smtp.SeProto5Syntax2, errmsg, err, false, true})
}

func (p *parser) xutf8localparterrorf() {
	code := p.utf8LocalpartCode
	if code == 0 {
		code = smtp.C550MailboxUnavail
	}
	// ../rfc/6531:466
	xsmtpUserErrorf(code, smtp.SeMsg6NonASCIIAddrNotPermitted7, "non-ascii address not permitted without smtputf8")
}

func (p *parser) empty() bool {
	return p.o == len(p.orig)
}

// note: use xend() for check for end of line with remaining white space, to be used by commands.
func (p *parser) xempty() {
	if p.o != len(p.orig) {
		p.xerrorf("expected end of line")
	}
}

// check we are at the end of a command.
func (p *parser) xend() {
	// For submission, we are strict.
	if p.conn.submission {
		p.xempty()
	}
	// Otherwise we allow trailing white space. ../rfc/5321:1758
	rem := p.remainder()
	for _, c := range rem {
		if c != ' ' && c != '\t' {
			p.xerrorf("trailing data, not white space: %q", rem)
		}
	}
}

func (p *parser) hasPrefix(s string) bool {
	return strings.HasPrefix(p.upper[p.o:], s)
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

func (p *parser) space() bool {
	return p.take(" ")
}

func (p *parser) xspace() {
	p.xtake(" ")
}

func (p *parser) xtaken(n int) string {
	r := p.orig[p.o : p.o+n]
	p.o += n
	return r
}

func (p *parser) remainder() string {
	r := p.orig[p.o:]
	p.o = len(p.orig)
	return r
}

func (p *parser) peekchar() rune {
	for _, c := range p.upper[p.o:] {
		return c
	}
	return -1
}

func (p *parser) takefn1(what string, fn func(c rune, i int) bool) string {
	if p.empty() {
		p.xerrorf("need at least one char for %s", what)
	}
	for i, c := range p.upper[p.o:] {
		if !fn(c, i) {
			if i == 0 {
				p.xerrorf("expected at least one char for %s", what)
			}
			return p.xtaken(i)
		}
	}
	return p.remainder()
}

func (p *parser) takefn1case(what string, fn func(c rune, i int) bool) string {
	if p.empty() {
		p.xerrorf("need at least one char for %s", what)
	}
	for i, c := range p.orig[p.o:] {
		if !fn(c, i) {
			if i == 0 {
				p.xerrorf("expected at least one char for %s", what)
			}
			return p.xtaken(i)
		}
	}
	return p.remainder()
}

func (p *parser) takefn(fn func(c rune, i int) bool) string {
	for i, c := range p.upper[p.o:] {
		if !fn(c, i) {
			return p.xtaken(i)
		}
	}
	return p.remainder()
}

// xrawReversePath returns the raw string between the <>'s. We cannot parse it
// immediately, because if this is an IDNA (internationalization) address, we would
// only see the SMTPUTF8 indicator after having parsed the reverse path here. So we
// parse the raw data here, and validate it after having seen all parameters.
// ../rfc/5321:2260
func (p *parser) xrawReversePath() string {
	p.xtake("<")
	s := p.takefn(func(c rune, i int) bool {
		return c != '>'
	})
	p.xtake(">")
	return s
}

// xbareReversePath parses a reverse-path without <>, as returned by
// xrawReversePath. It takes smtputf8 into account.
// ../rfc/5321:2260
func (p *parser) xbareReversePath() smtp.Path {
	if p.empty() {
		return smtp.Path{}
	}
	// ../rfc/6531:468
	p.utf8LocalpartCode = smtp.C550MailboxUnavail
	defer func() {
		p.utf8LocalpartCode = 0
	}()
	return p.xbarePath()
}

func (p *parser) xforwardPath() smtp.Path {
	// ../rfc/6531:466
	p.utf8LocalpartCode = smtp.C553BadMailbox
	defer func() {
		p.utf8LocalpartCode = 0
	}()
	return p.xpath()
}

// ../rfc/5321:2264
func (p *parser) xpath() smtp.Path {
	o := p.o
	p.xtake("<")
	r := p.xbarePath()
	p.xtake(">")
	if p.o-o > 256 {
		// ../rfc/5321:3495
		p.xerrorf("path longer than 256 octets")
	}
	return r
}

func (p *parser) xbarePath() smtp.Path {
	// We parse but ignore any source routing.
	// ../rfc/5321:1081 ../rfc/5321:1430 ../rfc/5321:1925
	if p.take("@") {
		p.xdomain()
		for p.take(",") {
			p.xtake("@")
			p.xdomain()
		}
		p.xtake(":")
	}
	return p.xmailbox()
}

// ../rfc/5321:2291
func (p *parser) xdomain() dns.Domain {
	s := p.xsubdomain()
	for p.take(".") {
		s += "." + p.xsubdomain()
	}
	d, err := dns.ParseDomain(s)
	if err != nil {
		p.xerrorf("parsing domain name %q: %s", s, err)
	}
	if len(s) > 255 {
		// ../rfc/5321:3491
		p.xerrorf("domain longer than 255 octets")
	}
	return d
}

// ../rfc/5321:2303
// ../rfc/5321:2303 ../rfc/6531:411
func (p *parser) xsubdomain() string {
	return p.takefn1("subdomain", func(c rune, i int) bool {
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || i > 0 && c == '-' || c > 0x7f && p.smtputf8
	})
}

// ../rfc/5321:2314
func (p *parser) xmailbox() smtp.Path {
	localpart := p.xlocalpart()
	p.xtake("@")
	return smtp.Path{Localpart: localpart, IPDomain: p.xipdomain(false)}
}

// ../rfc/5321:2307
func (p *parser) xldhstr() string {
	return p.takefn1("ldh-str", func(c rune, i int) bool {
		return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i == 0 && c == '-'
	})
}

// parse address-literal or domain.
func (p *parser) xipdomain(isehlo bool) dns.IPDomain {
	// ../rfc/5321:2309
	// ../rfc/5321:2397
	if p.take("[") {
		c := p.peekchar()
		var ipv6 bool
		if !(c >= '0' && c <= '9') {
			addrlit := p.xldhstr()
			p.xtake(":")
			if !strings.EqualFold(addrlit, "IPv6") {
				p.xerrorf("unrecognized address literal %q", addrlit)
			}
			ipv6 = true
		}
		ipaddr := p.takefn1("address literal", func(c rune, i int) bool {
			return c != ']'
		})
		p.take("]")
		ip := net.ParseIP(ipaddr)
		if ip == nil {
			p.xerrorf("invalid ip in address: %q", ipaddr)
		}
		isv4 := ip.To4() != nil
		isAllowedSloppyIPv6Submission := func() bool {
			// Mail user agents that submit are relatively likely to use IPs in EHLO and forget
			// that an IPv6 address needs to be tagged as such. We can forgive them. For
			// SMTP servers we are strict.
			return isehlo && p.conn.submission && !mox.Pedantic && ip.To16() != nil
		}
		if ipv6 && isv4 {
			p.xerrorf("ip address is not ipv6")
		} else if !ipv6 && !isv4 && !isAllowedSloppyIPv6Submission() {
			if ip.To16() != nil {
				p.xerrorf("ip address is ipv6, must use syntax [IPv6:...]")
			} else {
				p.xerrorf("ip address is not ipv4")
			}
		}
		return dns.IPDomain{IP: ip}
	}
	return dns.IPDomain{Domain: p.xdomain()}
}

// todo: reduce duplication between implementations: ../smtp/address.go:/xlocalpart ../dkim/parser.go:/xlocalpart ../smtpserver/parse.go:/xlocalpart
func (p *parser) xlocalpart() smtp.Localpart {
	// ../rfc/5321:2316
	var s string
	if p.hasPrefix(`"`) {
		s = p.xquotedString(true)
	} else {
		s = p.xatom(true)
		for p.take(".") {
			s += "." + p.xatom(true)
		}
	}
	// In the wild, some services use large localparts for generated (bounce) addresses.
	if mox.Pedantic && len(s) > 64 || len(s) > 128 {
		// ../rfc/5321:3486
		p.xerrorf("localpart longer than 64 octets")
	}
	return smtp.Localpart(s)
}

// ../rfc/5321:2324
func (p *parser) xquotedString(islocalpart bool) string {
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
		// ../rfc/5321:2332 ../rfc/6531:419
		if islocalpart && c > 0x7f && !p.smtputf8 {
			p.xutf8localparterrorf()
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
	for i, c := range p.orig[p.o:] {
		if i > 0 {
			o = i
			break
		}
		r = c
	}
	if o == 0 {
		p.o = len(p.orig)
	} else {
		p.o += o
	}
	return r
}

// ../rfc/5321:2320 ../rfc/6531:414
func (p *parser) xatom(islocalpart bool) string {
	return p.takefn1("atom", func(c rune, i int) bool {
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
			return true
		}
		if islocalpart && c > 0x7f && !p.smtputf8 {
			p.xutf8localparterrorf()
		}
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || (c > 0x7f && p.smtputf8)
	})
}

// ../rfc/5321:2338
func (p *parser) xstring() string {
	if p.peekchar() == '"' {
		return p.xquotedString(false)
	}
	return p.xatom(false)
}

// ../rfc/5321:2279
func (p *parser) xparamKeyword() string {
	return p.takefn1("parameter keyword", func(c rune, i int) bool {
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || (i > 0 && c == '-')
	})
}

// ../rfc/5321:2281 ../rfc/6531:422
func (p *parser) xparamValue() string {
	return p.takefn1("parameter value", func(c rune, i int) bool {
		return c > ' ' && c < 0x7f && c != '=' || (c > 0x7f && p.smtputf8)
	})
}

// for smtp parameters that take a numeric parameter with specified number of
// digits, eg SIZE=... for MAIL FROM.
func (p *parser) xnumber(maxDigits int) int64 {
	s := p.takefn1("number", func(c rune, i int) bool {
		return c >= '0' && c <= '9' && i < maxDigits
	})
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		p.xerrorf("bad number %q: %s", s, err)
	}
	return v
}

// sasl mechanism, for AUTH command.
// ../rfc/4422:436
func (p *parser) xsaslMech() string {
	return p.takefn1case("sasl-mech", func(c rune, i int) bool {
		return i < 20 && (c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	})
}

// ../rfc/4954:696 ../rfc/6533:259
func (p *parser) xtext() string {
	r := ""
	for !p.empty() {
		b := p.orig[p.o]
		if b >= 0x21 && b < 0x7f && b != '+' && b != '=' && b != ' ' {
			r += string(b)
			p.xtaken(1)
			continue
		}
		if b != '+' {
			break
		}
		p.xtaken(1)
		x := p.xtaken(2)
		for _, b := range x {
			if b >= '0' && b <= '9' || b >= 'A' && b <= 'F' {
				continue
			}
			p.xerrorf("parsing xtext: invalid hexadecimal %q", x)
		}
		const hex = "0123456789ABCDEF"
		b = byte(strings.IndexByte(hex, x[0])<<4) | byte(strings.IndexByte(hex, x[1])<<0)
		r += string(rune(b))
	}
	return r
}
