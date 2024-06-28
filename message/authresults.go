package message

import (
	"fmt"
	"strings"

	"github.com/mjl-/mox/dns"
)

// ../rfc/8601:577

// Authentication-Results header, see RFC 8601.
type AuthResults struct {
	Hostname string
	// Optional version of Authentication-Results header, assumed "1" when absent,
	// which is common.
	Version string
	Comment string       // If not empty, header comment without "()", added after Hostname.
	Methods []AuthMethod // Can be empty, in case of "none".
}

// ../rfc/8601:598

// AuthMethod is a result for one authentication method.
//
// Example encoding in the header: "spf=pass smtp.mailfrom=example.net".
type AuthMethod struct {
	// E.g. "dkim", "spf", "iprev", "auth".
	Method  string
	Version string // For optional method version. "1" is implied when missing, which is common.
	Result  string // Each method has a set of known values, e.g. "pass", "temperror", etc.
	Comment string // Optional, message header comment.
	Reason  string // Optional.
	Props   []AuthProp
}

// ../rfc/8601:606

// AuthProp describes properties for an authentication method.
// Each method has a set of known properties.
// Encoded in the header as "type.property=value", e.g. "smtp.mailfrom=example.net"
// for spf.
type AuthProp struct {
	// Valid values maintained at https://www.iana.org/assignments/email-auth/email-auth.xhtml
	Type     string
	Property string
	Value    string
	// Whether value is address-like (localpart@domain, or domain). Or another value,
	// which is subject to escaping.
	IsAddrLike bool
	Comment    string // If not empty, header comment without "()", added after Value.
}

// MakeAuthProp is a convenient way to make an AuthProp.
func MakeAuthProp(typ, property, value string, isAddrLike bool, Comment string) AuthProp {
	return AuthProp{typ, property, value, isAddrLike, Comment}
}

// todo future: we could store fields as dns.Domain, and when we encode as non-ascii also add the ascii version as a comment.

// Header returns an Authentication-Results header, possibly spanning multiple
// lines, always ending in crlf.
func (h AuthResults) Header() string {
	// Escaping of values: ../rfc/8601:684 ../rfc/2045:661

	optComment := func(s string) string {
		if s != "" {
			return " (" + s + ")"
		}
		return s
	}

	w := &HeaderWriter{}
	w.Add("", "Authentication-Results:"+optComment(h.Comment)+" "+value(h.Hostname, false)+";")
	for i, m := range h.Methods {
		w.Newline()

		tokens := []string{}
		addf := func(format string, args ...any) {
			s := fmt.Sprintf(format, args...)
			tokens = append(tokens, s)
		}
		addf("%s=%s", m.Method, m.Result)
		if m.Comment != "" && (m.Reason != "" || len(m.Props) > 0) {
			addf("(%s)", m.Comment)
		}
		if m.Reason != "" {
			addf("reason=%s", value(m.Reason, false))
		}
		for _, p := range m.Props {
			v := value(p.Value, p.IsAddrLike)
			addf("%s.%s=%s%s", p.Type, p.Property, v, optComment(p.Comment))
		}
		for j, t := range tokens {
			var sep string
			if j > 0 {
				sep = " "
			}
			if j == len(tokens)-1 && i < len(h.Methods)-1 {
				t += ";"
			}
			w.Add(sep, t)
		}
	}
	return w.String()
}

func value(s string, isAddrLike bool) string {
	quote := s == ""
	for _, c := range s {
		// utf-8 does not have to be quoted. ../rfc/6532:242
		// Characters outside of tokens do. ../rfc/2045:661
		if c <= ' ' || c == 0x7f || (c == '@' && !isAddrLike) || strings.ContainsRune(`()<>,;:\\"/[]?= `, c) {
			quote = true
			break
		}
	}
	if !quote {
		return s
	}
	r := `"`
	for _, c := range s {
		if c == '"' || c == '\\' {
			r += "\\"
		}
		r += string(c)
	}
	r += `"`
	return r
}

// ParseAuthResults parses a Authentication-Results header value.
//
// Comments are not populated in the returned AuthResults.
// Both crlf and lf line-endings are accepted. The input string must end with
// either crlf or lf.
func ParseAuthResults(s string) (ar AuthResults, err error) {
	// ../rfc/8601:577
	lower := make([]byte, len(s))
	for i, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	p := &parser{s: s, lower: string(lower)}
	defer p.recover(&err)

	p.cfws()
	ar.Hostname = p.xvalue()
	p.cfws()
	ar.Version = p.digits()
	p.cfws()
	for {
		p.xtake(";")
		p.cfws()
		// Yahoo has ";" at the end of the header value, incorrect.
		if !Pedantic && p.end() {
			break
		}
		method := p.xkeyword(false)
		p.cfws()
		if method == "none" {
			if len(ar.Methods) == 0 {
				p.xerrorf("missing results")
			}
			if !p.end() {
				p.xerrorf(`data after "none" result`)
			}
			return
		}
		ar.Methods = append(ar.Methods, p.xresinfo(method))
		p.cfws()
		if p.end() {
			break
		}
	}
	return
}

type parser struct {
	s     string
	lower string // Like s, but with ascii characters lower-cased (utf-8 offsets preserved).
	o     int
}

type parseError struct{ err error }

func (p *parser) recover(err *error) {
	x := recover()
	if x == nil {
		return
	}
	perr, ok := x.(parseError)
	if ok {
		*err = perr.err
		return
	}
	panic(x)
}

func (p *parser) xerrorf(format string, args ...any) {
	panic(parseError{fmt.Errorf(format, args...)})
}

func (p *parser) end() bool {
	return p.s[p.o:] == "\r\n" || p.s[p.o:] == "\n"
}

// ../rfc/5322:599
func (p *parser) cfws() {
	p.fws()
	for p.prefix("(") {
		p.xcomment()
	}
	p.fws()
}

func (p *parser) fws() {
	for p.take(" ") || p.take("\t") {
	}
	opts := []string{"\n ", "\n\t", "\r\n ", "\r\n\t"}
	for _, o := range opts {
		if p.take(o) {
			break
		}
	}
	for p.take(" ") || p.take("\t") {
	}
}

func (p *parser) xcomment() {
	p.xtake("(")
	p.fws()
	for !p.take(")") {
		if p.empty() {
			p.xerrorf("unexpected end in comment")
		}
		if p.prefix("(") {
			p.xcomment()
			p.fws()
			continue
		}
		p.take(`\`)
		if c := p.s[p.o]; c > ' ' && c < 0x7f {
			p.o++
		} else {
			p.xerrorf("bad character %c in comment", c)
		}
		p.fws()
	}
}

func (p *parser) prefix(s string) bool {
	return strings.HasPrefix(p.lower[p.o:], s)
}

func (p *parser) xvalue() string {
	if p.prefix(`"`) {
		return p.xquotedString()
	}
	return p.xtakefn1("value token", func(c rune, i int) bool {
		// ../rfc/2045:661
		// todo: token cannot contain utf-8? not updated in ../rfc/6532. however, we also use it for the localpart & domain parsing, so we'll allow it.
		return c > ' ' && !strings.ContainsRune(`()<>@,;:\\"/[]?= `, c)
	})
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
			p.xerrorf("bad escaped char %c in quoted string", c)
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			return s
		}
		if c >= ' ' && c != '\\' && c != '"' {
			s += string(c)
			continue
		}
		p.xerrorf("invalid quoted string, invalid character %c", c)
	}
}

func (p *parser) digits() string {
	o := p.o
	for o < len(p.s) && p.s[o] >= '0' && p.s[o] <= '9' {
		o++
	}
	p.o = o
	return p.s[o:p.o]
}

func (p *parser) xdigits() string {
	s := p.digits()
	if s == "" {
		p.xerrorf("expected digits, remaining %q", p.s[p.o:])
	}
	return s
}

func (p *parser) xtake(s string) {
	if !p.prefix(s) {
		p.xerrorf("expected %q, remaining %q", s, p.s[p.o:])
	}
	p.o += len(s)
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) take(s string) bool {
	if p.prefix(s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtakefn1(what string, fn func(c rune, i int) bool) string {
	if p.empty() {
		p.xerrorf("need at least one char for %s", what)
	}
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			if i == 0 {
				p.xerrorf("expected at least one char for %s, remaining %q", what, p.s[p.o:])
			}
			s := p.s[p.o : p.o+i]
			p.o += i
			return s
		}
	}
	s := p.s[p.o:]
	p.o = len(p.s)
	return s
}

// ../rfc/5321:2287
func (p *parser) xkeyword(isResult bool) string {
	s := strings.ToLower(p.xtakefn1("keyword", func(c rune, i int) bool {
		// Yahoo sends results like "dkim=perm_fail".
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || isResult && !Pedantic && c == '_'
	}))
	if s == "-" {
		p.xerrorf("missing keyword")
	} else if strings.HasSuffix(s, "-") {
		p.o--
		s = s[:len(s)-1]
	}
	return s
}

func (p *parser) xmethodspec(methodKeyword string) (string, string, string) {
	p.cfws()
	var methodDigits string
	if p.take("/") {
		methodDigits = p.xdigits()
		p.cfws()
	}
	p.xtake("=")
	p.cfws()
	result := p.xkeyword(true)
	return methodKeyword, methodDigits, result
}

func (p *parser) xpropspec() (ap AuthProp) {
	ap.Type = p.xkeyword(false)
	p.cfws()
	p.xtake(".")
	p.cfws()
	if p.take("mailfrom") {
		ap.Property = "mailfrom"
	} else if p.take("rcptto") {
		ap.Property = "rcptto"
	} else {
		ap.Property = p.xkeyword(false)
	}
	p.cfws()
	p.xtake("=")
	ap.IsAddrLike, ap.Value = p.xpvalue()
	return
}

// method keyword has been parsed, method-version not yet.
func (p *parser) xresinfo(methodKeyword string) (am AuthMethod) {
	p.cfws()
	am.Method, am.Version, am.Result = p.xmethodspec(methodKeyword)
	p.cfws()
	if p.take("reason") {
		p.cfws()
		p.xtake("=")
		p.cfws()
		am.Reason = p.xvalue()
	}
	p.cfws()
	for !p.prefix(";") && !p.end() {
		am.Props = append(am.Props, p.xpropspec())
		p.cfws()
	}
	return
}

// todo: could keep track whether this is a localpart.
func (p *parser) xpvalue() (bool, string) {
	p.cfws()
	if p.take("@") {
		// Bare domain.
		dom, _ := p.xdomain()
		return true, "@" + dom
	}
	s := p.xvalue()
	if p.take("@") {
		dom, _ := p.xdomain()
		s += "@" + dom
		return true, s
	}
	return false, s
}

// ../rfc/5321:2291
func (p *parser) xdomain() (string, dns.Domain) {
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
	return s, d
}

// ../rfc/5321:2303
// ../rfc/5321:2303 ../rfc/6531:411
func (p *parser) xsubdomain() string {
	return p.xtakefn1("subdomain", func(c rune, i int) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c == '-' || c > 0x7f
	})
}
