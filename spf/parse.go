package spf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Record is a parsed SPF DNS record.
//
// An example record for example.com:
//
//	v=spf1 +mx a:colo.example.com/28 -all
type Record struct {
	Version     string      // Must be "spf1".
	Directives  []Directive // An IP is evaluated against each directive until a match is found.
	Redirect    string      // Modifier that redirects SPF checks to other domain after directives did not match. Optional. For "redirect=".
	Explanation string      // Modifier for creating a user-friendly error message when an IP results in status "fail".
	Other       []Modifier  // Other modifiers.
}

// Directive consists of a mechanism that describes how to check if an IP matches,
// an (optional) qualifier indicating the policy for a match, and optional
// parameters specific to the mechanism.
type Directive struct {
	Qualifier  string // Sets the result if this directive matches. "" and "+" are "pass", "-" is "fail", "?" is "neutral", "~" is "softfail".
	Mechanism  string // "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists".
	DomainSpec string // For include, a, mx, ptr, exists. Always in lower-case when parsed using ParseRecord.
	IP         net.IP `json:"-"` // For ip4, ip6.
	IPstr      string // Original string for IP, always with /subnet.
	IP4CIDRLen *int   // For a, mx, ip4.
	IP6CIDRLen *int   // For a, mx, ip6.
}

// MechanismString returns a directive in string form for use in the Received-SPF header.
func (d Directive) MechanismString() string {
	s := d.Qualifier + d.Mechanism
	if d.DomainSpec != "" {
		s += ":" + d.DomainSpec
	} else if d.IP != nil {
		s += ":" + d.IP.String()
	}
	if d.IP4CIDRLen != nil {
		s += fmt.Sprintf("/%d", *d.IP4CIDRLen)
	}
	if d.IP6CIDRLen != nil {
		if d.Mechanism != "ip6" {
			s += "/"
		}
		s += fmt.Sprintf("/%d", *d.IP6CIDRLen)
	}
	return s
}

// Modifier provides additional information for a policy.
// "redirect" and "exp" are not represented as a Modifier but explicitly in a Record.
type Modifier struct {
	Key   string // Key is case-insensitive.
	Value string
}

// Record returns an DNS record, to be configured as a TXT record for a domain,
// e.g. a TXT record for example.com.
func (r Record) Record() (string, error) {
	b := &strings.Builder{}
	b.WriteString("v=")
	b.WriteString(r.Version)
	for _, d := range r.Directives {
		b.WriteString(" " + d.MechanismString())
	}
	if r.Redirect != "" {
		fmt.Fprintf(b, " redirect=%s", r.Redirect)
	}
	if r.Explanation != "" {
		fmt.Fprintf(b, " exp=%s", r.Explanation)
	}
	for _, m := range r.Other {
		fmt.Fprintf(b, " %s=%s", m.Key, m.Value)
	}
	return b.String(), nil
}

type parser struct {
	s     string
	lower string
	o     int
}

type parseError string

func (e parseError) Error() string {
	return string(e)
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

// ParseRecord parses an SPF DNS TXT record.
func ParseRecord(s string) (r *Record, isspf bool, rerr error) {
	p := parser{s: s, lower: toLower(s)}

	r = &Record{
		Version: "spf1",
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(parseError); ok {
			rerr = err
			return
		}
		panic(x)
	}()

	p.xtake("v=spf1")
	for !p.empty() {
		p.xtake(" ")
		isspf = true // ../rfc/7208:825
		for p.take(" ") {
		}
		if p.empty() {
			break
		}

		qualifier := p.takelist("+", "-", "?", "~")
		mechanism := p.takelist("all", "include:", "a", "mx", "ptr", "ip4:", "ip6:", "exists:")
		if qualifier != "" && mechanism == "" {
			p.xerrorf("expected mechanism after qualifier")
		}
		if mechanism == "" {
			// ../rfc/7208:2597
			modifier := p.takelist("redirect=", "exp=")
			if modifier == "" {
				// ../rfc/7208:2600
				name := p.xtakefn1(func(c rune, i int) bool {
					alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
					return alpha || i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.')
				})
				p.xtake("=")
				v := p.xmacroString(true)
				r.Other = append(r.Other, Modifier{name, v})
				continue
			}
			v := p.xdomainSpec(true)
			modifier = strings.TrimSuffix(modifier, "=")
			if modifier == "redirect" {
				if r.Redirect != "" {
					// ../rfc/7208:1419
					p.xerrorf("duplicate redirect modifier")
				}
				r.Redirect = v
			}
			if modifier == "exp" {
				if r.Explanation != "" {
					// ../rfc/7208:1419
					p.xerrorf("duplicate exp modifier")
				}
				r.Explanation = v
			}
			continue
		}
		// ../rfc/7208:2585
		d := Directive{
			Qualifier: qualifier,
			Mechanism: strings.TrimSuffix(mechanism, ":"),
		}
		switch d.Mechanism {
		case "all":
		case "include":
			d.DomainSpec = p.xdomainSpec(false)
		case "a", "mx":
			if p.take(":") {
				d.DomainSpec = p.xdomainSpec(false)
			}
			if p.take("/") {
				if !p.take("/") {
					num, _ := p.xnumber()
					if num > 32 {
						p.xerrorf("invalid ip4 cidr length %d", num)
					}
					d.IP4CIDRLen = &num
					if !p.take("//") {
						break
					}
				}
				num, _ := p.xnumber()
				if num > 128 {
					p.xerrorf("invalid ip6 cidr length %d", num)
				}
				d.IP6CIDRLen = &num
			}
		case "ptr":
			if p.take(":") {
				d.DomainSpec = p.xdomainSpec(false)
			}
		case "ip4":
			d.IP, d.IPstr = p.xip4address()
			if p.take("/") {
				num, _ := p.xnumber()
				if num > 32 {
					p.xerrorf("invalid ip4 cidr length %d", num)
				}
				d.IP4CIDRLen = &num
				d.IPstr += fmt.Sprintf("/%d", num)
			} else {
				d.IPstr += "/32"
			}
		case "ip6":
			d.IP, d.IPstr = p.xip6address()
			if p.take("/") {
				num, _ := p.xnumber()
				if num > 128 {
					p.xerrorf("invalid ip6 cidr length %d", num)
				}
				d.IP6CIDRLen = &num
				d.IPstr += fmt.Sprintf("/%d", num)
			} else {
				d.IPstr += "/128"
			}
		case "exists":
			d.DomainSpec = p.xdomainSpec(false)
		default:
			return nil, true, fmt.Errorf("internal error, missing case for mechanism %q", d.Mechanism)
		}
		r.Directives = append(r.Directives, d)
	}
	return r, true, nil
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !p.empty() {
		msg += fmt.Sprintf(" (leftover %q)", p.s[p.o:])
	}
	panic(parseError(msg))
}

// operates on original-cased characters.
func (p *parser) xtakefn1(fn func(rune, int) bool) string {
	r := ""
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			break
		}
		r += string(c)
	}
	if r == "" {
		p.xerrorf("need at least 1 char")
	}
	p.o += len(r)
	return r
}

// caller should set includingSlash to false when parsing "a" or "mx", or the / would be consumed as valid macro literal.
func (p *parser) xdomainSpec(includingSlash bool) string {
	// ../rfc/7208:1579
	// This also consumes the "domain-end" part, which we check below.
	s := p.xmacroString(includingSlash)

	// The ABNF says s must either end in macro-expand, or "." toplabel ["."]. The
	// toplabel rule implies the intention is to force a valid DNS name. We cannot just
	// check if the name is valid, because "macro-expand" is not a valid label. So we
	// recognize the macro-expand, and check for valid toplabel otherwise, because we
	// syntax errors must result in Permerror.
	for _, suf := range []string{"%%", "%_", "%-", "}"} {
		// The check for "}" assumes a "%{" precedes it...
		if strings.HasSuffix(s, suf) {
			return s
		}
	}
	tl := strings.Split(strings.TrimSuffix(s, "."), ".")
	t := tl[len(tl)-1]
	if t == "" {
		p.xerrorf("invalid empty toplabel")
	}
	nums := 0
	for i, c := range t {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
			nums++
		case c == '-':
			if i == 0 {
				p.xerrorf("bad toplabel, invalid leading dash")
			}
			if i == len(t)-1 {
				p.xerrorf("bad toplabel, invalid trailing dash")
			}
		default:
			p.xerrorf("bad toplabel, invalid character")
		}
	}
	if nums == len(t) {
		p.xerrorf("bad toplabel, cannot be all digits")
	}
	return s
}

func (p *parser) xmacroString(includingSlash bool) string {
	// ../rfc/7208:1588
	r := ""
	for !p.empty() {
		w := p.takelist("%{", "%%", "%_", "%-") // "macro-expand"
		if w == "" {
			// "macro-literal"
			if !p.empty() {
				b := p.peekchar()
				if b > ' ' && b < 0x7f && b != '%' && (includingSlash || b != '/') {
					r += string(b)
					p.o++
					continue
				}
			}
			break
		}
		r += w
		if w != "%{" {
			continue
		}
		r += p.xtakelist("s", "l", "o", "d", "i", "p", "h", "c", "r", "t", "v") // "macro-letter"
		digits := p.digits()
		if digits != "" {
			if v, err := strconv.Atoi(digits); err != nil {
				p.xerrorf("bad digits: %v", err)
			} else if v == 0 {
				p.xerrorf("bad digits 0 for 0 labels")
			}
		}
		r += digits
		if p.take("r") {
			r += "r"
		}
		for {
			delimiter := p.takelist(".", "-", "+", ",", "/", "_", "=")
			if delimiter == "" {
				break
			}
			r += delimiter
		}
		r += p.xtake("}")
	}
	return r
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

// returns next original-cased character.
func (p *parser) peekchar() byte {
	return p.s[p.o]
}

func (p *parser) xtakelist(l ...string) string {
	w := p.takelist(l...)
	if w == "" {
		p.xerrorf("no match for %v", l)
	}
	return w
}

func (p *parser) takelist(l ...string) string {
	for _, w := range l {
		if strings.HasPrefix(p.lower[p.o:], w) {
			p.o += len(w)
			return w
		}
	}
	return ""
}

// digits parses zero or more digits.
func (p *parser) digits() string {
	r := ""
	for !p.empty() {
		b := p.peekchar()
		if b >= '0' && b <= '9' {
			r += string(b)
			p.o++
		} else {
			break
		}
	}
	return r
}

func (p *parser) take(s string) bool {
	if strings.HasPrefix(p.lower[p.o:], s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtake(s string) string {
	ok := p.take(s)
	if !ok {
		p.xerrorf("expected %q", s)
	}
	return s
}

func (p *parser) xnumber() (int, string) {
	s := p.digits()
	if s == "" {
		p.xerrorf("expected number")
	}
	if s == "0" {
		return 0, s
	}
	if strings.HasPrefix(s, "0") {
		p.xerrorf("bogus leading 0 in number")
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		p.xerrorf("parsing number for %q: %s", s, err)
	}
	return v, s
}

func (p *parser) xip4address() (net.IP, string) {
	// ../rfc/7208:2607
	ip4num := func() (byte, string) {
		v, vs := p.xnumber()
		if v > 255 {
			p.xerrorf("bad ip4 number %d", v)
		}
		return byte(v), vs
	}
	a, as := ip4num()
	p.xtake(".")
	b, bs := ip4num()
	p.xtake(".")
	c, cs := ip4num()
	p.xtake(".")
	d, ds := ip4num()
	return net.IPv4(a, b, c, d), as + "." + bs + "." + cs + "." + ds
}

func (p *parser) xip6address() (net.IP, string) {
	// ../rfc/7208:2614
	// We just take in a string that has characters that IPv6 uses, then parse it.
	s := p.xtakefn1(func(c rune, i int) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.'
	})
	ip := net.ParseIP(s)
	if ip == nil {
		p.xerrorf("ip6 address %q not valid", s)
	}
	return ip, s
}
