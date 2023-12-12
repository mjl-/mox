package dmarc

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type parseErr string

func (e parseErr) Error() string {
	return string(e)
}

// ParseRecord parses a DMARC TXT record.
//
// Fields and values are are case-insensitive in DMARC are returned in lower case
// for easy comparison.
//
// DefaultRecord provides default values for tags not present in s.
//
// isdmarc indicates if the record starts tag "v" with value "DMARC1", and should
// be treated as a valid DMARC record. Used to detect possibly multiple DMARC
// records (invalid) for a domain with multiple TXT record (quite common).
func ParseRecord(s string) (record *Record, isdmarc bool, rerr error) {
	return parseRecord(s, true)
}

// ParseRecordNoRequired is like ParseRecord, but don't check for required fields
// for regular DMARC records. Useful for checking the _report._dmarc record,
// used for opting into receiving reports for other domains.
func ParseRecordNoRequired(s string) (record *Record, isdmarc bool, rerr error) {
	return parseRecord(s, false)
}

func parseRecord(s string, checkRequired bool) (record *Record, isdmarc bool, rerr error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(parseErr); ok {
			rerr = err
			return
		}
		panic(x)
	}()

	r := DefaultRecord
	p := newParser(s)

	// v= is required and must be first. ../rfc/7489:1099
	p.xtake("v")
	p.wsp()
	p.xtake("=")
	p.wsp()
	r.Version = p.xtakecase("DMARC1")
	p.wsp()
	p.xtake(";")
	isdmarc = true
	seen := map[string]bool{}
	for {
		p.wsp()
		if p.empty() {
			break
		}
		W := p.xword()
		w := strings.ToLower(W)
		if seen[w] {
			// RFC does not say anything about duplicate tags. They can only confuse, so we
			// don't allow them.
			p.xerrorf("duplicate tag %q", W)
		}
		seen[w] = true
		p.wsp()
		p.xtake("=")
		p.wsp()
		switch w {
		default:
			// ../rfc/7489:924 implies that we should know how to parse unknown tags.
			// The formal definition at ../rfc/7489:1127 does not allow for unknown tags.
			// We just parse until the next semicolon or end.
			for !p.empty() {
				if p.peek(';') {
					break
				}
				p.xtaken(1)
			}
		case "p":
			if len(seen) != 1 {
				// ../rfc/7489:1105
				p.xerrorf("p= (policy) must be first tag")
			}
			r.Policy = DMARCPolicy(p.xtakelist("none", "quarantine", "reject"))
		case "sp":
			r.SubdomainPolicy = DMARCPolicy(p.xkeyword())
			// note: we check if the value is valid before returning.
		case "rua":
			r.AggregateReportAddresses = append(r.AggregateReportAddresses, p.xuri())
			p.wsp()
			for p.take(",") {
				p.wsp()
				r.AggregateReportAddresses = append(r.AggregateReportAddresses, p.xuri())
				p.wsp()
			}
		case "ruf":
			r.FailureReportAddresses = append(r.FailureReportAddresses, p.xuri())
			p.wsp()
			for p.take(",") {
				p.wsp()
				r.FailureReportAddresses = append(r.FailureReportAddresses, p.xuri())
				p.wsp()
			}
		case "adkim":
			r.ADKIM = Align(p.xtakelist("r", "s"))
		case "aspf":
			r.ASPF = Align(p.xtakelist("r", "s"))
		case "ri":
			r.AggregateReportingInterval = p.xnumber()
		case "fo":
			r.FailureReportingOptions = []string{p.xtakelist("0", "1", "d", "s")}
			p.wsp()
			for p.take(":") {
				p.wsp()
				r.FailureReportingOptions = append(r.FailureReportingOptions, p.xtakelist("0", "1", "d", "s"))
				p.wsp()
			}
		case "rf":
			r.ReportingFormat = []string{p.xkeyword()}
			p.wsp()
			for p.take(":") {
				p.wsp()
				r.ReportingFormat = append(r.ReportingFormat, p.xkeyword())
				p.wsp()
			}
		case "pct":
			r.Percentage = p.xnumber()
			if r.Percentage > 100 {
				p.xerrorf("bad percentage %d", r.Percentage)
			}
		}
		p.wsp()
		if !p.take(";") && !p.empty() {
			p.xerrorf("expected ;")
		}
	}

	// ../rfc/7489:1106 says "p" is required, but ../rfc/7489:1407 implies we must be
	// able to parse a record without a "p" or with invalid "sp" tag.
	sp := r.SubdomainPolicy
	if checkRequired && (!seen["p"] || sp != PolicyEmpty && sp != PolicyNone && sp != PolicyQuarantine && sp != PolicyReject) {
		if len(r.AggregateReportAddresses) > 0 {
			r.Policy = PolicyNone
			r.SubdomainPolicy = PolicyEmpty
		} else {
			p.xerrorf("invalid (subdomain)policy and no valid aggregate reporting address")
		}
	}

	return &r, true, nil
}

type parser struct {
	s     string
	lower string
	o     int
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

func newParser(s string) *parser {
	return &parser{
		s:     s,
		lower: toLower(s),
	}
}

func (p *parser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.o < len(p.s) {
		msg += fmt.Sprintf(" (remain %q)", p.s[p.o:])
	}
	panic(parseErr(msg))
}

func (p *parser) empty() bool {
	return p.o >= len(p.s)
}

func (p *parser) peek(b byte) bool {
	return p.o < len(p.s) && p.s[p.o] == b
}

// case insensitive prefix
func (p *parser) prefix(s string) bool {
	return strings.HasPrefix(p.lower[p.o:], s)
}

func (p *parser) take(s string) bool {
	if p.prefix(s) {
		p.o += len(s)
		return true
	}
	return false
}

func (p *parser) xtaken(n int) string {
	r := p.lower[p.o : p.o+n]
	p.o += n
	return r
}

func (p *parser) xtake(s string) string {
	if !p.prefix(s) {
		p.xerrorf("expected %q", s)
	}
	return p.xtaken(len(s))
}

func (p *parser) xtakecase(s string) string {
	if !strings.HasPrefix(p.s[p.o:], s) {
		p.xerrorf("expected %q", s)
	}
	r := p.s[p.o : p.o+len(s)]
	p.o += len(s)
	return r
}

// *WSP
func (p *parser) wsp() {
	for !p.empty() && (p.s[p.o] == ' ' || p.s[p.o] == '\t') {
		p.o++
	}
}

// take one of the strings in l.
func (p *parser) xtakelist(l ...string) string {
	for _, s := range l {
		if p.prefix(s) {
			return p.xtaken(len(s))
		}
	}
	p.xerrorf("expected on one %v", l)
	panic("not reached")
}

func (p *parser) xtakefn1case(fn func(byte, int) bool) string {
	for i, b := range []byte(p.lower[p.o:]) {
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
	r := p.s[p.o:]
	p.o += len(r)
	return r
}

// used for the tag keys.
func (p *parser) xword() string {
	return p.xtakefn1case(func(c byte, i int) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	})
}

func (p *parser) xdigits() string {
	return p.xtakefn1case(func(b byte, i int) bool {
		return isdigit(b)
	})
}

// ../rfc/7489:883
// Syntax: ../rfc/7489:1132
func (p *parser) xuri() URI {
	// Ideally, we would simply parse an URI here. But a URI can contain a semicolon so
	// could consume the rest of the DMARC record. Instead, we'll assume no one uses
	// semicolons in URIs in DMARC records and first collect
	// space/comma/semicolon/end-separated characters, then parse.
	// ../rfc/3986:684
	v := p.xtakefn1case(func(b byte, i int) bool {
		return b != ',' && b != ' ' && b != '\t' && b != ';'
	})
	t := strings.SplitN(v, "!", 2)
	u, err := url.Parse(t[0])
	if err != nil {
		p.xerrorf("parsing uri %q: %s", t[0], err)
	}
	if u.Scheme == "" {
		p.xerrorf("missing scheme in uri")
	}
	uri := URI{
		Address: t[0],
	}
	if len(t) == 2 {
		o := t[1]
		if o != "" {
			c := o[len(o)-1]
			switch c {
			case 'k', 'K', 'm', 'M', 'g', 'G', 't', 'T':
				uri.Unit = strings.ToLower(o[len(o)-1:])
				o = o[:len(o)-1]
			}
		}
		uri.MaxSize, err = strconv.ParseUint(o, 10, 64)
		if err != nil {
			p.xerrorf("parsing max size for uri: %s", err)
		}
	}
	return uri
}

func (p *parser) xnumber() int {
	digits := p.xdigits()
	v, err := strconv.Atoi(digits)
	if err != nil {
		p.xerrorf("parsing %q: %s", digits, err)
	}
	return v
}

func (p *parser) xkeyword() string {
	// ../rfc/7489:1195, keyword is imported from smtp.
	// ../rfc/5321:2287
	n := len(p.s) - p.o
	return p.xtakefn1case(func(b byte, i int) bool {
		return isalphadigit(b) || (b == '-' && i < n-1 && isalphadigit(p.s[p.o+i+1]))
	})
}

func isdigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isalpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isalphadigit(b byte) bool {
	return isdigit(b) || isalpha(b)
}
