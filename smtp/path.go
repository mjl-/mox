package smtp

import (
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
)

// Path is an SMTP forward/reverse path, as used in MAIL FROM and RCPT TO
// commands.
type Path struct {
	Localpart Localpart
	IPDomain  dns.IPDomain
}

func (p Path) IsZero() bool {
	return p.Localpart == "" && p.IPDomain.IsZero()
}

// String returns a string representation with ASCII-only domain name.
func (p Path) String() string {
	return p.XString(false)
}

// LogString returns both the ASCII-only and optional UTF-8 representation.
func (p Path) LogString() string {
	if p.Localpart == "" && p.IPDomain.IsZero() {
		return ""
	}
	s := p.XString(true)
	lp := p.Localpart.String()
	qlp := strconv.QuoteToASCII(lp)
	escaped := qlp != `"`+lp+`"`
	if p.IPDomain.Domain.Unicode != "" || escaped {
		if escaped {
			lp = qlp
		}
		s += "/" + lp + "@" + p.IPDomain.XString(false)
	}
	return s
}

// XString is like String, but returns unicode UTF-8 domain names if utf8 is
// true.
func (p Path) XString(utf8 bool) string {
	if p.Localpart == "" && p.IPDomain.IsZero() {
		return ""
	}
	return p.Localpart.String() + "@" + p.IPDomain.XString(utf8)
}

// ASCIIExtra returns an ascii-only path if utf8 is true and the ipdomain is a
// unicode domain. Otherwise returns an empty string.
//
// For use in comments in message headers added during SMTP.
func (p Path) ASCIIExtra(utf8 bool) string {
	if utf8 && p.IPDomain.Domain.Unicode != "" {
		return p.XString(false)
	}
	return ""
}

// DSNString returns a string representation as used with DSN with/without
// UTF-8 support.
//
// If utf8 is false, the domain is represented as US-ASCII (IDNA), and the
// localpart is encoded with in 7bit according to RFC 6533.
func (p Path) DSNString(utf8 bool) string {
	if utf8 {
		return p.XString(utf8)
	}
	return p.Localpart.DSNString(utf8) + "@" + p.IPDomain.XString(utf8)
}

func (p Path) Equal(o Path) bool {
	if p.Localpart != o.Localpart {
		return false
	}
	d0 := p.IPDomain
	d1 := o.IPDomain
	if len(d0.IP) > 0 || len(d1.IP) > 0 {
		return d0.IP.Equal(d1.IP)
	}
	return strings.EqualFold(d0.Domain.ASCII, d1.Domain.ASCII)
}
