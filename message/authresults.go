package message

import (
	"fmt"
)

// ../rfc/8601:577

// Authentication-Results header, see RFC 8601.
type AuthResults struct {
	Hostname string
	Comment  string // If not empty, header comment without "()", added after Hostname.
	Methods  []AuthMethod
}

// ../rfc/8601:598

// AuthMethod is a result for one authentication method.
//
// Example encoding in the header: "spf=pass smtp.mailfrom=example.net".
type AuthMethod struct {
	// E.g. "dkim", "spf", "iprev", "auth".
	Method  string
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
	Comment    string // If not empty, header comment withtout "()", added after Value.
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
	w.Add("", "Authentication-Results:"+optComment(h.Comment)+" "+value(h.Hostname)+";")
	for i, m := range h.Methods {
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
			addf("reason=%s", value(m.Reason))
		}
		for _, p := range m.Props {
			v := p.Value
			if !p.IsAddrLike {
				v = value(v)
			}
			addf("%s.%s=%s%s", p.Type, p.Property, v, optComment(p.Comment))
		}
		for j, t := range tokens {
			if j == len(tokens)-1 && i < len(h.Methods)-1 {
				t += ";"
			}
			w.Add(" ", t)
		}
	}
	return w.String()
}

func value(s string) string {
	quote := s == ""
	for _, c := range s {
		// utf-8 does not have to be quoted. ../rfc/6532:242
		if c == '"' || c == '\\' || c <= ' ' || c == 0x7f {
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
