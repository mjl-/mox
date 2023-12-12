package spf

import (
	"net"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
)

// ../rfc/7208:2083

// Received represents a Received-SPF header with the SPF verify results, to be
// prepended to a message.
//
// Example:
//
//	Received-SPF: pass (mybox.example.org: domain of
//	 myname@example.com designates 192.0.2.1 as permitted sender)
//	 receiver=mybox.example.org; client-ip=192.0.2.1;
//	 envelope-from="myname@example.com"; helo=foo.example.com;
type Received struct {
	Result       Status
	Comment      string       // Additional free-form information about the verification result. Optional. Included in message header comment inside "()".
	ClientIP     net.IP       // IP address of remote SMTP client, "client-ip=".
	EnvelopeFrom string       // Sender mailbox, typically SMTP MAIL FROM, but will be set to "postmaster" at SMTP EHLO if MAIL FROM is empty, "envelop-from=".
	Helo         dns.IPDomain // IP or host name from EHLO or HELO command, "helo=".
	Problem      string       // Optional. "problem="
	Receiver     string       // Hostname of receiving mail server, "receiver=".
	Identity     Identity     // The identity that was checked, "mailfrom" or "helo", for "identity=".
	Mechanism    string       // Mechanism that caused the result, can be "default". Optional.
}

// Identity that was verified.
type Identity string

const (
	ReceivedMailFrom Identity = "mailfrom"
	ReceivedHELO     Identity = "helo"
)

func receivedValueEncode(s string) string {
	if s == "" {
		return quotedString("")
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c > 0x7f {
			continue
		}
		// ../rfc/5322:679
		const atext = "!#$%&'*+-/=?^_`{|}~"
		if strings.IndexByte(atext, byte(c)) >= 0 {
			continue
		}
		if c != '.' || (i == 0 || i+1 == len(s)) {
			return quotedString(s)
		}
	}
	return s
}

// ../rfc/5322:736
func quotedString(s string) string {
	w := &strings.Builder{}
	w.WriteByte('"')
	for _, c := range s {
		if c > ' ' && c < 0x7f && c != '"' && c != '\\' || c > 0x7f || c == ' ' || c == '\t' {
			// We allow utf-8. This should only be needed when the destination address has an
			// utf8 localpart, in which case we are already doing smtputf8.
			// We also allow unescaped space and tab. This is FWS, and the name of ABNF
			// production "qcontent" implies the FWS is not part of the string, but escaping
			// space and tab leads to ugly strings. ../rfc/5322:743
			w.WriteRune(c)
			continue
		}
		switch c {
		case ' ', '\t', '"', '\\':
			w.WriteByte('\\')
			w.WriteRune(c)
		}
	}
	w.WriteByte('"')
	return w.String()
}

// Header returns a Received-SPF header including trailing crlf that can be
// prepended to an incoming message.
func (r Received) Header() string {
	// ../rfc/7208:2043
	w := &message.HeaderWriter{}
	w.Add("", "Received-SPF: "+string(r.Result))
	if r.Comment != "" {
		w.Add(" ", "("+r.Comment+")")
	}
	w.Addf(" ", "client-ip=%s;", receivedValueEncode(r.ClientIP.String()))
	w.Addf(" ", "envelope-from=%s;", receivedValueEncode(r.EnvelopeFrom))
	var helo string
	if len(r.Helo.IP) > 0 {
		helo = r.Helo.IP.String()
	} else {
		helo = r.Helo.Domain.ASCII
	}
	w.Addf(" ", "helo=%s;", receivedValueEncode(helo))
	if r.Problem != "" {
		s := r.Problem
		max := 77 - len("problem=; ")
		if len(s) > max {
			s = s[:max]
		}
		w.Addf(" ", "problem=%s;", receivedValueEncode(s))
	}
	if r.Mechanism != "" {
		w.Addf(" ", "mechanism=%s;", receivedValueEncode(r.Mechanism))
	}
	w.Addf(" ", "receiver=%s;", receivedValueEncode(r.Receiver))
	w.Addf(" ", "identity=%s", receivedValueEncode(string(r.Identity)))
	return w.String()
}
