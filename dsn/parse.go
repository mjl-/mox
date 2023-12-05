package dsn

import (
	"bufio"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
)

// Parse reads a DSN message.
//
// A DSN is a multipart internet mail message with 2 or 3 parts: human-readable
// text, machine-parsable text, and optional original message or headers.
//
// The first return value is the machine-parsed DSN message. The second value is
// the entire MIME multipart message. Use its Parts field to access the
// human-readable text and optional original message/headers.
func Parse(elog *slog.Logger, r io.ReaderAt) (*Message, *message.Part, error) {
	log := mlog.New("dsn", elog)

	// DSNs can mix and match subtypes with and without utf-8. ../rfc/6533:441

	part, err := message.Parse(log.Logger, false, r)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing message: %v", err)
	}
	if part.MediaType != "MULTIPART" || part.MediaSubType != "REPORT" {
		return nil, nil, fmt.Errorf(`message has content-type %q, must have "message/report"`, strings.ToLower(part.MediaType+"/"+part.MediaSubType))
	}
	err = part.Walk(log.Logger, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing message parts: %v", err)
	}
	nparts := len(part.Parts)
	if nparts != 2 && nparts != 3 {
		return nil, nil, fmt.Errorf("invalid dsn, got %d multipart parts, 2 or 3 required", nparts)
	}
	p0 := part.Parts[0]
	if !(p0.MediaType == "" && p0.MediaSubType == "") && !(p0.MediaType == "TEXT" && p0.MediaSubType == "PLAIN") {
		return nil, nil, fmt.Errorf(`invalid dsn, first part has content-type %q, must have "text/plain"`, strings.ToLower(p0.MediaType+"/"+p0.MediaSubType))
	}

	p1 := part.Parts[1]
	var m *Message
	if !(p1.MediaType == "MESSAGE" && (p1.MediaSubType == "DELIVERY-STATUS" || p1.MediaSubType == "GLOBAL-DELIVERY-STATUS")) {
		return nil, nil, fmt.Errorf(`invalid dsn, second part has content-type %q, must have "message/delivery-status" or "message/global-delivery-status"`, strings.ToLower(p1.MediaType+"/"+p1.MediaSubType))
	}
	utf8 := p1.MediaSubType == "GLOBAL-DELIVERY-STATUS"
	m, err = Decode(p1.Reader(), utf8)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing dsn delivery-status part: %v", err)
	}

	addressPath := func(a message.Address) (smtp.Path, error) {
		d, err := dns.ParseDomain(a.Host)
		if err != nil {
			return smtp.Path{}, fmt.Errorf("parsing domain: %v", err)
		}
		return smtp.Path{Localpart: smtp.Localpart(a.User), IPDomain: dns.IPDomain{Domain: d}}, nil
	}
	if len(part.Envelope.From) == 1 {
		m.From, err = addressPath(part.Envelope.From[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parsing From-header: %v", err)
		}
	}
	if len(part.Envelope.To) == 1 {
		m.To, err = addressPath(part.Envelope.To[0])
		if err != nil {
			return nil, nil, fmt.Errorf("parsing To-header: %v", err)
		}
	}
	m.Subject = part.Envelope.Subject
	buf, err := io.ReadAll(p0.ReaderUTF8OrBinary())
	if err != nil {
		return nil, nil, fmt.Errorf("reading human-readable text part: %v", err)
	}
	m.TextBody = strings.ReplaceAll(string(buf), "\r\n", "\n")

	if nparts == 2 {
		return m, &part, nil
	}

	p2 := part.Parts[2]
	ct := strings.ToLower(p2.MediaType + "/" + p2.MediaSubType)
	switch ct {
	case "text/rfc822-headers":
	case "message/global-headers":
	case "message/rfc822":
	case "message/global":
	default:
		return nil, nil, fmt.Errorf("invalid content-type %q for optional third part with original message/headers", ct)
	}

	return m, &part, nil
}

// Decode parses the (global) delivery-status part of a DSN.
//
// utf8 indicates if UTF-8 is allowed for this message, if used by the media
// subtype of the message parts.
func Decode(r io.Reader, utf8 bool) (*Message, error) {
	m := Message{SMTPUTF8: utf8}

	// We are using textproto.Reader to read mime headers. It requires a header section ending in \r\n.
	// ../rfc/3464:486
	b := bufio.NewReader(io.MultiReader(r, strings.NewReader("\r\n")))
	mr := textproto.NewReader(b)

	// Read per-message lines.
	// ../rfc/3464:1522 ../rfc/6533:366
	msgh, err := mr.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("reading per-message lines: %v", err)
	}
	for k, l := range msgh {
		if len(l) != 1 {
			return nil, fmt.Errorf("multiple values for %q: %v", k, l)
		}
		v := l[0]
		// note: headers are in canonical form, as parsed by textproto.
		switch k {
		case "Original-Envelope-Id":
			m.OriginalEnvelopeID = v
		case "Reporting-Mta":
			mta, err := parseMTA(v, utf8)
			if err != nil {
				return nil, fmt.Errorf("parsing reporting-mta: %v", err)
			}
			m.ReportingMTA = mta
		case "Dsn-Gateway":
			mta, err := parseMTA(v, utf8)
			if err != nil {
				return nil, fmt.Errorf("parsing dsn-gateway: %v", err)
			}
			m.DSNGateway = mta
		case "Received-From-Mta":
			mta, err := parseMTA(v, utf8)
			if err != nil {
				return nil, fmt.Errorf("parsing received-from-mta: %v", err)
			}
			d, err := dns.ParseDomain(mta)
			if err != nil {
				return nil, fmt.Errorf("parsing received-from-mta domain %q: %v", mta, err)
			}
			m.ReceivedFromMTA = smtp.Ehlo{Name: dns.IPDomain{Domain: d}}
		case "Arrival-Date":
			tm, err := parseDateTime(v)
			if err != nil {
				return nil, fmt.Errorf("parsing arrival-date: %v", err)
			}
			m.ArrivalDate = tm
		default:
			// We'll assume it is an extension field, we'll ignore it for now.
		}
	}
	m.MessageHeader = msgh

	required := []string{"Reporting-Mta"}
	for _, req := range required {
		if _, ok := msgh[req]; !ok {
			return nil, fmt.Errorf("missing required recipient field %q", req)
		}
	}

	rh, err := parseRecipientHeader(mr, utf8)
	if err != nil {
		return nil, fmt.Errorf("reading per-recipient header: %v", err)
	}
	m.Recipients = []Recipient{rh}
	for {
		if _, err := b.Peek(1); err == io.EOF {
			break
		}
		rh, err := parseRecipientHeader(mr, utf8)
		if err != nil {
			return nil, fmt.Errorf("reading another per-recipient header: %v", err)
		}
		m.Recipients = append(m.Recipients, rh)
	}
	return &m, nil
}

// ../rfc/3464:1530 ../rfc/6533:370
func parseRecipientHeader(mr *textproto.Reader, utf8 bool) (Recipient, error) {
	var r Recipient
	h, err := mr.ReadMIMEHeader()
	if err != nil {
		return Recipient{}, err
	}

	for k, l := range h {
		if len(l) != 1 {
			return Recipient{}, fmt.Errorf("multiple values for %q: %v", k, l)
		}
		v := l[0]
		// note: headers are in canonical form, as parsed by textproto.
		var err error
		switch k {
		case "Original-Recipient":
			r.OriginalRecipient, err = parseAddress(v, utf8)
		case "Final-Recipient":
			r.FinalRecipient, err = parseAddress(v, utf8)
		case "Action":
			a := Action(strings.ToLower(v))
			actions := []Action{Failed, Delayed, Delivered, Relayed, Expanded}
			var ok bool
			for _, x := range actions {
				if a == x {
					ok = true
					break
				}
			}
			if !ok {
				err = fmt.Errorf("unrecognized action %q", v)
			}
		case "Status":
			// todo: parse the enhanced status code?
			r.Status = v
		case "Remote-Mta":
			r.RemoteMTA = NameIP{Name: v}
		case "Diagnostic-Code":
			// ../rfc/3464:518
			t := strings.SplitN(v, ";", 2)
			dt := strings.TrimSpace(t[0])
			if strings.ToLower(dt) != "smtp" {
				err = fmt.Errorf("unknown diagnostic-type %q, expected smtp", dt)
			} else if len(t) != 2 {
				err = fmt.Errorf("missing semicolon to separate diagnostic-type from code")
			} else {
				r.DiagnosticCode = strings.TrimSpace(t[1])
			}
		case "Last-Attempt-Date":
			r.LastAttemptDate, err = parseDateTime(v)
		case "Final-Log-Id":
			r.FinalLogID = v
		case "Will-Retry-Until":
			tm, err := parseDateTime(v)
			if err == nil {
				r.WillRetryUntil = &tm
			}
		default:
			// todo future: parse localized diagnostic text field?
			// We'll assume it is an extension field, we'll ignore it for now.
		}
		if err != nil {
			return Recipient{}, fmt.Errorf("parsing field %q %q: %v", k, v, err)
		}
	}

	required := []string{"Final-Recipient", "Action", "Status"}
	for _, req := range required {
		if _, ok := h[req]; !ok {
			return Recipient{}, fmt.Errorf("missing required recipient field %q", req)
		}
	}

	r.Header = h
	return r, nil
}

// ../rfc/3464:525
func parseMTA(s string, utf8 bool) (string, error) {
	s = removeComments(s)
	t := strings.SplitN(s, ";", 2)
	if len(t) != 2 {
		return "", fmt.Errorf("missing semicolon that splits type and name")
	}
	k := strings.TrimSpace(t[0])
	if !strings.EqualFold(k, "dns") {
		return "", fmt.Errorf("unknown type %q, expected dns", k)
	}
	return strings.TrimSpace(t[1]), nil
}

func parseDateTime(s string) (time.Time, error) {
	s = removeComments(s)
	return time.Parse(message.RFC5322Z, s)
}

func parseAddress(s string, utf8 bool) (smtp.Path, error) {
	s = removeComments(s)
	t := strings.SplitN(s, ";", 2)
	// ../rfc/3464:513 ../rfc/6533:250
	addrType := strings.ToLower(strings.TrimSpace(t[0]))
	if len(t) != 2 {
		return smtp.Path{}, fmt.Errorf("missing semicolon that splits address type and address")
	} else if addrType == "utf-8" {
		if !utf8 {
			return smtp.Path{}, fmt.Errorf("utf-8 address type for non-utf-8 dsn")
		}
	} else if addrType != "rfc822" {
		return smtp.Path{}, fmt.Errorf("unrecognized address type %q, expected rfc822", addrType)
	}
	s = strings.TrimSpace(t[1])
	if !utf8 {
		for _, c := range s {
			if c > 0x7f {
				return smtp.Path{}, fmt.Errorf("non-ascii without utf-8 enabled")
			}
		}
	}
	// todo: more proper parser
	t = strings.SplitN(s, "@", 2)
	if len(t) != 2 || t[0] == "" || t[1] == "" {
		return smtp.Path{}, fmt.Errorf("invalid email address")
	}
	d, err := dns.ParseDomain(t[1])
	if err != nil {
		return smtp.Path{}, fmt.Errorf("parsing domain: %v", err)
	}
	var lp string
	var esc string
	for _, c := range t[0] {
		if esc == "" && c == '\\' || esc == `\` && (c == 'x' || c == 'X') || esc == `\x` && c == '{' {
			if c == 'X' {
				c = 'x'
			}
			esc += string(c)
		} else if strings.HasPrefix(esc, `\x{`) {
			if c == '}' {
				c, err := strconv.ParseInt(esc[3:], 16, 32)
				if err != nil {
					return smtp.Path{}, fmt.Errorf("parsing localpart with hexpoint: %v", err)
				}
				lp += string(rune(c))
				esc = ""
			} else {
				esc += string(c)
			}
		} else {
			lp += string(c)
		}
	}
	if esc != "" {
		return smtp.Path{}, fmt.Errorf("parsing localpart: unfinished embedded unicode char")
	}
	p := smtp.Path{Localpart: smtp.Localpart(lp), IPDomain: dns.IPDomain{Domain: d}}
	return p, nil
}

func removeComments(s string) string {
	n := 0
	r := ""
	for _, c := range s {
		if c == '(' {
			n++
		} else if c == ')' && n > 0 {
			n--
		} else if n == 0 {
			r += string(c)
		}
	}
	return r
}
