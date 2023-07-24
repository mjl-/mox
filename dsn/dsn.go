// Package dsn parses and composes Delivery Status Notification messages, see
// RFC 3464 and RFC 6533.
package dsn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

// Message represents a DSN message, with basic message headers, human-readable text,
// machine-parsable data, and optional original message/headers.
//
// A DSN represents a delayed, failed or successful delivery. Failing incoming
// deliveries over SMTP, and failing outgoing deliveries from the message queue,
// can result in a DSN being sent.
type Message struct {
	SMTPUTF8 bool // Whether the original was received with smtputf8.

	// DSN message From header. E.g. postmaster@ourdomain.example. NOTE:
	// DSNs should be sent with a null reverse path to prevent mail loops.
	// ../rfc/3464:421
	From smtp.Path

	// "To" header, and also SMTP RCP TO to deliver DSN to. Should be taken
	// from original SMTP transaction MAIL FROM.
	// ../rfc/3464:415
	To smtp.Path

	// Message subject header, e.g. describing mail delivery failure.
	Subject string

	// Set when message is composed.
	MessageID string

	// References header, with Message-ID of original message this DSN is about. So
	// mail user-agents will thread the DSN with the original message.
	References string

	// Human-readable text explaining the failure. Line endings should be
	// bare newlines, not \r\n. They are converted to \r\n when composing.
	TextBody string

	// Per-message fields.
	OriginalEnvelopeID string
	ReportingMTA       string // Required.
	DSNGateway         string
	ReceivedFromMTA    smtp.Ehlo // Host from which message was received.
	ArrivalDate        time.Time

	// All per-message fields, including extensions. Only used for parsing,
	// not composing.
	MessageHeader textproto.MIMEHeader

	// One or more per-recipient fields.
	// ../rfc/3464:436
	Recipients []Recipient

	// Original message or headers to include in DSN as third MIME part.
	// Optional. Only used for generating DSNs, not set for parsed DNSs.
	Original []byte
}

// Action is a field in a DSN.
type Action string

// ../rfc/3464:890

const (
	Failed    Action = "failed"
	Delayed   Action = "delayed"
	Delivered Action = "delivered"
	Relayed   Action = "relayed"
	Expanded  Action = "expanded"
)

// ../rfc/3464:1530 ../rfc/6533:370

// Recipient holds the per-recipient delivery-status lines in a DSN.
type Recipient struct {
	// Required fields.
	FinalRecipient smtp.Path // Final recipient of message.
	Action         Action

	// Enhanced status code. First digit indicates permanent or temporary
	// error. If the string contains more than just a status, that
	// additional text is added as comment when composing a DSN.
	Status string

	// Optional fields.
	// Original intended recipient of message. Used with the DSN extensions ORCPT
	// parameter.
	// ../rfc/3464:1197
	OriginalRecipient smtp.Path

	// Remote host that returned an error code. Can also be empty for
	// deliveries.
	RemoteMTA NameIP

	// If RemoteMTA is present, DiagnosticCode is from remote. When
	// creating a DSN, additional text in the string will be added to the
	// DSN as comment.
	DiagnosticCode  string
	LastAttemptDate time.Time
	FinalLogID      string

	// For delayed deliveries, deliveries may be retried until this time.
	WillRetryUntil *time.Time

	// All fields, including extensions. Only used for parsing, not
	// composing.
	Header textproto.MIMEHeader
}

// Compose returns a DSN message.
//
// smtputf8 indicates whether the remote MTA that is receiving the DSN
// supports smtputf8. This influences the message media (sub)types used for the
// DSN.
//
// DKIM signatures are added if DKIM signing is configured for the "from" domain.
func (m *Message) Compose(log *mlog.Log, smtputf8 bool) ([]byte, error) {
	// ../rfc/3462:119
	// ../rfc/3464:377
	// We'll make a multipart/report with 2 or 3 parts:
	// - 1. human-readable explanation;
	// - 2. message/delivery-status;
	// - 3. (optional) original message (either in full, or only headers).

	// todo future: add option to send full message. but only do so if the message is <100kb.
	// todo future: possibly write to a file directly, instead of building up message in memory.

	// If message does not require smtputf8, we are never generating a utf-8 DSN.
	if !m.SMTPUTF8 {
		smtputf8 = false
	}

	// We check for errors once after all the writes.
	msgw := &errWriter{w: &bytes.Buffer{}}

	header := func(k, v string) {
		fmt.Fprintf(msgw, "%s: %s\r\n", k, v)
	}

	line := func(w io.Writer) {
		_, _ = w.Write([]byte("\r\n"))
	}

	// Outer message headers.
	header("From", fmt.Sprintf("<%s>", m.From.XString(smtputf8))) // todo: would be good to have a local ascii-only name for this address.
	header("To", fmt.Sprintf("<%s>", m.To.XString(smtputf8)))     // todo: we could just leave this out if it has utf-8 and remote does not support utf-8.
	header("Subject", m.Subject)
	m.MessageID = mox.MessageIDGen(smtputf8)
	header("Message-Id", fmt.Sprintf("<%s>", m.MessageID))
	if m.References != "" {
		header("References", m.References)
	}
	header("Date", time.Now().Format(message.RFC5322Z))
	header("MIME-Version", "1.0")
	mp := multipart.NewWriter(msgw)
	header("Content-Type", fmt.Sprintf(`multipart/report; report-type="delivery-status"; boundary="%s"`, mp.Boundary()))

	line(msgw)

	// First part, human-readable message.
	msgHdr := textproto.MIMEHeader{}
	if smtputf8 {
		msgHdr.Set("Content-Type", "text/plain; charset=utf-8")
		msgHdr.Set("Content-Transfer-Encoding", "8BIT")
	} else {
		msgHdr.Set("Content-Type", "text/plain")
		msgHdr.Set("Content-Transfer-Encoding", "7BIT")
	}
	msgp, err := mp.CreatePart(msgHdr)
	if err != nil {
		return nil, err
	}
	if _, err := msgp.Write([]byte(strings.ReplaceAll(m.TextBody, "\n", "\r\n"))); err != nil {
		return nil, err
	}

	// Machine-parsable message. ../rfc/3464:455
	statusHdr := textproto.MIMEHeader{}
	if smtputf8 {
		// ../rfc/6533:325
		statusHdr.Set("Content-Type", "message/global-delivery-status")
		statusHdr.Set("Content-Transfer-Encoding", "8BIT")
	} else {
		statusHdr.Set("Content-Type", "message/delivery-status")
		statusHdr.Set("Content-Transfer-Encoding", "7BIT")
	}
	statusp, err := mp.CreatePart(statusHdr)
	if err != nil {
		return nil, err
	}

	// ../rfc/3464:470
	// examples: ../rfc/3464:1855
	// type fields: ../rfc/3464:536 https://www.iana.org/assignments/dsn-types/dsn-types.xhtml

	status := func(k, v string) {
		fmt.Fprintf(statusp, "%s: %s\r\n", k, v)
	}

	// Per-message fields first. ../rfc/3464:575
	// todo future: once we support the smtp dsn extension, the envid should be saved/set as OriginalEnvelopeID. ../rfc/3464:583 ../rfc/3461:1139
	if m.OriginalEnvelopeID != "" {
		status("Original-Envelope-ID", m.OriginalEnvelopeID)
	}
	status("Reporting-MTA", "dns; "+m.ReportingMTA) // ../rfc/3464:628
	if m.DSNGateway != "" {
		// ../rfc/3464:714
		status("DSN-Gateway", "dns; "+m.DSNGateway)
	}
	if !m.ReceivedFromMTA.IsZero() {
		// ../rfc/3464:735
		status("Received-From-MTA", fmt.Sprintf("dns;%s (%s)", m.ReceivedFromMTA.Name, smtp.AddressLiteral(m.ReceivedFromMTA.ConnIP)))
	}
	status("Arrival-Date", m.ArrivalDate.Format(message.RFC5322Z)) // ../rfc/3464:758

	// Then per-recipient fields. ../rfc/3464:769
	// todo: should also handle other address types. at least recognize "unknown". Probably just store this field. ../rfc/3464:819
	addrType := "rfc822;" // ../rfc/3464:514
	if smtputf8 {
		addrType = "utf-8;" // ../rfc/6533:250
	}
	if len(m.Recipients) == 0 {
		return nil, fmt.Errorf("missing per-recipient fields")
	}
	for _, r := range m.Recipients {
		line(statusp)
		if !r.OriginalRecipient.IsZero() {
			// ../rfc/3464:807
			status("Original-Recipient", addrType+r.OriginalRecipient.DSNString(smtputf8))
		}
		status("Final-Recipient", addrType+r.FinalRecipient.DSNString(smtputf8)) // ../rfc/3464:829
		status("Action", string(r.Action))                                       // ../rfc/3464:879
		st := r.Status
		if st == "" {
			// ../rfc/3464:944
			// Making up a status code is not great, but the field is required. We could simply
			// require the caller to make one up...
			switch r.Action {
			case Delayed:
				st = "4.0.0"
			case Failed:
				st = "5.0.0"
			default:
				st = "2.0.0"
			}
		}
		var rest string
		st, rest = codeLine(st)
		statusLine := st
		if rest != "" {
			statusLine += " (" + rest + ")"
		}
		status("Status", statusLine) // ../rfc/3464:975
		if !r.RemoteMTA.IsZero() {
			// ../rfc/3464:1015
			s := "dns;" + r.RemoteMTA.Name
			if len(r.RemoteMTA.IP) > 0 {
				s += " (" + smtp.AddressLiteral(r.RemoteMTA.IP) + ")"
			}
			status("Remote-MTA", s)
		}
		// Presence of Diagnostic-Code indicates the code is from Remote-MTA. ../rfc/3464:1053
		if r.DiagnosticCode != "" {
			diagCode, rest := codeLine(r.DiagnosticCode)
			diagLine := diagCode
			if rest != "" {
				diagLine += " (" + rest + ")"
			}
			// ../rfc/6533:589
			status("Diagnostic-Code", "smtp; "+diagLine)
		}
		if !r.LastAttemptDate.IsZero() {
			status("Last-Attempt-Date", r.LastAttemptDate.Format(message.RFC5322Z)) // ../rfc/3464:1076
		}
		if r.FinalLogID != "" {
			// todo future: think about adding cid as "Final-Log-Id"?
			status("Final-Log-ID", r.FinalLogID) // ../rfc/3464:1098
		}
		if r.WillRetryUntil != nil {
			status("Will-Retry-Until", r.WillRetryUntil.Format(message.RFC5322Z)) // ../rfc/3464:1108
		}
	}

	// We include only the header of the original message.
	// todo: add the textual version of the original message, if it exists and isn't too large.
	if m.Original != nil {
		headers, err := message.ReadHeaders(bufio.NewReader(bytes.NewReader(m.Original)))
		if err != nil && errors.Is(err, message.ErrHeaderSeparator) {
			// Whole data is a header.
			headers = m.Original
		} else if err != nil {
			return nil, err
		}
		// Else, this is a whole message. We still only include the headers. todo: include the whole body.

		origHdr := textproto.MIMEHeader{}
		if smtputf8 {
			// ../rfc/6533:431
			// ../rfc/6533:605
			origHdr.Set("Content-Type", "message/global-headers") // ../rfc/6533:625
			origHdr.Set("Content-Transfer-Encoding", "8BIT")
		} else {
			// ../rfc/3462:175
			if m.SMTPUTF8 {
				// ../rfc/6533:480
				origHdr.Set("Content-Type", "text/rfc822-headers; charset=utf-8")
				origHdr.Set("Content-Transfer-Encoding", "BASE64")
			} else {
				origHdr.Set("Content-Type", "text/rfc822-headers")
				origHdr.Set("Content-Transfer-Encoding", "7BIT")
			}
		}
		origp, err := mp.CreatePart(origHdr)
		if err != nil {
			return nil, err
		}

		if !smtputf8 && m.SMTPUTF8 {
			data := base64.StdEncoding.EncodeToString(headers)
			for len(data) > 0 {
				line := data
				n := len(line)
				if n > 78 {
					n = 78
				}
				line, data = data[:n], data[n:]
				if _, err := origp.Write([]byte(line + "\r\n")); err != nil {
					return nil, err
				}
			}
		} else {
			if _, err := origp.Write(headers); err != nil {
				return nil, err
			}
		}
	}

	if err := mp.Close(); err != nil {
		return nil, err
	}

	if msgw.err != nil {
		return nil, err
	}

	data := msgw.w.Bytes()

	fd := m.From.IPDomain.Domain
	confDom, _ := mox.Conf.Domain(fd)
	if len(confDom.DKIM.Sign) > 0 {
		if dkimHeaders, err := dkim.Sign(context.Background(), m.From.Localpart, fd, confDom.DKIM, smtputf8, bytes.NewReader(data)); err != nil {
			log.Errorx("dsn: dkim sign for domain, returning unsigned dsn", err, mlog.Field("domain", fd))
		} else {
			data = append([]byte(dkimHeaders), data...)
		}
	}

	return data, nil
}

type errWriter struct {
	w   *bytes.Buffer
	err error
}

func (w *errWriter) Write(buf []byte) (int, error) {
	if w.err != nil {
		return -1, w.err
	}
	n, err := w.w.Write(buf)
	w.err = err
	return n, err
}

// split a line into enhanced status code and rest.
func codeLine(s string) (string, string) {
	t := strings.SplitN(s, " ", 2)
	l := strings.Split(t[0], ".")
	if len(l) != 3 {
		return "", s
	}
	for i, e := range l {
		_, err := strconv.ParseInt(e, 10, 32)
		if err != nil {
			return "", s
		}
		if i == 0 && len(e) != 1 {
			return "", s
		}
	}

	var rest string
	if len(t) == 2 {
		rest = t[1]
	}
	return t[0], rest
}

// HasCode returns whether line starts with an enhanced SMTP status code.
func HasCode(line string) bool {
	// ../rfc/3464:986
	ecode, _ := codeLine(line)
	return ecode != ""
}
