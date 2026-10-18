package smtpserver

import (
	"bufio"
	"io"
	"log/slog"
	"mime"
	"net/mail"
	"net/textproto"
	"os"
	"strings"

	"github.com/mjl-/mox/chatmail"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/smtp"
)

// xchatmailCheck enforces the chatmail encryption requirements, if chatmail is
// enabled, on the message in dataFile. It must be called after the full message
// has been received, and before it is submitted or delivered.
//
// For submissions, messages of chatmail accounts must be end-to-end encrypted,
// with exceptions for Secure-Join requests and Autocrypt Setup Messages sent by
// a user to themselves.
//
// For incoming deliveries, if IncomingEncryptedOnly is set, messages for
// chatmail accounts must be end-to-end encrypted, with exceptions for
// Secure-Join requests and mailer-daemon reports.
func (c *conn) xchatmailCheck(dataFile *os.File) {
	conf := mox.Conf.DynamicConfig()
	if !conf.Chatmail.Enabled {
		return
	}

	var enforce bool
	if c.submission {
		if c.account != nil {
			acc, ok := conf.Accounts[c.account.Name]
			enforce = ok && acc.Chatmail
		}
	} else if conf.Chatmail.IncomingEncryptedOnly {
		for _, r := range c.recipients {
			if r.Account == nil {
				continue
			}
			if acc, ok := conf.Accounts[r.Account.AccountName]; ok && acc.Chatmail {
				enforce = true
				break
			}
		}
	}
	if !enforce {
		return
	}

	// Parse the message on demand, from the start of dataFile. The reader
	// implementations operate on the file offset-independently, so we can parse
	// multiple times without disturbing the eventual delivery.
	parse := func() (textproto.MIMEHeader, io.Reader, error) {
		m, err := mail.ReadMessage(bufio.NewReader(&moxio.AtReader{R: dataFile}))
		if err != nil {
			return nil, nil, err
		}
		return textproto.MIMEHeader(m.Header), m.Body, nil
	}

	// Secure-Join requests are intentionally unencrypted.
	if h, b, err := parse(); err == nil && chatmail.SecureJoin(h, b) {
		return
	}

	// Encrypted messages are always allowed. ../rfc/3156
	if h, b, err := parse(); err == nil && chatmail.Encrypted(h, b, !c.submission) {
		return
	}

	if c.submission {
		// Allow an Autocrypt Setup Message sent by a user to themselves. Users send
		// this unencrypted message (with an encrypted payload) to add a device.
		// ../rfc/9580
		if len(c.recipients) == 1 && c.mailFrom != nil && strings.EqualFold(c.recipients[0].Addr.String(), c.mailFrom.String()) {
			if h, _, err := parse(); err == nil && chatmail.AutocryptSetupMessage(h) {
				return
			}
		}
	} else {
		// Allow cleartext mailer-daemon reports, e.g. delivery status notifications.
		if h, _, err := parse(); err == nil && h.Get("Auto-Submitted") != "" {
			if addr, err := mail.ParseAddress(h.Get("From")); err == nil && strings.HasPrefix(strings.ToLower(addr.Address), "mailer-daemon@") {
				if mediatype, _, err := mime.ParseMediaType(h.Get("Content-Type")); err == nil && strings.EqualFold(mediatype, "multipart/report") {
					return
				}
			}
		}
	}

	c.log.Info("rejecting unencrypted message for chatmail account", slog.Bool("submission", c.submission))
	xsmtpUserErrorf(smtp.C523EncryptionNeeded, smtp.SePol7EncNeeded10, "message must be end-to-end encrypted")
}
