// Package subjectpass implements a mechanism for reject an incoming message with a challenge to include a token in a next delivery attempt.
//
// An SMTP server can reject a message with instructions to send another
// message, this time including a special token. The sender will receive a DSN,
// which will include the error message with instructions. By sending the
// message again with the token, as instructed, the SMTP server can recognize
// the token, verify it, and accept the message.
package subjectpass

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/stub"
)

var (
	MetricGenerate stub.Counter    = stub.CounterIgnore{}
	MetricVerify   stub.CounterVec = stub.CounterVecIgnore{}
)

var (
	ErrMessage = errors.New("subjectpass: malformed message")
	ErrAbsent  = errors.New("subjectpass: no token found")
	ErrFrom    = errors.New("subjectpass: bad From")
	ErrInvalid = errors.New("subjectpass: malformed token")
	ErrVerify  = errors.New("subjectpass: verification failed")
	ErrExpired = errors.New("subjectpass: token expired")
)

var Explanation = "Your message resembles spam. If your email is legitimate, please send it again with the following added to the email message subject: "

// Generate generates a token that is valid for "mailFrom", starting from "tm"
// and signed with "key".
//
// The token is of the form: (pass:<signeddata>). Instructions to the sender should
// be to include this token in the Subject header of a new message.
func Generate(elog *slog.Logger, mailFrom smtp.Address, key []byte, tm time.Time) string {
	log := mlog.New("subjectpass", elog)

	MetricGenerate.Inc()
	log.Debug("subjectpass generate", slog.Any("mailfrom", mailFrom))

	// We discard the lower 8 bits of the time, we can do with less precision.
	t := tm.Unix()
	buf := []byte{
		0 | (byte(t>>32) & 0x0f), // 4 bits version, 4 bits time
		byte(t>>24) & 0xff,
		byte(t>>16) & 0xff,
		byte(t>>8) & 0xff,
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	mac.Write([]byte(mailFrom.String()))
	h := mac.Sum(nil)[:12]
	buf = append(buf, h...)
	return "(pass:" + base64.RawURLEncoding.EncodeToString(buf) + ")"
}

// Verify parses "message" and checks if it includes a subjectpass token in its
// Subject header that is still valid (within "period") and signed with "key".
func Verify(elog *slog.Logger, r io.ReaderAt, key []byte, period time.Duration) (rerr error) {
	log := mlog.New("subjectpass", elog)

	var token string

	defer func() {
		result := "fail"
		if rerr == nil {
			result = "ok"
		}
		MetricVerify.IncLabels(result)

		log.Debugx("subjectpass verify result", rerr, slog.String("token", token), slog.Duration("period", period))
	}()

	p, err := message.Parse(log.Logger, true, r)
	if err != nil {
		return fmt.Errorf("%w: parse message: %s", ErrMessage, err)
	}
	header, err := p.Header()
	if err != nil {
		return fmt.Errorf("%w: parse message headers: %s", ErrMessage, err)
	}
	subject := header.Get("Subject")
	if subject == "" {
		log.Info("no subject header")
		return fmt.Errorf("%w: no subject header", ErrAbsent)
	}
	t := strings.SplitN(subject, "(pass:", 2)
	if len(t) != 2 {
		return fmt.Errorf("%w: no token in subject", ErrAbsent)
	}
	t = strings.SplitN(t[1], ")", 2)
	if len(t) != 2 {
		return fmt.Errorf("%w: no token in subject (2)", ErrAbsent)
	}
	token = t[0]

	if len(p.Envelope.From) != 1 {
		return fmt.Errorf("%w: need 1 from address, got %d", ErrFrom, len(p.Envelope.From))
	}
	from := p.Envelope.From[0]
	d, err := dns.ParseDomain(from.Host)
	if err != nil {
		return fmt.Errorf("%w: from address with bad domain: %v", ErrFrom, err)
	}
	addr := smtp.Address{Localpart: smtp.Localpart(from.User), Domain: d}.Pack(true)

	buf, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("%w: parsing base64: %s", ErrInvalid, err)
	}

	if len(buf) == 0 {
		return fmt.Errorf("%w: empty pass token", ErrInvalid)
	}

	version := buf[0] >> 4
	if version != 0 {
		return fmt.Errorf("%w: unknown version %d", ErrInvalid, version)
	}
	if len(buf) != 4+12 {
		return fmt.Errorf("%w: bad length of pass token, %d", ErrInvalid, len(buf))
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:4])
	mac.Write([]byte(addr))
	h := mac.Sum(nil)[:12]
	if !hmac.Equal(buf[4:], h) {
		return ErrVerify
	}

	tsign := time.Unix(int64(buf[0]&0x0f)<<32|int64(buf[1])<<24|int64(buf[2])<<16|int64(buf[3])<<8, 0)
	if time.Since(tsign) > period {
		return fmt.Errorf("%w: pass token expired, signed at %s, period %s", ErrExpired, tsign, period)
	}

	return nil
}
