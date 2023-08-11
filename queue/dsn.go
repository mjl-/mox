package queue

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

func queueDSNFailure(log *mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string) {
	const subject = "mail delivery failed"
	message := fmt.Sprintf(`
Delivery has failed permanently for your email to:

	%s

No further deliveries will be attempted.

Error during the last delivery attempt:

	%s
`, m.Recipient().XString(m.SMTPUTF8), errmsg)

	queueDSN(log, m, remoteMTA, secodeOpt, errmsg, true, nil, subject, message)
}

func queueDSNDelay(log *mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string, retryUntil time.Time) {
	const subject = "mail delivery delayed"
	message := fmt.Sprintf(`
Delivery has been delayed of your email to:

	%s

Next attempts to deliver: in 4 hours, 8 hours and 16 hours.
If these attempts all fail, you will receive a notice.

Error during the last delivery attempt:

	%s
`, m.Recipient().XString(false), errmsg)

	queueDSN(log, m, remoteMTA, secodeOpt, errmsg, false, &retryUntil, subject, message)
}

// We only queue DSNs for delivery failures for emails submitted by authenticated
// users. So we are delivering to local users. ../rfc/5321:1466
// ../rfc/5321:1494
// ../rfc/7208:490
// todo future: when we implement relaying, we should be able to send DSNs to non-local users. and possibly specify a null mailfrom. ../rfc/5321:1503
func queueDSN(log *mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string, permanent bool, retryUntil *time.Time, subject, textBody string) {
	kind := "delayed delivery"
	if permanent {
		kind = "failure"
	}

	qlog := func(text string, err error) {
		log.Errorx("queue dsn: "+text+": sender will not be informed about dsn", err, mlog.Field("sender", m.Sender().XString(m.SMTPUTF8)), mlog.Field("kind", kind))
	}

	msgf, err := os.Open(m.MessagePath())
	if err != nil {
		qlog("opening queued message", err)
		return
	}
	msgr := store.FileMsgReader(m.MsgPrefix, msgf)
	defer func() {
		err := msgr.Close()
		log.Check(err, "closing message reader after queuing dsn")
	}()
	headers, err := message.ReadHeaders(bufio.NewReader(msgr))
	if err != nil {
		qlog("reading headers of queued message", err)
		return
	}

	var action dsn.Action
	var status string
	if permanent {
		status = "5."
		action = dsn.Failed
	} else {
		action = dsn.Delayed
		status = "4."
	}
	if secodeOpt != "" {
		status += secodeOpt
	} else {
		status += "0.0"
	}
	diagCode := errmsg
	if !dsn.HasCode(diagCode) {
		diagCode = status + " " + errmsg
	}

	dsnMsg := &dsn.Message{
		SMTPUTF8:   m.SMTPUTF8,
		From:       smtp.Path{Localpart: "postmaster", IPDomain: dns.IPDomain{Domain: mox.Conf.Static.HostnameDomain}},
		To:         m.Sender(),
		Subject:    subject,
		References: m.MessageID,
		TextBody:   textBody,

		ReportingMTA: mox.Conf.Static.HostnameDomain.ASCII,
		ArrivalDate:  m.Queued,

		Recipients: []dsn.Recipient{
			{
				FinalRecipient:  m.Recipient(),
				Action:          action,
				Status:          status,
				RemoteMTA:       remoteMTA,
				DiagnosticCode:  diagCode,
				LastAttemptDate: *m.LastAttempt,
				WillRetryUntil:  retryUntil,
			},
		},

		Original: headers,
	}
	msgData, err := dsnMsg.Compose(log, m.SMTPUTF8)
	if err != nil {
		qlog("composing dsn", err)
		return
	}

	msgData = append(msgData, []byte("Return-Path: <"+dsnMsg.From.XString(m.SMTPUTF8)+">\r\n")...)

	mailbox := "Inbox"
	acc, err := store.OpenAccount(m.SenderAccount)
	if err != nil {
		acc, err = store.OpenAccount(mox.Conf.Static.Postmaster.Account)
		if err != nil {
			qlog("looking up postmaster account after sender account was not found", err)
			return
		}
		mailbox = mox.Conf.Static.Postmaster.Mailbox
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "queue dsn: closing account", mlog.Field("sender", m.Sender().XString(m.SMTPUTF8)), mlog.Field("kind", kind))
	}()

	msgFile, err := store.CreateMessageTemp("queue-dsn")
	if err != nil {
		qlog("creating temporary message file", err)
		return
	}
	defer func() {
		if msgFile != nil {
			err := os.Remove(msgFile.Name())
			log.Check(err, "removing message file", mlog.Field("path", msgFile.Name()))
			err = msgFile.Close()
			log.Check(err, "closing message file")
		}
	}()

	msgWriter := message.NewWriter(msgFile)
	if _, err := msgWriter.Write(msgData); err != nil {
		qlog("writing dsn message", err)
		return
	}

	msg := &store.Message{
		Received:  time.Now(),
		Size:      msgWriter.Size,
		MsgPrefix: []byte{},
	}
	acc.WithWLock(func() {
		if err := acc.DeliverMailbox(log, mailbox, msg, msgFile, true); err != nil {
			qlog("delivering dsn to mailbox", err)
			return
		}
	})
	err = msgFile.Close()
	log.Check(err, "closing dsn file")
	msgFile = nil
}
