package queue

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/exp/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

var (
	metricDMARCReportFailure = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_dmarcreport_failure_total",
			Help: "Permanent failures to deliver a DMARC report.",
		},
	)
)

func deliverDSNFailure(ctx context.Context, log mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string) {
	const subject = "mail delivery failed"
	message := fmt.Sprintf(`
Delivery has failed permanently for your email to:

	%s

No further deliveries will be attempted.

Error during the last delivery attempt:

	%s
`, m.Recipient().XString(m.SMTPUTF8), errmsg)

	deliverDSN(ctx, log, m, remoteMTA, secodeOpt, errmsg, true, nil, subject, message)
}

func deliverDSNDelay(ctx context.Context, log mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string, retryUntil time.Time) {
	// Should not happen, but doesn't hurt to prevent sending delayed delivery
	// notifications for DMARC reports. We don't want to waste postmaster attention.
	if m.IsDMARCReport {
		return
	}

	const subject = "mail delivery delayed"
	message := fmt.Sprintf(`
Delivery has been delayed of your email to:

	%s

Next attempts to deliver: in 4 hours, 8 hours and 16 hours.
If these attempts all fail, you will receive a notice.

Error during the last delivery attempt:

	%s
`, m.Recipient().XString(false), errmsg)

	deliverDSN(ctx, log, m, remoteMTA, secodeOpt, errmsg, false, &retryUntil, subject, message)
}

// We only queue DSNs for delivery failures for emails submitted by authenticated
// users. So we are delivering to local users. ../rfc/5321:1466
// ../rfc/5321:1494
// ../rfc/7208:490
func deliverDSN(ctx context.Context, log mlog.Log, m Msg, remoteMTA dsn.NameIP, secodeOpt, errmsg string, permanent bool, retryUntil *time.Time, subject, textBody string) {
	kind := "delayed delivery"
	if permanent {
		kind = "failure"
	}

	qlog := func(text string, err error) {
		log.Errorx("queue dsn: "+text+": sender will not be informed about dsn", err, slog.String("sender", m.Sender().XString(m.SMTPUTF8)), slog.String("kind", kind))
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
		MessageID:  mox.MessageIDGen(false),
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

	msgData = append([]byte("Return-Path: <"+dsnMsg.From.XString(m.SMTPUTF8)+">\r\n"), msgData...)

	mailbox := "Inbox"
	senderAccount := m.SenderAccount
	if m.IsDMARCReport {
		// senderAccount should already by postmaster, but doesn't hurt to ensure it.
		senderAccount = mox.Conf.Static.Postmaster.Account
	}
	acc, err := store.OpenAccount(log, senderAccount)
	if err != nil {
		acc, err = store.OpenAccount(log, mox.Conf.Static.Postmaster.Account)
		if err != nil {
			qlog("looking up postmaster account after sender account was not found", err)
			return
		}
		mailbox = mox.Conf.Static.Postmaster.Mailbox
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "queue dsn: closing account", slog.String("sender", m.Sender().XString(m.SMTPUTF8)), slog.String("kind", kind))
	}()

	msgFile, err := store.CreateMessageTemp(log, "queue-dsn")
	if err != nil {
		qlog("creating temporary message file", err)
		return
	}
	defer store.CloseRemoveTempFile(log, msgFile, "dsn message")

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

	// If this is a DMARC report, deliver it as seen message to a submailbox of the
	// postmaster mailbox. We mark it as seen so it doesn't waste postmaster attention,
	// but we deliver them so they can be checked in case of problems.
	if m.IsDMARCReport {
		mailbox = fmt.Sprintf("%s/dmarc", mox.Conf.Static.Postmaster.Mailbox)
		msg.Seen = true
		metricDMARCReportFailure.Inc()
		log.Info("delivering dsn for failure to deliver outgoing dmarc report")
	}

	acc.WithWLock(func() {
		if err := acc.DeliverMailbox(log, mailbox, msg, msgFile); err != nil {
			qlog("delivering dsn to mailbox", err)
			return
		}
	})
}
