package smtpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/iprev"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/subjectpass"
	"github.com/mjl-/mox/tlsrpt"
)

type delivery struct {
	tls              bool
	m                *store.Message
	dataFile         *os.File
	smtpRcptTo       smtp.Path // As used in SMTP, possibly address of alias.
	deliverTo        smtp.Path // To deliver to, either smtpRcptTo or an alias member address.
	destination      config.Destination
	canonicalAddress string
	acc              *store.Account
	msgTo            []message.Address
	msgCc            []message.Address
	msgFrom          smtp.Address
	dnsBLs           []dns.Domain
	dmarcUse         bool
	dmarcResult      dmarc.Result
	dkimResults      []dkim.Result
	iprevStatus      iprev.Status
}

type analysis struct {
	d                   delivery
	accept              bool
	mailbox             string
	code                int
	secode              string
	userError           bool
	errmsg              string
	err                 error              // For our own logging, not sent to remote.
	dmarcReport         *dmarcrpt.Feedback // Validated DMARC aggregate report, not yet stored.
	tlsReport           *tlsrpt.Report     // Validated TLS report, not yet stored.
	reason              string             // If non-empty, reason for this decision. Can be one of reputationMethod and a few other tokens.
	dmarcOverrideReason string             // If set, one of dmarcrpt.PolicyOverride
	// Additional headers to add during delivery. Used for reasons a message to a
	// dmarc/tls reporting address isn't processed.
	headers string
}

const (
	reasonListAllow         = "list-allow"
	reasonDMARCPolicy       = "dmarc-policy"
	reasonReputationError   = "reputation-error"
	reasonReporting         = "reporting"
	reasonSPFPolicy         = "spf-policy"
	reasonJunkClassifyError = "junk-classify-error"
	reasonJunkFilterError   = "junk-filter-error"
	reasonGiveSubjectpass   = "give-subjectpass"
	reasonNoBadSignals      = "no-bad-signals"
	reasonJunkContent       = "junk-content"
	reasonJunkContentStrict = "junk-content-strict"
	reasonDNSBlocklisted    = "dns-blocklisted"
	reasonSubjectpass       = "subjectpass"
	reasonSubjectpassError  = "subjectpass-error"
	reasonIPrev             = "iprev"     // No or mild junk reputation signals, and bad iprev.
	reasonHighRate          = "high-rate" // Too many messages, not added to rejects.
)

func isListDomain(d delivery, ld dns.Domain) bool {
	if d.m.MailFromValidated && ld.Name() == d.m.MailFromDomain {
		return true
	}
	for _, r := range d.dkimResults {
		if r.Status == dkim.StatusPass && r.Sig.Domain == ld {
			return true
		}
	}
	return false
}

func analyze(ctx context.Context, log mlog.Log, resolver dns.Resolver, d delivery) analysis {
	var headers string

	// We don't want to let a single IP or network deliver too many messages to an
	// account. They may fill up the mailbox, either with messages that have to be
	// purged, or by filling the disk. We check both cases for IP's and networks.
	var rateError bool // Whether returned error represents a rate error.
	err := d.acc.DB.Read(ctx, func(tx *bstore.Tx) (retErr error) {
		now := time.Now()
		defer func() {
			log.Debugx("checking message and size delivery rates", retErr, slog.Duration("duration", time.Since(now)))
		}()

		checkCount := func(msg store.Message, window time.Duration, limit int) {
			if retErr != nil {
				return
			}
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(msg)
			q.FilterGreater("Received", now.Add(-window))
			q.FilterEqual("Expunged", false)
			n, err := q.Count()
			if err != nil {
				retErr = err
				return
			}
			if n >= limit {
				rateError = true
				retErr = fmt.Errorf("more than %d messages in past %s from your ip/network", limit, window)
			}
		}

		checkSize := func(msg store.Message, window time.Duration, limit int64) {
			if retErr != nil {
				return
			}
			q := bstore.QueryTx[store.Message](tx)
			q.FilterNonzero(msg)
			q.FilterGreater("Received", now.Add(-window))
			q.FilterEqual("Expunged", false)
			size := d.m.Size
			err := q.ForEach(func(v store.Message) error {
				size += v.Size
				return nil
			})
			if err != nil {
				retErr = err
				return
			}
			if size > limit {
				rateError = true
				retErr = fmt.Errorf("more than %d bytes in past %s from your ip/network", limit, window)
			}
		}

		// todo future: make these configurable
		// todo: should we have a limit for forwarded messages? they are stored with empty RemoteIPMasked*

		const day = 24 * time.Hour
		checkCount(store.Message{RemoteIPMasked1: d.m.RemoteIPMasked1}, time.Minute, limitIPMasked1MessagesPerMinute)
		checkCount(store.Message{RemoteIPMasked1: d.m.RemoteIPMasked1}, day, 20*500)
		checkCount(store.Message{RemoteIPMasked2: d.m.RemoteIPMasked2}, time.Minute, 1500)
		checkCount(store.Message{RemoteIPMasked2: d.m.RemoteIPMasked2}, day, 20*1500)
		checkCount(store.Message{RemoteIPMasked3: d.m.RemoteIPMasked3}, time.Minute, 4500)
		checkCount(store.Message{RemoteIPMasked3: d.m.RemoteIPMasked3}, day, 20*4500)

		const MB = 1024 * 1024
		checkSize(store.Message{RemoteIPMasked1: d.m.RemoteIPMasked1}, time.Minute, limitIPMasked1SizePerMinute)
		checkSize(store.Message{RemoteIPMasked1: d.m.RemoteIPMasked1}, day, 3*1000*MB)
		checkSize(store.Message{RemoteIPMasked2: d.m.RemoteIPMasked2}, time.Minute, 3000*MB)
		checkSize(store.Message{RemoteIPMasked2: d.m.RemoteIPMasked2}, day, 3*3000*MB)
		checkSize(store.Message{RemoteIPMasked3: d.m.RemoteIPMasked3}, time.Minute, 9000*MB)
		checkSize(store.Message{RemoteIPMasked3: d.m.RemoteIPMasked3}, day, 3*9000*MB)

		return retErr
	})
	if err != nil && !rateError {
		log.Errorx("checking delivery rates", err)
		metricDelivery.WithLabelValues("checkrates", "").Inc()
		return analysis{d, false, "", smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing", err, nil, nil, reasonReputationError, "", headers}
	} else if err != nil {
		log.Debugx("refusing due to high delivery rate", err)
		metricDelivery.WithLabelValues("highrate", "").Inc()
		return analysis{d, false, "", smtp.C452StorageFull, smtp.SeMailbox2Full2, true, err.Error(), err, nil, nil, reasonHighRate, "", headers}
	}

	mailbox := d.destination.Mailbox
	if mailbox == "" {
		mailbox = "Inbox"
	}

	// If destination mailbox has a mailing list domain (for SPF/DKIM) configured,
	// check it for a pass.
	rs := store.MessageRuleset(log, d.destination, d.m, d.m.MsgPrefix, d.dataFile)
	if rs != nil {
		mailbox = rs.Mailbox
	}
	if rs != nil && !rs.ListAllowDNSDomain.IsZero() {
		// todo: on temporary failures, reject temporarily?
		if isListDomain(d, rs.ListAllowDNSDomain) {
			d.m.IsMailingList = true
			return analysis{d: d, accept: true, mailbox: mailbox, reason: reasonListAllow, dmarcOverrideReason: string(dmarcrpt.PolicyOverrideMailingList), headers: headers}
		}
	}

	var dmarcOverrideReason string

	// For forwarded messages, we have different junk analysis. We don't reject for
	// failing DMARC, and we clear fields that could implicate the forwarding mail
	// server during future classifications on incoming messages (the forwarding mail
	// server isn't responsible for the message).
	if rs != nil && rs.IsForward {
		d.dmarcUse = false
		d.m.IsForward = true
		d.m.RemoteIPMasked1 = ""
		d.m.RemoteIPMasked2 = ""
		d.m.RemoteIPMasked3 = ""
		d.m.OrigEHLODomain = d.m.EHLODomain
		d.m.EHLODomain = ""
		d.m.MailFromDomain = "" // Still available in MailFrom.
		d.m.OrigDKIMDomains = d.m.DKIMDomains
		dkimdoms := []string{}
		for _, dom := range d.m.DKIMDomains {
			if dom != rs.VerifiedDNSDomain.Name() {
				dkimdoms = append(dkimdoms, dom)
			}
		}
		d.m.DKIMDomains = dkimdoms
		dmarcOverrideReason = string(dmarcrpt.PolicyOverrideForwarded)
		log.Info("forwarded message, clearing identifying signals of forwarding mail server")
	}

	assignMailbox := func(tx *bstore.Tx) error {
		// Set message MailboxID to which mail will be delivered. Reputation is
		// per-mailbox. If referenced mailbox is not found (e.g. does not yet exist), we
		// can still determine a reputation because we also base it on outgoing
		// messages and those are account-global.
		mb, err := d.acc.MailboxFind(tx, mailbox)
		if err != nil {
			return fmt.Errorf("finding destination mailbox: %w", err)
		}
		if mb != nil {
			// We want to deliver to mb.ID, but this message may be rejected and sent to the
			// Rejects mailbox instead, with MailboxID overwritten. Record the ID in
			// MailboxDestinedID too. If the message is later moved out of the Rejects mailbox,
			// we'll adjust the MailboxOrigID so it gets taken into account during reputation
			// calculating in future deliveries. If we end up delivering to the intended
			// mailbox (i.e. not rejecting), MailboxDestinedID is cleared during delivery so we
			// don't store it unnecessarily.
			d.m.MailboxID = mb.ID
			d.m.MailboxDestinedID = mb.ID
		} else {
			log.Debug("mailbox not found in database", slog.String("mailbox", mailbox))
		}
		return nil
	}

	reject := func(code int, secode string, errmsg string, err error, reason string) analysis {
		// We may have set MailboxDestinedID below already while we had a transaction. If
		// not, do it now. This makes it possible to use the per-mailbox reputation when a
		// user moves the message out of the Rejects mailbox to the intended mailbox
		// (typically Inbox).
		if d.m.MailboxDestinedID == 0 {
			var mberr error
			d.acc.WithRLock(func() {
				mberr = d.acc.DB.Read(ctx, func(tx *bstore.Tx) error {
					return assignMailbox(tx)
				})
			})
			if mberr != nil {
				return analysis{d, false, mailbox, smtp.C451LocalErr, smtp.SeSys3Other0, false, "error processing", err, nil, nil, reasonReputationError, dmarcOverrideReason, headers}
			}
			d.m.MailboxID = 0 // We plan to reject, no need to set intended MailboxID.
		}

		accept := false
		if rs != nil && rs.AcceptRejectsToMailbox != "" {
			accept = true
			mailbox = rs.AcceptRejectsToMailbox
			d.m.IsReject = true
			// Don't draw attention, but don't go so far as to mark as junk.
			d.m.Seen = true
			log.Info("accepting reject to configured mailbox due to ruleset")
		}
		return analysis{d, accept, mailbox, code, secode, err == nil, errmsg, err, nil, nil, reason, dmarcOverrideReason, headers}
	}

	if d.dmarcUse && d.dmarcResult.Reject {
		return reject(smtp.C550MailboxUnavail, smtp.SePol7MultiAuthFails26, "rejecting per dmarc policy", nil, reasonDMARCPolicy)
	}
	// todo: should we also reject messages that have a dmarc pass but an spf record "v=spf1 -all"? suggested by m3aawg best practices.

	// If destination is the DMARC reporting mailbox, do additional checks and keep
	// track of the report. We'll check reputation, defaulting to accept.
	var dmarcReport *dmarcrpt.Feedback
	if d.destination.DMARCReports {
		// Messages with DMARC aggregate reports must have a DMARC pass. ../rfc/7489:1866
		if d.dmarcResult.Status != dmarc.StatusPass {
			log.Info("received dmarc aggregate report without dmarc pass, not processing as dmarc report")
			headers += "X-Mox-DMARCReport-Error: no DMARC pass\r\n"
		} else if report, err := dmarcrpt.ParseMessageReport(log.Logger, store.FileMsgReader(d.m.MsgPrefix, d.dataFile)); err != nil {
			log.Infox("parsing dmarc aggregate report", err)
			headers += "X-Mox-DMARCReport-Error: could not parse report\r\n"
		} else if d, err := dns.ParseDomain(report.PolicyPublished.Domain); err != nil {
			log.Infox("parsing domain in dmarc aggregate report", err)
			headers += "X-Mox-DMARCReport-Error: could not parse domain in published policy\r\n"
		} else if _, ok := mox.Conf.Domain(d); !ok {
			log.Info("dmarc aggregate report for domain not configured, ignoring", slog.Any("domain", d))
			headers += "X-Mox-DMARCReport-Error: published policy domain unrecognized\r\n"
		} else if report.ReportMetadata.DateRange.End > time.Now().Unix()+60 {
			log.Info("dmarc aggregate report with end date in the future, ignoring", slog.Any("domain", d), slog.Time("end", time.Unix(report.ReportMetadata.DateRange.End, 0)))
			headers += "X-Mox-DMARCReport-Error: report has end date in the future\r\n"
		} else {
			dmarcReport = report
		}
	}

	// Similar to DMARC reporting, we check for the required DKIM. We'll check
	// reputation, defaulting to accept.
	var tlsReport *tlsrpt.Report
	if d.destination.HostTLSReports || d.destination.DomainTLSReports {
		matchesDomain := func(sigDomain dns.Domain) bool {
			// RFC seems to require exact DKIM domain match with submitt and message From, we
			// also allow msgFrom to be subdomain. ../rfc/8460:322
			return sigDomain == d.msgFrom.Domain || strings.HasSuffix(d.msgFrom.Domain.ASCII, "."+sigDomain.ASCII) && publicsuffix.Lookup(ctx, log.Logger, d.msgFrom.Domain) == publicsuffix.Lookup(ctx, log.Logger, sigDomain)
		}
		// Valid DKIM signature for domain must be present. We take "valid" to assume
		// "passing", not "syntactically valid". We also check for "tlsrpt" as service.
		// This check is optional, but if anyone goes through the trouble to explicitly
		// list allowed services, they would be surprised to see them ignored.
		// ../rfc/8460:320
		ok := false
		for _, r := range d.dkimResults {
			// The record should have an allowed service "tlsrpt". The RFC mentions it as if
			// the service must be specified explicitly, but the default allowed services for a
			// DKIM record are "*", which includes "tlsrpt". Unless a DKIM record explicitly
			// specifies services (e.g. s=email), a record will work for TLS reports. The DKIM
			// records seen used for TLS reporting in the wild don't explicitly set "s" for
			// services.
			// ../rfc/8460:326
			if r.Status == dkim.StatusPass && matchesDomain(r.Sig.Domain) && r.Sig.Length < 0 && r.Record.ServiceAllowed("tlsrpt") {
				ok = true
				break
			}
		}

		if !ok {
			log.Info("received mail to tlsrpt without acceptable DKIM signature, not processing as tls report")
			headers += "X-Mox-TLSReport-Error: no acceptable DKIM signature\r\n"
		} else if reportJSON, err := tlsrpt.ParseMessage(log.Logger, store.FileMsgReader(d.m.MsgPrefix, d.dataFile)); err != nil {
			log.Infox("parsing tls report", err)
			headers += "X-Mox-TLSReport-Error: could not parse TLS report\r\n"
		} else {
			var known bool
			for _, p := range reportJSON.Policies {
				log.Info("tlsrpt policy domain", slog.String("domain", p.Policy.Domain))
				if d, err := dns.ParseDomain(p.Policy.Domain); err != nil {
					log.Infox("parsing domain in tls report", err)
				} else if _, ok := mox.Conf.Domain(d); ok || d == mox.Conf.Static.HostnameDomain {
					known = true
					break
				}
			}
			if !known {
				log.Info("tls report without one of configured domains, ignoring")
				headers += "X-Mox-TLSReport-Error: report for unknown domain\r\n"
			} else {
				report := reportJSON.Convert()
				tlsReport = &report
			}
		}
	}

	// Determine if message is acceptable based on DMARC domain, DKIM identities, or
	// host-based reputation.
	var isjunk *bool
	var conclusive bool
	var method reputationMethod
	var reason string
	d.acc.WithRLock(func() {
		err = d.acc.DB.Read(ctx, func(tx *bstore.Tx) error {
			if err := assignMailbox(tx); err != nil {
				return err
			}

			isjunk, conclusive, method, err = reputation(tx, log, d.m)
			reason = string(method)
			return err
		})
	})
	if err != nil {
		log.Infox("determining reputation", err, slog.Any("message", d.m))
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonReputationError)
	}
	log.Info("reputation analyzed",
		slog.Bool("conclusive", conclusive),
		slog.Any("isjunk", isjunk),
		slog.String("method", string(method)))
	if conclusive {
		if !*isjunk {
			return analysis{d: d, accept: true, mailbox: mailbox, dmarcReport: dmarcReport, tlsReport: tlsReport, reason: reason, dmarcOverrideReason: dmarcOverrideReason, headers: headers}
		}
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, string(method))
	} else if dmarcReport != nil || tlsReport != nil {
		log.Info("accepting message with dmarc aggregate report or tls report without reputation")
		return analysis{d: d, accept: true, mailbox: mailbox, dmarcReport: dmarcReport, tlsReport: tlsReport, reason: reasonReporting, dmarcOverrideReason: dmarcOverrideReason, headers: headers}
	}
	// If there was no previous message from sender or its domain, and we have an SPF
	// (soft)fail, reject the message.
	switch method {
	case methodDKIMSPF, methodIP1, methodIP2, methodIP3, methodNone:
		switch d.m.MailFromValidation {
		case store.ValidationFail, store.ValidationSoftfail:
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reasonSPFPolicy)
		}
	}

	// Senders without reputation and without iprev pass, are likely spam.
	var suspiciousIPrevFail bool
	switch method {
	case methodDKIMSPF, methodIP1, methodIP2, methodIP3, methodNone:
		suspiciousIPrevFail = d.iprevStatus != iprev.StatusPass
	}

	// With already a mild junk signal, an iprev fail on top is enough to reject.
	if suspiciousIPrevFail && isjunk != nil && *isjunk {
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reasonIPrev)
	}

	var subjectpassKey string
	conf, _ := d.acc.Conf()
	if conf.SubjectPass.Period > 0 {
		subjectpassKey, err = d.acc.Subjectpass(d.canonicalAddress)
		if err != nil {
			log.Errorx("get key for verifying subject token", err)
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonSubjectpassError)
		}
		err = subjectpass.Verify(log.Logger, d.dataFile, []byte(subjectpassKey), conf.SubjectPass.Period)
		pass := err == nil
		log.Infox("pass by subject token", err, slog.Bool("pass", pass))
		if pass {
			return analysis{d: d, accept: true, mailbox: mailbox, reason: reasonSubjectpass, dmarcOverrideReason: dmarcOverrideReason, headers: headers}
		}
	}

	reason = reasonNoBadSignals
	accept := true
	var junkSubjectpass bool
	f, jf, err := d.acc.OpenJunkFilter(ctx, log)
	if err == nil {
		defer func() {
			err := f.Close()
			log.Check(err, "closing junkfilter")
		}()
		contentProb, _, _, _, err := f.ClassifyMessageReader(ctx, store.FileMsgReader(d.m.MsgPrefix, d.dataFile), d.m.Size)
		if err != nil {
			log.Errorx("testing for spam", err)
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonJunkClassifyError)
		}
		// todo: if isjunk is not nil (i.e. there was inconclusive reputation), use it in the probability calculation. give reputation a score of 0.25 or .75 perhaps?
		// todo: if there aren't enough historic messages, we should just let messages in.
		// todo: we could require nham and nspam to be above a certain number when there were plenty of words in the message, and in the database. can indicate a spammer is misspelling words. however, it can also mean a message in a different language/script...

		// If we don't accept, we may still respond with a "subjectpass" hint below.
		// We add some jitter to the threshold we use. So we don't act as too easy an
		// oracle for words that are a strong indicator of haminess.
		// todo: we should rate-limit uses of the junkfilter.
		jitter := (jitterRand.Float64() - 0.5) / 10
		threshold := jf.Threshold + jitter

		rcptToMatch := func(l []message.Address) bool {
			// todo: we use Go's net/mail to parse message header addresses. it does not allow empty quoted strings (contrary to spec), leaving To empty. so we don't verify To address for that unusual case for now. ../rfc/5322:961 ../rfc/5322:743
			if d.smtpRcptTo.Localpart == "" {
				return true
			}
			for _, a := range l {
				dom, err := dns.ParseDomain(a.Host)
				if err != nil {
					continue
				}
				lp, err := smtp.ParseLocalpart(a.User)
				if err == nil && dom == d.smtpRcptTo.IPDomain.Domain && lp == d.smtpRcptTo.Localpart {
					return true
				}
			}
			return false
		}

		// todo: some of these checks should also apply for reputation-based analysis with a weak signal, e.g. verified dkim/spf signal from new domain.
		// With an iprev fail, non-TLS connection or our address not in To/Cc header, we set a higher bar for content.
		reason = reasonJunkContent
		if suspiciousIPrevFail && threshold > 0.25 {
			threshold = 0.25
			log.Info("setting junk threshold due to iprev fail", slog.Float64("threshold", threshold))
			reason = reasonJunkContentStrict
		} else if !d.tls && threshold > 0.25 {
			threshold = 0.25
			log.Info("setting junk threshold due to plaintext smtp", slog.Float64("threshold", threshold))
			reason = reasonJunkContentStrict
		} else if (rs == nil || !rs.IsForward) && threshold > 0.25 && !rcptToMatch(d.msgTo) && !rcptToMatch(d.msgCc) {
			// A common theme in junk messages is your recipient address not being in the To/Cc
			// headers. We may be in Bcc, but that's unusual for first-time senders. Some
			// providers (e.g. gmail) does not DKIM-sign Bcc headers, so junk messages can be
			// sent with matching Bcc headers. We don't get here for known senders.
			threshold = 0.25
			log.Info("setting junk threshold due to smtp rcpt to and message to/cc address mismatch", slog.Float64("threshold", threshold))
			reason = reasonJunkContentStrict
		}
		accept = contentProb <= threshold
		junkSubjectpass = contentProb < threshold-0.2
		log.Info("content analyzed",
			slog.Bool("accept", accept),
			slog.Float64("contentprob", contentProb),
			slog.Bool("subjectpass", junkSubjectpass))
	} else if err != store.ErrNoJunkFilter {
		log.Errorx("open junkfilter", err)
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonJunkFilterError)
	}

	// If content looks good, we'll still look at DNS block lists for a reason to
	// reject. We normally won't get here if we've communicated with this sender
	// before.
	var dnsblocklisted bool
	if accept {
		blocked := func(zone dns.Domain) bool {
			dnsblctx, dnsblcancel := context.WithTimeout(ctx, 30*time.Second)
			defer dnsblcancel()
			if !checkDNSBLHealth(dnsblctx, log, resolver, zone) {
				log.Info("dnsbl not healthy, skipping", slog.Any("zone", zone))
				return false
			}

			status, expl, err := dnsbl.Lookup(dnsblctx, log.Logger, resolver, zone, net.ParseIP(d.m.RemoteIP))
			dnsblcancel()
			if status == dnsbl.StatusFail {
				log.Info("rejecting due to listing in dnsbl", slog.Any("zone", zone), slog.String("explanation", expl))
				return true
			} else if err != nil {
				log.Infox("dnsbl lookup", err, slog.Any("zone", zone), slog.Any("status", status))
			}
			return false
		}

		// Note: We don't check in parallel, we are in no hurry to accept possible spam.
		for _, zone := range d.dnsBLs {
			if blocked(zone) {
				accept = false
				dnsblocklisted = true
				reason = reasonDNSBlocklisted
				break
			}
		}
	}

	if accept {
		return analysis{d: d, accept: true, mailbox: mailbox, reason: reasonNoBadSignals, dmarcOverrideReason: dmarcOverrideReason, headers: headers}
	}

	if subjectpassKey != "" && d.dmarcResult.Status == dmarc.StatusPass && method == methodNone && (dnsblocklisted || junkSubjectpass) {
		log.Info("permanent reject with subjectpass hint of moderately spammy email without reputation")
		pass := subjectpass.Generate(log.Logger, d.msgFrom, []byte(subjectpassKey), time.Now())
		return reject(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, subjectpass.Explanation+pass, nil, reasonGiveSubjectpass)
	}

	return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reason)
}
