package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
)

func cmdGentestdata(c *cmd) {
	c.unlisted = true
	c.params = "dest-dir"
	c.help = `Generate a data directory populated, for testing upgrades.`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	destDataDir, err := filepath.Abs(args[0])
	xcheckf(err, "making destination directory an absolute path")

	if _, err := os.Stat(destDataDir); err == nil {
		log.Fatalf("destination directory already exists, refusing to generate test data")
	}
	err = os.MkdirAll(destDataDir, 0770)
	xcheckf(err, "creating destination data directory")
	err = os.MkdirAll(filepath.Join(destDataDir, "tmp"), 0770)
	xcheckf(err, "creating tmp directory")

	tempfile := func() *os.File {
		f, err := os.CreateTemp(filepath.Join(destDataDir, "tmp"), "temp")
		xcheckf(err, "creating temp file")
		return f
	}

	log := mlog.New("gentestdata")
	ctxbg := context.Background()
	mox.Conf.Log[""] = mlog.LevelInfo
	mlog.SetConfig(mox.Conf.Log)

	const domainsConf = `
Domains:
	mox.example: nil
	☺.example: nil
Accounts:
	test0:
		Domain: mox.example
		Destinations:
			test0@mox.example: nil
	test1:
		Domain: mox.example
		Destinations:
			test1@mox.example: nil
	test2:
		Domain: ☺.example
		Destinations:
			☹@☺.example: nil
		JunkFilter:
			Threshold: 0.95
			Params:
				Twograms: true
				MaxPower: 0.1
				TopWords: 10
				IgnoreWords: 0.1
`

	mox.ConfigStaticPath = "/tmp/mox-bogus/mox.conf"
	mox.ConfigDynamicPath = "/tmp/mox-bogus/domains.conf"
	mox.Conf.DynamicLastCheck = time.Now() // Should prevent warning.
	mox.Conf.Static = config.Static{
		DataDir: destDataDir,
	}
	err = sconf.Parse(strings.NewReader(domainsConf), &mox.Conf.Dynamic)
	xcheckf(err, "parsing domains config")

	const dmarcReport = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>10051505501689795560</report_id>
    <date_range>
      <begin>1596412800</begin>
      <end>1596499199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>mox.example</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.1</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.org</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.org</domain>
        <result>pass</result>
        <selector>example</selector>
      </dkim>
      <spf>
        <domain>example.org</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`

	const tlsReport = `{
     "organization-name": "Company-X",
     "date-range": {
       "start-datetime": "2016-04-01T00:00:00Z",
       "end-datetime": "2016-04-01T23:59:59Z"
     },
     "contact-info": "sts-reporting@company-x.example",
     "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
     "policies": [{
       "policy": {
         "policy-type": "sts",
         "policy-string": ["version: STSv1","mode: testing",
               "mx: *.mail.company-y.example","max_age: 86400"],
         "policy-domain": "mox.example",
         "mx-host": ["*.mail.company-y.example"]
       },
       "summary": {
         "total-successful-session-count": 5326,
         "total-failure-session-count": 303
       },
       "failure-details": [{
         "result-type": "certificate-expired",
         "sending-mta-ip": "2001:db8:abcd:0012::1",
         "receiving-mx-hostname": "mx1.mail.company-y.example",
         "failed-session-count": 100
       }, {
         "result-type": "starttls-not-supported",
         "sending-mta-ip": "2001:db8:abcd:0013::1",
         "receiving-mx-hostname": "mx2.mail.company-y.example",
         "receiving-ip": "203.0.113.56",
         "failed-session-count": 200,
         "additional-information": "https://reports.company-x.example/report_info ? id = 5065427 c - 23 d3# StarttlsNotSupported "
       }, {
         "result-type": "validation-failure",
         "sending-mta-ip": "198.51.100.62",
         "receiving-ip": "203.0.113.58",
         "receiving-mx-hostname": "mx-backup.mail.company-y.example",
         "failed-session-count": 3,
         "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
       }]
     }]
   }`

	err = os.WriteFile(filepath.Join(destDataDir, "moxversion"), []byte(moxvar.Version), 0660)
	xcheckf(err, "writing moxversion")

	// Populate dmarc.db.
	err = dmarcdb.Init()
	xcheckf(err, "dmarcdb init")
	report, err := dmarcrpt.ParseReport(strings.NewReader(dmarcReport))
	xcheckf(err, "parsing dmarc report")
	err = dmarcdb.AddReport(ctxbg, report, dns.Domain{ASCII: "mox.example"})
	xcheckf(err, "adding dmarc report")

	// Populate mtasts.db.
	err = mtastsdb.Init(false)
	xcheckf(err, "mtastsdb init")
	mtastsPolicy := mtasts.Policy{
		Version: "STSv1",
		Mode:    mtasts.ModeTesting,
		MX: []mtasts.STSMX{
			{Domain: dns.Domain{ASCII: "mx1.example.com"}},
			{Domain: dns.Domain{ASCII: "mx2.example.com"}},
			{Domain: dns.Domain{ASCII: "backup-example.com"}, Wildcard: true},
		},
		MaxAgeSeconds: 1296000,
	}
	err = mtastsdb.Upsert(ctxbg, dns.Domain{ASCII: "mox.example"}, "123", &mtastsPolicy)
	xcheckf(err, "adding mtastsdb report")

	// Populate tlsrpt.db.
	err = tlsrptdb.Init()
	xcheckf(err, "tlsrptdb init")
	tlsr, err := tlsrpt.Parse(strings.NewReader(tlsReport))
	xcheckf(err, "parsing tls report")
	err = tlsrptdb.AddReport(ctxbg, dns.Domain{ASCII: "mox.example"}, "tlsrpt@mox.example", tlsr)
	xcheckf(err, "adding tls report")

	// Populate queue, with a message.
	err = queue.Init()
	xcheckf(err, "queue init")
	mailfrom := smtp.Path{Localpart: "other", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "other.example"}}}
	rcptto := smtp.Path{Localpart: "test0", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	prefix := []byte{}
	mf := tempfile()
	xcheckf(err, "temp file for queue message")
	defer mf.Close()
	const qmsg = "From: <test0@mox.example>\r\nTo: <other@remote.example>\r\nSubject: test\r\n\r\nthe message...\r\n"
	_, err = fmt.Fprint(mf, qmsg)
	xcheckf(err, "writing message")
	_, err = queue.Add(ctxbg, log, "test0", mailfrom, rcptto, false, false, int64(len(qmsg)), "<test@localhost>", prefix, mf, nil, true)
	xcheckf(err, "enqueue message")

	// Create three accounts.
	// First account without messages.
	accTest0, err := store.OpenAccount("test0")
	xcheckf(err, "open account test0")
	err = accTest0.ThreadingWait(log)
	xcheckf(err, "wait for threading to finish")
	err = accTest0.Close()
	xcheckf(err, "close account")

	// Second account with one message.
	accTest1, err := store.OpenAccount("test1")
	xcheckf(err, "open account test1")
	err = accTest1.ThreadingWait(log)
	xcheckf(err, "wait for threading to finish")
	err = accTest1.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		inbox, err := bstore.QueryTx[store.Mailbox](tx).FilterNonzero(store.Mailbox{Name: "Inbox"}).Get()
		xcheckf(err, "looking up inbox")
		const msg = "From: <other@remote.example>\r\nTo: <test1@mox.example>\r\nSubject: test\r\n\r\nthe message...\r\n"
		m := store.Message{
			MailboxID:          inbox.ID,
			MailboxOrigID:      inbox.ID,
			MailboxDestinedID:  inbox.ID,
			RemoteIP:           "1.2.3.4",
			RemoteIPMasked1:    "1.2.3.4",
			RemoteIPMasked2:    "1.2.3.0",
			RemoteIPMasked3:    "1.2.0.0",
			EHLODomain:         "other.example",
			MailFrom:           "other@remote.example",
			MailFromLocalpart:  smtp.Localpart("other"),
			MailFromDomain:     "remote.example",
			RcptToLocalpart:    "test1",
			RcptToDomain:       "mox.example",
			MsgFromLocalpart:   "other",
			MsgFromDomain:      "remote.example",
			MsgFromOrgDomain:   "remote.example",
			EHLOValidated:      true,
			MailFromValidated:  true,
			MsgFromValidated:   true,
			EHLOValidation:     store.ValidationStrict,
			MailFromValidation: store.ValidationPass,
			MsgFromValidation:  store.ValidationStrict,
			DKIMDomains:        []string{"other.example"},
			Size:               int64(len(msg)),
		}
		mf := tempfile()
		xcheckf(err, "creating temp file for delivery")
		_, err = fmt.Fprint(mf, msg)
		xcheckf(err, "writing deliver message to file")
		err = accTest1.DeliverMessage(log, tx, &m, mf, true, false, true, false)
		xcheckf(err, "add message to account test1")
		err = mf.Close()
		xcheckf(err, "closing file")

		err = tx.Get(&inbox)
		xcheckf(err, "get inbox")
		inbox.Add(m.MailboxCounts())
		err = tx.Update(&inbox)
		xcheckf(err, "update inbox")

		return nil
	})
	xcheckf(err, "write transaction with new message")
	err = accTest1.Close()
	xcheckf(err, "close account")

	// Third account with two messages and junkfilter.
	accTest2, err := store.OpenAccount("test2")
	xcheckf(err, "open account test2")
	err = accTest2.ThreadingWait(log)
	xcheckf(err, "wait for threading to finish")
	err = accTest2.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		inbox, err := bstore.QueryTx[store.Mailbox](tx).FilterNonzero(store.Mailbox{Name: "Inbox"}).Get()
		xcheckf(err, "looking up inbox")
		const msg0 = "From: <other@remote.example>\r\nTo: <☹@xn--74h.example>\r\nSubject: test\r\n\r\nthe message...\r\n"
		m0 := store.Message{
			MailboxID:          inbox.ID,
			MailboxOrigID:      inbox.ID,
			MailboxDestinedID:  inbox.ID,
			RemoteIP:           "::1",
			RemoteIPMasked1:    "::",
			RemoteIPMasked2:    "::",
			RemoteIPMasked3:    "::",
			EHLODomain:         "other.example",
			MailFrom:           "other@remote.example",
			MailFromLocalpart:  smtp.Localpart("other"),
			MailFromDomain:     "remote.example",
			RcptToLocalpart:    "☹",
			RcptToDomain:       "☺.example",
			MsgFromLocalpart:   "other",
			MsgFromDomain:      "remote.example",
			MsgFromOrgDomain:   "remote.example",
			EHLOValidated:      true,
			MailFromValidated:  true,
			MsgFromValidated:   true,
			EHLOValidation:     store.ValidationStrict,
			MailFromValidation: store.ValidationPass,
			MsgFromValidation:  store.ValidationStrict,
			DKIMDomains:        []string{"other.example"},
			Size:               int64(len(msg0)),
		}
		mf0 := tempfile()
		xcheckf(err, "creating temp file for delivery")
		_, err = fmt.Fprint(mf0, msg0)
		xcheckf(err, "writing deliver message to file")
		err = accTest2.DeliverMessage(log, tx, &m0, mf0, true, false, false, false)
		xcheckf(err, "add message to account test2")
		err = mf0.Close()
		xcheckf(err, "closing file")

		err = tx.Get(&inbox)
		xcheckf(err, "get inbox")
		inbox.Add(m0.MailboxCounts())
		err = tx.Update(&inbox)
		xcheckf(err, "update inbox")

		sent, err := bstore.QueryTx[store.Mailbox](tx).FilterNonzero(store.Mailbox{Name: "Sent"}).Get()
		xcheckf(err, "looking up inbox")
		const prefix1 = "Extra: test\r\n"
		const msg1 = "From: <other@remote.example>\r\nTo: <☹@xn--74h.example>\r\nSubject: test\r\n\r\nthe message...\r\n"
		m1 := store.Message{
			MailboxID:         sent.ID,
			MailboxOrigID:     sent.ID,
			MailboxDestinedID: sent.ID,
			Flags:             store.Flags{Seen: true, Junk: true},
			Size:              int64(len(prefix1) + len(msg1)),
			MsgPrefix:         []byte(prefix1),
		}
		mf1 := tempfile()
		xcheckf(err, "creating temp file for delivery")
		_, err = fmt.Fprint(mf1, msg1)
		xcheckf(err, "writing deliver message to file")
		err = accTest2.DeliverMessage(log, tx, &m1, mf1, true, false, false, false)
		xcheckf(err, "add message to account test2")
		err = mf1.Close()
		xcheckf(err, "closing file")

		err = tx.Get(&sent)
		xcheckf(err, "get sent")
		sent.Add(m1.MailboxCounts())
		err = tx.Update(&sent)
		xcheckf(err, "update sent")

		return nil
	})
	xcheckf(err, "write transaction with new message")
	err = accTest2.Close()
	xcheckf(err, "close account")
}
