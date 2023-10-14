//go:build !quickstart && !integration

package main

import (
	"context"
	"flag"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, errmsg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %v", errmsg, err)
	}
}

// TestCtl executes commands through ctl. This tests at least the protocols (who
// sends when/what) is tested. We often don't check the actual results, but
// unhandled errors would cause a panic.
func TestCtl(t *testing.T) {
	os.RemoveAll("testdata/ctl/data")
	mox.ConfigStaticPath = filepath.FromSlash("testdata/ctl/mox.conf")
	mox.ConfigDynamicPath = filepath.FromSlash("testdata/ctl/domains.conf")
	if errs := mox.LoadConfig(ctxbg, true, false); len(errs) > 0 {
		t.Fatalf("loading mox config: %v", errs)
	}
	defer store.Switchboard()()

	xlog := mlog.New("ctl")

	testctl := func(fn func(clientctl *ctl)) {
		t.Helper()

		cconn, sconn := net.Pipe()
		clientctl := ctl{conn: cconn, log: xlog}
		serverctl := ctl{conn: sconn, log: xlog}
		go servectlcmd(ctxbg, &serverctl, func() {})
		fn(&clientctl)
		cconn.Close()
		sconn.Close()
	}

	// "deliver"
	testctl(func(ctl *ctl) {
		ctlcmdDeliver(ctl, "mjl@mox.example")
	})

	// "setaccountpassword"
	testctl(func(ctl *ctl) {
		ctlcmdSetaccountpassword(ctl, "mjl", "test4321")
	})

	err := queue.Init()
	tcheck(t, err, "queue init")

	// "queue"
	testctl(func(ctl *ctl) {
		ctlcmdQueueList(ctl)
	})

	// "queuekick"
	testctl(func(ctl *ctl) {
		ctlcmdQueueKick(ctl, 0, "", "", "")
	})

	// "queuedrop"
	testctl(func(ctl *ctl) {
		ctlcmdQueueDrop(ctl, 0, "", "")
	})

	// no "queuedump", we don't have a message to dump, and the commands exits without a message.

	// "importmbox"
	testctl(func(ctl *ctl) {
		ctlcmdImport(ctl, true, "mjl", "inbox", "testdata/importtest.mbox")
	})

	// "importmaildir"
	testctl(func(ctl *ctl) {
		ctlcmdImport(ctl, false, "mjl", "inbox", "testdata/importtest.maildir")
	})

	// "domainadd"
	testctl(func(ctl *ctl) {
		ctlcmdConfigDomainAdd(ctl, dns.Domain{ASCII: "mox2.example"}, "mjl", "")
	})

	// "accountadd"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAccountAdd(ctl, "mjl2", "mjl2@mox2.example")
	})

	// "addressadd"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAddressAdd(ctl, "mjl3@mox2.example", "mjl2")
	})

	// Add a message.
	testctl(func(ctl *ctl) {
		ctlcmdDeliver(ctl, "mjl3@mox2.example")
	})
	// "retrain", retrain junk filter.
	testctl(func(ctl *ctl) {
		ctlcmdRetrain(ctl, "mjl2")
	})

	// "addressrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAddressRemove(ctl, "mjl3@mox2.example")
	})

	// "accountrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAccountRemove(ctl, "mjl2")
	})

	// "domainrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigDomainRemove(ctl, dns.Domain{ASCII: "mox2.example"})
	})

	// "loglevels"
	testctl(func(ctl *ctl) {
		ctlcmdLoglevels(ctl)
	})

	// "setloglevels"
	testctl(func(ctl *ctl) {
		ctlcmdSetLoglevels(ctl, "", "debug")
	})
	testctl(func(ctl *ctl) {
		ctlcmdSetLoglevels(ctl, "smtpserver", "debug")
	})

	// Export data, import it again
	xcmdExport(true, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/mbox/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, nil)
	xcmdExport(false, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/maildir/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, nil)
	testctl(func(ctl *ctl) {
		ctlcmdImport(ctl, true, "mjl", "inbox", filepath.FromSlash("testdata/ctl/data/tmp/export/mbox/Inbox.mbox"))
	})
	testctl(func(ctl *ctl) {
		ctlcmdImport(ctl, false, "mjl", "inbox", filepath.FromSlash("testdata/ctl/data/tmp/export/maildir/Inbox"))
	})

	// "recalculatemailboxcounts"
	testctl(func(ctl *ctl) {
		ctlcmdRecalculateMailboxCounts(ctl, "mjl")
	})

	// "fixmsgsize"
	testctl(func(ctl *ctl) {
		ctlcmdFixmsgsize(ctl, "mjl")
	})
	testctl(func(ctl *ctl) {
		acc, err := store.OpenAccount("mjl")
		tcheck(t, err, "open account")
		defer acc.Close()

		content := []byte("Subject: hi\r\n\r\nbody\r\n")

		deliver := func(m *store.Message) {
			t.Helper()
			m.Size = int64(len(content))
			msgf, err := store.CreateMessageTemp("ctltest")
			tcheck(t, err, "create temp file")
			defer os.Remove(msgf.Name())
			defer msgf.Close()
			_, err = msgf.Write(content)
			tcheck(t, err, "write message file")
			err = acc.DeliverMailbox(xlog, "Inbox", m, msgf)
			tcheck(t, err, "deliver message")
		}

		var msgBadSize store.Message
		deliver(&msgBadSize)

		msgBadSize.Size = 1
		err = acc.DB.Update(ctxbg, &msgBadSize)
		tcheck(t, err, "update message to bad size")
		mb := store.Mailbox{ID: msgBadSize.MailboxID}
		err = acc.DB.Get(ctxbg, &mb)
		tcheck(t, err, "get db")
		mb.Size -= int64(len(content))
		mb.Size += 1
		err = acc.DB.Update(ctxbg, &mb)
		tcheck(t, err, "update mailbox size")

		// Fix up the size.
		ctlcmdFixmsgsize(ctl, "")

		err = acc.DB.Get(ctxbg, &msgBadSize)
		tcheck(t, err, "get message")
		if msgBadSize.Size != int64(len(content)) {
			t.Fatalf("after fixing, message size is %d, should be %d", msgBadSize.Size, len(content))
		}
	})

	// "reparse"
	testctl(func(ctl *ctl) {
		ctlcmdReparse(ctl, "mjl")
	})
	testctl(func(ctl *ctl) {
		ctlcmdReparse(ctl, "")
	})

	// "reassignthreads"
	testctl(func(ctl *ctl) {
		ctlcmdReassignthreads(ctl, "mjl")
	})
	testctl(func(ctl *ctl) {
		ctlcmdReassignthreads(ctl, "")
	})

	// "backup", backup account.
	err = dmarcdb.Init()
	tcheck(t, err, "dmarcdb init")
	err = mtastsdb.Init(false)
	tcheck(t, err, "mtastsdb init")
	err = tlsrptdb.Init()
	tcheck(t, err, "tlsrptdb init")
	testctl(func(ctl *ctl) {
		os.RemoveAll("testdata/ctl/data/tmp/backup-data")
		err := os.WriteFile("testdata/ctl/data/receivedid.key", make([]byte, 16), 0600)
		tcheck(t, err, "writing receivedid.key")
		ctlcmdBackup(ctl, filepath.FromSlash("testdata/ctl/data/tmp/backup-data"), false)
	})

	// Verify the backup.
	xcmd := cmd{
		flag:     flag.NewFlagSet("", flag.ExitOnError),
		flagArgs: []string{filepath.FromSlash("testdata/ctl/data/tmp/backup-data")},
	}
	cmdVerifydata(&xcmd)
}
