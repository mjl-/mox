//go:build !integration

package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

var ctxbg = context.Background()
var pkglog = mlog.New("ctl", nil)

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
	mox.ConfigStaticPath = filepath.FromSlash("testdata/ctl/config/mox.conf")
	mox.ConfigDynamicPath = filepath.FromSlash("testdata/ctl/config/domains.conf")
	if errs := mox.LoadConfig(ctxbg, pkglog, true, false); len(errs) > 0 {
		t.Fatalf("loading mox config: %v", errs)
	}
	defer store.Switchboard()()

	err := queue.Init()
	tcheck(t, err, "queue init")
	defer queue.Shutdown()

	err = store.Init(ctxbg)
	tcheck(t, err, "store init")
	defer store.Close()

	testctl := func(fn func(clientctl *ctl)) {
		t.Helper()

		cconn, sconn := net.Pipe()
		clientctl := ctl{conn: cconn, log: pkglog}
		serverctl := ctl{conn: sconn, log: pkglog}
		done := make(chan struct{})
		go func() {
			servectlcmd(ctxbg, &serverctl, func() {})
			close(done)
		}()
		fn(&clientctl)
		cconn.Close()
		<-done
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

	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesList(ctl)
	})

	// All messages.
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "", "", "")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "mjl", "", "")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "", "☺.mox.example", "")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "mox", "☺.mox.example", "example.com")
	})

	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesRemove(ctl, 1)
	})

	// Queue a message to list/change/dump.
	msg := "Subject: subject\r\n\r\nbody\r\n"
	msgFile, err := store.CreateMessageTemp(pkglog, "queuedump-test")
	tcheck(t, err, "temp file")
	_, err = msgFile.Write([]byte(msg))
	tcheck(t, err, "write message")
	_, err = msgFile.Seek(0, 0)
	tcheck(t, err, "rewind message")
	defer os.Remove(msgFile.Name())
	defer msgFile.Close()
	addr, err := smtp.ParseAddress("mjl@mox.example")
	tcheck(t, err, "parse address")
	qml := []queue.Msg{queue.MakeMsg(addr.Path(), addr.Path(), false, false, int64(len(msg)), "<random@localhost>", nil, nil, time.Now(), "subject")}
	queue.Add(ctxbg, pkglog, "mjl", msgFile, qml...)
	qmid := qml[0].ID

	// Has entries now.
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesList(ctl)
	})

	// "queuelist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueList(ctl, queue.Filter{}, queue.Sort{})
	})

	// "queueholdset"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldSet(ctl, queue.Filter{}, true)
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldSet(ctl, queue.Filter{}, false)
	})

	// "queueschedule"
	testctl(func(ctl *ctl) {
		ctlcmdQueueSchedule(ctl, queue.Filter{}, true, time.Minute)
	})

	// "queuetransport"
	testctl(func(ctl *ctl) {
		ctlcmdQueueTransport(ctl, queue.Filter{}, "socks")
	})

	// "queuerequiretls"
	testctl(func(ctl *ctl) {
		ctlcmdQueueRequireTLS(ctl, queue.Filter{}, nil)
	})

	// "queuedump"
	testctl(func(ctl *ctl) {
		ctlcmdQueueDump(ctl, fmt.Sprintf("%d", qmid))
	})

	// "queuefail"
	testctl(func(ctl *ctl) {
		ctlcmdQueueFail(ctl, queue.Filter{})
	})

	// "queuedrop"
	testctl(func(ctl *ctl) {
		ctlcmdQueueDrop(ctl, queue.Filter{})
	})

	// "queueholdruleslist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesList(ctl)
	})

	// "queueholdrulesadd"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "mjl", "", "")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesAdd(ctl, "mjl", "localhost", "")
	})

	// "queueholdrulesremove"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesRemove(ctl, 2)
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueHoldrulesList(ctl)
	})

	// "queuesuppresslist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressList(ctl, "mjl")
	})

	// "queuesuppressadd"
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressAdd(ctl, "mjl", "base@localhost")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressAdd(ctl, "mjl", "other@localhost")
	})

	// "queuesuppresslookup"
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressLookup(ctl, "mjl", "base@localhost")
	})

	// "queuesuppressremove"
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressRemove(ctl, "mjl", "base@localhost")
	})
	testctl(func(ctl *ctl) {
		ctlcmdQueueSuppressList(ctl, "mjl")
	})

	// "queueretiredlist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueRetiredList(ctl, queue.RetiredFilter{}, queue.RetiredSort{})
	})

	// "queueretiredprint"
	testctl(func(ctl *ctl) {
		ctlcmdQueueRetiredPrint(ctl, "1")
	})

	// "queuehooklist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookList(ctl, queue.HookFilter{}, queue.HookSort{})
	})

	// "queuehookschedule"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookSchedule(ctl, queue.HookFilter{}, true, time.Minute)
	})

	// "queuehookprint"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookPrint(ctl, "1")
	})

	// "queuehookcancel"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookCancel(ctl, queue.HookFilter{})
	})

	// "queuehookretiredlist"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookRetiredList(ctl, queue.HookRetiredFilter{}, queue.HookRetiredSort{})
	})

	// "queuehookretiredprint"
	testctl(func(ctl *ctl) {
		ctlcmdQueueHookRetiredPrint(ctl, "1")
	})

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
		ctlcmdConfigDomainAdd(ctl, false, dns.Domain{ASCII: "mox2.example"}, "mjl", "")
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

	// "accountdisabled"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAccountDisabled(ctl, "mjl2", "testing")
	})
	testctl(func(ctl *ctl) {
		ctlcmdConfigAccountDisabled(ctl, "mjl2", "")
	})

	// "accountrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAccountRemove(ctl, "mjl2")
	})

	// "domaindisabled"
	testctl(func(ctl *ctl) {
		ctlcmdConfigDomainDisabled(ctl, dns.Domain{ASCII: "mox2.example"}, true)
	})
	testctl(func(ctl *ctl) {
		ctlcmdConfigDomainDisabled(ctl, dns.Domain{ASCII: "mox2.example"}, false)
	})

	// "domainrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigDomainRemove(ctl, dns.Domain{ASCII: "mox2.example"})
	})

	// "aliasadd"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasAdd(ctl, "support@mox.example", config.Alias{Addresses: []string{"mjl@mox.example"}})
	})

	// "aliaslist"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasList(ctl, "mox.example")
	})

	// "aliasprint"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasPrint(ctl, "support@mox.example")
	})

	// "aliasupdate"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasUpdate(ctl, "support@mox.example", "true", "true", "true")
	})

	// "aliasaddaddr"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasAddaddr(ctl, "support@mox.example", []string{"mjl2@mox.example"})
	})

	// "aliasrmaddr"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasRmaddr(ctl, "support@mox.example", []string{"mjl2@mox.example"})
	})

	// "aliasrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigAliasRemove(ctl, "support@mox.example")
	})

	// accounttlspubkeyadd
	certDER := fakeCert(t)
	testctl(func(ctl *ctl) {
		ctlcmdConfigTlspubkeyAdd(ctl, "mjl@mox.example", "testkey", false, certDER)
	})

	// "accounttlspubkeylist"
	testctl(func(ctl *ctl) {
		ctlcmdConfigTlspubkeyList(ctl, "")
	})
	testctl(func(ctl *ctl) {
		ctlcmdConfigTlspubkeyList(ctl, "mjl")
	})

	tpkl, err := store.TLSPublicKeyList(ctxbg, "")
	tcheck(t, err, "list tls public keys")
	if len(tpkl) != 1 {
		t.Fatalf("got %d tls public keys, expected 1", len(tpkl))
	}
	fingerprint := tpkl[0].Fingerprint

	// "accounttlspubkeyget"
	testctl(func(ctl *ctl) {
		ctlcmdConfigTlspubkeyGet(ctl, fingerprint)
	})

	// "accounttlspubkeyrm"
	testctl(func(ctl *ctl) {
		ctlcmdConfigTlspubkeyRemove(ctl, fingerprint)
	})

	tpkl, err = store.TLSPublicKeyList(ctxbg, "")
	tcheck(t, err, "list tls public keys")
	if len(tpkl) != 0 {
		t.Fatalf("got %d tls public keys, expected 0", len(tpkl))
	}

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
	xcmdExport(true, false, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/mbox/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, &cmd{log: pkglog})
	xcmdExport(false, false, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/maildir/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, &cmd{log: pkglog})
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
		acc, err := store.OpenAccount(ctl.log, "mjl", false)
		tcheck(t, err, "open account")
		defer func() {
			acc.Close()
			acc.CheckClosed()
		}()

		content := []byte("Subject: hi\r\n\r\nbody\r\n")

		deliver := func(m *store.Message) {
			t.Helper()
			m.Size = int64(len(content))
			msgf, err := store.CreateMessageTemp(ctl.log, "ctltest")
			tcheck(t, err, "create temp file")
			defer os.Remove(msgf.Name())
			defer msgf.Close()
			_, err = msgf.Write(content)
			tcheck(t, err, "write message file")
			err = acc.DeliverMailbox(ctl.log, "Inbox", m, msgf)
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
	defer dmarcdb.Close()
	err = mtastsdb.Init(false)
	tcheck(t, err, "mtastsdb init")
	defer mtastsdb.Close()
	err = tlsrptdb.Init()
	tcheck(t, err, "tlsrptdb init")
	defer tlsrptdb.Close()
	testctl(func(ctl *ctl) {
		os.RemoveAll("testdata/ctl/data/tmp/backup")
		err := os.WriteFile("testdata/ctl/data/receivedid.key", make([]byte, 16), 0600)
		tcheck(t, err, "writing receivedid.key")
		ctlcmdBackup(ctl, filepath.FromSlash("testdata/ctl/data/tmp/backup"), false)
	})

	// Verify the backup.
	xcmd := cmd{
		flag:     flag.NewFlagSet("", flag.ExitOnError),
		flagArgs: []string{filepath.FromSlash("testdata/ctl/data/tmp/backup/data")},
	}
	cmdVerifydata(&xcmd)
}

func fakeCert(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	privKey := ed25519.NewKeyFromSeed(seed) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	tcheck(t, err, "making certificate")
	return localCertBuf
}
