//go:build !integration

package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapclient"
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
	err := store.Init(ctxbg)
	tcheck(t, err, "store init")
	defer store.Close()
	defer store.Switchboard()()

	err = queue.Init()
	tcheck(t, err, "queue init")
	defer queue.Shutdown()

	var cid int64

	testctl := func(fn func(clientxctl *ctl)) {
		t.Helper()

		cconn, sconn := net.Pipe()
		clientxctl := ctl{conn: cconn, log: pkglog}
		serverxctl := ctl{conn: sconn, log: pkglog}
		done := make(chan struct{})
		go func() {
			cid++
			servectlcmd(ctxbg, &serverxctl, cid, func() {})
			close(done)
		}()
		fn(&clientxctl)
		cconn.Close()
		<-done
		sconn.Close()
	}

	// "deliver"
	testctl(func(xctl *ctl) {
		ctlcmdDeliver(xctl, "mjl@mox.example")
	})

	// "setaccountpassword"
	testctl(func(xctl *ctl) {
		ctlcmdSetaccountpassword(xctl, "mjl", "test4321")
	})

	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesList(xctl)
	})

	// All messages.
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "", "", "")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "mjl", "", "")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "", "☺.mox.example", "")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "mox", "☺.mox.example", "example.com")
	})

	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesRemove(xctl, 1)
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
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesList(xctl)
	})

	// "queuelist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueList(xctl, queue.Filter{}, queue.Sort{})
	})

	// "queueholdset"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldSet(xctl, queue.Filter{}, true)
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldSet(xctl, queue.Filter{}, false)
	})

	// "queueschedule"
	testctl(func(xctl *ctl) {
		ctlcmdQueueSchedule(xctl, queue.Filter{}, true, time.Minute)
	})

	// "queuetransport"
	testctl(func(xctl *ctl) {
		ctlcmdQueueTransport(xctl, queue.Filter{}, "socks")
	})

	// "queuerequiretls"
	testctl(func(xctl *ctl) {
		ctlcmdQueueRequireTLS(xctl, queue.Filter{}, nil)
	})

	// "queuedump"
	testctl(func(xctl *ctl) {
		ctlcmdQueueDump(xctl, fmt.Sprintf("%d", qmid))
	})

	// "queuefail"
	testctl(func(xctl *ctl) {
		ctlcmdQueueFail(xctl, queue.Filter{})
	})

	// "queuedrop"
	testctl(func(xctl *ctl) {
		ctlcmdQueueDrop(xctl, queue.Filter{})
	})

	// "queueholdruleslist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesList(xctl)
	})

	// "queueholdrulesadd"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "mjl", "", "")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesAdd(xctl, "mjl", "localhost", "")
	})

	// "queueholdrulesremove"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesRemove(xctl, 2)
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueHoldrulesList(xctl)
	})

	// "queuesuppresslist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressList(xctl, "mjl")
	})

	// "queuesuppressadd"
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressAdd(xctl, "mjl", "base@localhost")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressAdd(xctl, "mjl", "other@localhost")
	})

	// "queuesuppresslookup"
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressLookup(xctl, "mjl", "base@localhost")
	})

	// "queuesuppressremove"
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressRemove(xctl, "mjl", "base@localhost")
	})
	testctl(func(xctl *ctl) {
		ctlcmdQueueSuppressList(xctl, "mjl")
	})

	// "queueretiredlist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueRetiredList(xctl, queue.RetiredFilter{}, queue.RetiredSort{})
	})

	// "queueretiredprint"
	testctl(func(xctl *ctl) {
		ctlcmdQueueRetiredPrint(xctl, "1")
	})

	// "queuehooklist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookList(xctl, queue.HookFilter{}, queue.HookSort{})
	})

	// "queuehookschedule"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookSchedule(xctl, queue.HookFilter{}, true, time.Minute)
	})

	// "queuehookprint"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookPrint(xctl, "1")
	})

	// "queuehookcancel"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookCancel(xctl, queue.HookFilter{})
	})

	// "queuehookretiredlist"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookRetiredList(xctl, queue.HookRetiredFilter{}, queue.HookRetiredSort{})
	})

	// "queuehookretiredprint"
	testctl(func(xctl *ctl) {
		ctlcmdQueueHookRetiredPrint(xctl, "1")
	})

	// "importmbox"
	testctl(func(xctl *ctl) {
		ctlcmdImport(xctl, true, "mjl", "inbox", "testdata/importtest.mbox")
	})

	// "importmaildir"
	testctl(func(xctl *ctl) {
		ctlcmdImport(xctl, false, "mjl", "inbox", "testdata/importtest.maildir")
	})

	// "domainadd"
	testctl(func(xctl *ctl) {
		ctlcmdConfigDomainAdd(xctl, false, dns.Domain{ASCII: "mox2.example"}, "mjl", "")
	})

	// "accountadd"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAccountAdd(xctl, "mjl2", "mjl2@mox2.example")
	})

	// "addressadd"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAddressAdd(xctl, "mjl3@mox2.example", "mjl2")
	})

	// Add a message.
	testctl(func(xctl *ctl) {
		ctlcmdDeliver(xctl, "mjl3@mox2.example")
	})
	// "retrain", retrain junk filter.
	testctl(func(xctl *ctl) {
		ctlcmdRetrain(xctl, "mjl2")
	})

	// "addressrm"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAddressRemove(xctl, "mjl3@mox2.example")
	})

	// "accountdisabled"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAccountDisabled(xctl, "mjl2", "testing")
	})

	// "accountlist"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAccountList(xctl)
	})

	testctl(func(xctl *ctl) {
		ctlcmdConfigAccountDisabled(xctl, "mjl2", "")
	})

	// "accountrm"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAccountRemove(xctl, "mjl2")
	})

	// "domaindisabled"
	testctl(func(xctl *ctl) {
		ctlcmdConfigDomainDisabled(xctl, dns.Domain{ASCII: "mox2.example"}, true)
	})
	testctl(func(xctl *ctl) {
		ctlcmdConfigDomainDisabled(xctl, dns.Domain{ASCII: "mox2.example"}, false)
	})

	// "domainrm"
	testctl(func(xctl *ctl) {
		ctlcmdConfigDomainRemove(xctl, dns.Domain{ASCII: "mox2.example"})
	})

	// "aliasadd"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasAdd(xctl, "support@mox.example", config.Alias{Addresses: []string{"mjl@mox.example"}})
	})

	// "aliaslist"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasList(xctl, "mox.example")
	})

	// "aliasprint"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasPrint(xctl, "support@mox.example")
	})

	// "aliasupdate"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasUpdate(xctl, "support@mox.example", "true", "true", "true")
	})

	// "aliasaddaddr"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasAddaddr(xctl, "support@mox.example", []string{"mjl2@mox.example"})
	})

	// "aliasrmaddr"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasRmaddr(xctl, "support@mox.example", []string{"mjl2@mox.example"})
	})

	// "aliasrm"
	testctl(func(xctl *ctl) {
		ctlcmdConfigAliasRemove(xctl, "support@mox.example")
	})

	// accounttlspubkeyadd
	certDER := fakeCert(t)
	testctl(func(xctl *ctl) {
		ctlcmdConfigTlspubkeyAdd(xctl, "mjl@mox.example", "testkey", false, certDER)
	})

	// "accounttlspubkeylist"
	testctl(func(xctl *ctl) {
		ctlcmdConfigTlspubkeyList(xctl, "")
	})
	testctl(func(xctl *ctl) {
		ctlcmdConfigTlspubkeyList(xctl, "mjl")
	})

	tpkl, err := store.TLSPublicKeyList(ctxbg, "")
	tcheck(t, err, "list tls public keys")
	if len(tpkl) != 1 {
		t.Fatalf("got %d tls public keys, expected 1", len(tpkl))
	}
	fingerprint := tpkl[0].Fingerprint

	// "accounttlspubkeyget"
	testctl(func(xctl *ctl) {
		ctlcmdConfigTlspubkeyGet(xctl, fingerprint)
	})

	// "accounttlspubkeyrm"
	testctl(func(xctl *ctl) {
		ctlcmdConfigTlspubkeyRemove(xctl, fingerprint)
	})

	tpkl, err = store.TLSPublicKeyList(ctxbg, "")
	tcheck(t, err, "list tls public keys")
	if len(tpkl) != 0 {
		t.Fatalf("got %d tls public keys, expected 0", len(tpkl))
	}

	// "loglevels"
	testctl(func(xctl *ctl) {
		ctlcmdLoglevels(xctl)
	})

	// "setloglevels"
	testctl(func(xctl *ctl) {
		ctlcmdSetLoglevels(xctl, "", "debug")
	})
	testctl(func(xctl *ctl) {
		ctlcmdSetLoglevels(xctl, "smtpserver", "debug")
	})

	// Export data, import it again
	xcmdExport(true, false, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/mbox/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, &cmd{log: pkglog})
	xcmdExport(false, false, []string{filepath.FromSlash("testdata/ctl/data/tmp/export/maildir/"), filepath.FromSlash("testdata/ctl/data/accounts/mjl")}, &cmd{log: pkglog})
	testctl(func(xctl *ctl) {
		ctlcmdImport(xctl, true, "mjl", "inbox", filepath.FromSlash("testdata/ctl/data/tmp/export/mbox/Inbox.mbox"))
	})
	testctl(func(xctl *ctl) {
		ctlcmdImport(xctl, false, "mjl", "inbox", filepath.FromSlash("testdata/ctl/data/tmp/export/maildir/Inbox"))
	})

	// "recalculatemailboxcounts"
	testctl(func(xctl *ctl) {
		ctlcmdRecalculateMailboxCounts(xctl, "mjl")
	})

	// "fixmsgsize"
	testctl(func(xctl *ctl) {
		ctlcmdFixmsgsize(xctl, "mjl")
	})
	testctl(func(xctl *ctl) {
		acc, err := store.OpenAccount(xctl.log, "mjl", false)
		tcheck(t, err, "open account")
		defer func() {
			acc.Close()
			acc.WaitClosed()
		}()

		content := []byte("Subject: hi\r\n\r\nbody\r\n")

		deliver := func(m *store.Message) {
			t.Helper()
			m.Size = int64(len(content))
			msgf, err := store.CreateMessageTemp(xctl.log, "ctltest")
			tcheck(t, err, "create temp file")
			defer os.Remove(msgf.Name())
			defer msgf.Close()
			_, err = msgf.Write(content)
			tcheck(t, err, "write message file")

			acc.WithWLock(func() {
				err = acc.DeliverMailbox(xctl.log, "Inbox", m, msgf)
				tcheck(t, err, "deliver message")
			})
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
		ctlcmdFixmsgsize(xctl, "")

		err = acc.DB.Get(ctxbg, &msgBadSize)
		tcheck(t, err, "get message")
		if msgBadSize.Size != int64(len(content)) {
			t.Fatalf("after fixing, message size is %d, should be %d", msgBadSize.Size, len(content))
		}
	})

	// "reparse"
	testctl(func(xctl *ctl) {
		ctlcmdReparse(xctl, "mjl")
	})
	testctl(func(xctl *ctl) {
		ctlcmdReparse(xctl, "")
	})

	// "reassignthreads"
	testctl(func(xctl *ctl) {
		ctlcmdReassignthreads(xctl, "mjl")
	})
	testctl(func(xctl *ctl) {
		ctlcmdReassignthreads(xctl, "")
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
	testctl(func(xctl *ctl) {
		os.RemoveAll("testdata/ctl/data/tmp/backup")
		err := os.WriteFile("testdata/ctl/data/receivedid.key", make([]byte, 16), 0600)
		tcheck(t, err, "writing receivedid.key")
		ctlcmdBackup(xctl, filepath.FromSlash("testdata/ctl/data/tmp/backup"), false)
	})

	// Verify the backup.
	xcmd := cmd{
		flag:     flag.NewFlagSet("", flag.ExitOnError),
		flagArgs: []string{filepath.FromSlash("testdata/ctl/data/tmp/backup/data")},
	}
	cmdVerifydata(&xcmd)

	// IMAP connection.
	testctl(func(xctl *ctl) {
		a, b := net.Pipe()
		go func() {
			opts := imapclient.Opts{
				Logger: slog.Default().With("cid", mox.Cid()),
				Error:  func(err error) { panic(err) },
			}
			client, err := imapclient.New(a, &opts)
			tcheck(t, err, "new imapclient")
			client.Select("inbox")
			client.Logout()
			defer a.Close()
		}()
		ctlcmdIMAPServe(xctl, "mjl@mox.example", b, b)
	})
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
