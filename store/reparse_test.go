package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

func TestReparse(t *testing.T) {
	log := mlog.New("store", nil)
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()

	orig := reparseMessageBatchSize
	reparseMessageBatchSize = 2
	defer func() {
		reparseMessageBatchSize = orig
	}()

	acc, err := OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")

	// Prepare message to add later.
	msgFile, err := CreateMessageTemp(log, "account-test")
	tcheck(t, err, "create temp message file")
	defer CloseRemoveTempFile(log, msgFile, "temp message file")
	msgWriter := message.NewWriter(msgFile)
	_, err = msgWriter.Write([]byte(" message"))
	tcheck(t, err, "write message")

	msgPrefix := []byte("From: <mjl@mox.example\r\nTo: <mjl@mox.example>\r\nCc: <mjl@mox.example>Subject: test\r\nMessage-Id: <m01@mox.example>\r\n\r\n")
	m := Message{
		Received:  time.Now(),
		Size:      int64(len(msgPrefix)) + msgWriter.Size,
		MsgPrefix: msgPrefix,
	}

	// Add messages.
	acc.WithRLock(func() {
		conf, _ := acc.Conf()
		for range 10 {
			nm := m
			err := acc.DeliverDestination(log, conf.Destinations["mjl"], &nm, msgFile)
			tcheck(t, err, "deliver")
		}
	})

	// Reparse explicitly.
	total, err := acc.ReparseMessages(ctxbg, log)
	tcheck(t, err, "reparsing messages")
	tcompare(t, total, 10)

	// Ensure a next reopen will reparse messages in the background.
	_, err = bstore.QueryDB[Upgrade](ctxbg, acc.DB).UpdateNonzero(Upgrade{MessageParseVersion: MessageParseVersionLatest + 1})
	tcheck(t, err, "change")

	// Close account, and wait until really closed.
	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()

	// Reopen account, should trigger reparse. We immediately Close again, account DB
	// should be kept open.
	acc, err = OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()

	// Check that the reparse is finished.
	acc, err = OpenAccount(log, "mjl", false)
	tcheck(t, err, "open account")
	for range 10 {
		up, err := bstore.QueryDB[Upgrade](ctxbg, acc.DB).Get()
		tcheck(t, err, "change")
		if up.MessageParseVersion == MessageParseVersionLatest {
			break
		}
		time.Sleep(time.Second / 10)
	}
	err = acc.Close()
	tcheck(t, err, "closing account")
	acc.WaitClosed()
}
