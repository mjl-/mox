package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// todo: add option to trust imported messages, causing us to look at Authentication-Results and Received-SPF headers and add eg verified spf/dkim/dmarc domains to our store, to jumpstart reputation.

const importCommonHelp = `The mbox/maildir archive is accessed and imported by the running mox process, so
it must have access to the archive files. The default suggested systemd service
file isolates mox from most of the file system, with only the "data/" directory
accessible, so you may want to put the mbox/maildir archive files in a
directory like "data/import/" to make it available to mox.

By default, messages will train the junk filter based on their flags and, if
"automatic junk flags" configuration is set, based on mailbox naming.

If the destination mailbox is the Sent mailbox, the recipients of the messages
are added to the message metadata, causing later incoming messages from these
recipients to be accepted, unless other reputation signals prevent that.

Users can also import mailboxes/messages through the account web page by
uploading a zip or tgz file with mbox and/or maildirs.
`

func cmdImportMaildir(c *cmd) {
	c.params = "accountname mailboxname maildir"
	c.help = `Import a maildir into an account.

` + importCommonHelp + `
Mailbox flags, like "seen", "answered", will be imported. An optional
dovecot-keywords file can specify additional flags, like Forwarded/Junk/NotJunk.
`
	args := c.Parse()
	if len(args) != 3 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdImport(xctl(), false, args[0], args[1], args[2])
}

func cmdImportMbox(c *cmd) {
	c.params = "accountname mailboxname mbox"
	c.help = `Import an mbox into an account.

Using mbox is not recommended, maildir is a better defined format.

` + importCommonHelp
	args := c.Parse()
	if len(args) != 3 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdImport(xctl(), true, args[0], args[1], args[2])
}

func cmdXImportMaildir(c *cmd) {
	c.unlisted = true
	c.params = "accountdir mailboxname maildir"
	c.help = `Import a maildir into an account by directly accessing the data directory.


See "mox help import maildir" for details.
`
	xcmdXImport(false, c)
}

func cmdXImportMbox(c *cmd) {
	c.unlisted = true
	c.params = "accountdir mailboxname mbox"
	c.help = `Import an mbox into an account by directly accessing the data directory.

See "mox help import mbox" for details.
`
	xcmdXImport(true, c)
}

func xcmdXImport(mbox bool, c *cmd) {
	args := c.Parse()
	if len(args) != 3 {
		c.Usage()
	}

	accountdir := args[0]
	account := filepath.Base(accountdir)

	// Set up the mox config so the account can be opened.
	if filepath.Base(filepath.Dir(accountdir)) != "accounts" {
		log.Fatalf("accountdir must be of the form .../accounts/<name>")
	}
	var err error
	mox.Conf.Static.DataDir, err = filepath.Abs(filepath.Dir(filepath.Dir(accountdir)))
	xcheckf(err, "making absolute datadir")
	mox.ConfigStaticPath = "fake.conf"
	mox.Conf.DynamicLastCheck = time.Now().Add(time.Hour) // Silence errors about config file.
	mox.Conf.Dynamic.Accounts = map[string]config.Account{
		account: {},
	}
	defer store.Switchboard()()

	cconn, sconn := net.Pipe()
	clientctl := ctl{conn: cconn, r: bufio.NewReader(cconn), log: c.log}
	serverctl := ctl{conn: sconn, r: bufio.NewReader(sconn), log: c.log}
	go servectlcmd(context.Background(), &serverctl, func() {})

	ctlcmdImport(&clientctl, mbox, account, args[1], args[2])
}

func ctlcmdImport(ctl *ctl, mbox bool, account, mailbox, src string) {
	if mbox {
		ctl.xwrite("importmbox")
	} else {
		ctl.xwrite("importmaildir")
	}
	ctl.xwrite(account)
	if strings.EqualFold(mailbox, "Inbox") {
		mailbox = "Inbox"
	}
	ctl.xwrite(mailbox)
	ctl.xwrite(src)
	ctl.xreadok()
	fmt.Fprintln(os.Stderr, "importing...")
	for {
		line := ctl.xread()
		if strings.HasPrefix(line, "progress ") {
			n := line[len("progress "):]
			fmt.Fprintf(os.Stderr, "%s...\n", n)
			continue
		}
		if line != "ok" {
			log.Fatalf("import, expected ok, got %q", line)
		}
		break
	}
	count := ctl.xread()
	fmt.Fprintf(os.Stderr, "%s imported\n", count)
}

func importctl(ctx context.Context, ctl *ctl, mbox bool) {
	/* protocol:
	> "importmaildir" or "importmbox"
	> account
	> mailbox
	> src (mbox file or maildir directory)
	< "ok" or error
	< "progress" count (zero or more times, once for every 1000 messages)
	< "ok" when done, or error
	< count (of total imported messages, only if not error)
	*/
	account := ctl.xread()
	mailbox := ctl.xread()
	src := ctl.xread()

	kind := "maildir"
	if mbox {
		kind = "mbox"
	}
	ctl.log.Info("importing messages",
		slog.String("kind", kind),
		slog.String("account", account),
		slog.String("mailbox", mailbox),
		slog.String("source", src))

	var err error
	var mboxf *os.File
	var mdnewf, mdcurf *os.File
	var msgreader store.MsgSource

	// Open account, creating a database file if it doesn't exist yet. It must be known
	// in the configuration file.
	a, err := store.OpenAccount(ctl.log, account)
	ctl.xcheck(err, "opening account")
	defer func() {
		if a != nil {
			err := a.Close()
			ctl.log.Check(err, "closing account after import")
		}
	}()

	err = a.ThreadingWait(ctl.log)
	ctl.xcheck(err, "waiting for account thread upgrade")

	defer func() {
		if mboxf != nil {
			err := mboxf.Close()
			ctl.log.Check(err, "closing mbox file after import")
		}
		if mdnewf != nil {
			err := mdnewf.Close()
			ctl.log.Check(err, "closing maildir new after import")
		}
		if mdcurf != nil {
			err := mdcurf.Close()
			ctl.log.Check(err, "closing maildir cur after import")
		}
	}()

	// Messages don't always have a junk flag set. We'll assume anything in a mailbox
	// starting with junk or spam is junk mail.

	// First check if we can access the mbox/maildir.
	// Mox needs to be able to access those files, the user running the import command
	// may be a different user who can access the files.
	if mbox {
		mboxf, err = os.Open(src)
		ctl.xcheck(err, "open mbox file")
		msgreader = store.NewMboxReader(ctl.log, store.CreateMessageTemp, src, mboxf)
	} else {
		mdnewf, err = os.Open(filepath.Join(src, "new"))
		ctl.xcheck(err, "open subdir new of maildir")
		mdcurf, err = os.Open(filepath.Join(src, "cur"))
		ctl.xcheck(err, "open subdir cur of maildir")
		msgreader = store.NewMaildirReader(ctl.log, store.CreateMessageTemp, mdnewf, mdcurf)
	}

	tx, err := a.DB.Begin(ctx, true)
	ctl.xcheck(err, "begin transaction")
	defer func() {
		if tx != nil {
			err := tx.Rollback()
			ctl.log.Check(err, "rolling back transaction")
		}
	}()

	// All preparations done. Good to go.
	ctl.xwriteok()

	// We will be delivering messages. If we fail halfway, we need to remove the created msg files.
	var deliveredIDs []int64

	defer func() {
		x := recover()
		if x == nil {
			return
		}

		if x != ctl.x {
			ctl.log.Error("import error", slog.String("panic", fmt.Sprintf("%v", x)))
			debug.PrintStack()
			metrics.PanicInc(metrics.Import)
		} else {
			ctl.log.Error("import error")
		}

		for _, id := range deliveredIDs {
			p := a.MessagePath(id)
			err := os.Remove(p)
			ctl.log.Check(err, "closing message file after import error", slog.String("path", p))
		}

		ctl.xerror(fmt.Sprintf("import error: %v", x))
	}()

	var changes []store.Change

	var modseq store.ModSeq // Assigned on first delivered messages, used for all messages.

	xdeliver := func(m *store.Message, mf *os.File) {
		// todo: possibly set dmarcdomain to the domain of the from address? at least for non-spams that have been seen. otherwise user would start without any reputations. the assumption would be that the user has accepted email and deemed it legit, coming from the indicated sender.

		const sync = false
		const notrain = true
		const nothreads = true
		const updateDiskUsage = false
		err := a.DeliverMessage(ctl.log, tx, m, mf, sync, notrain, nothreads, updateDiskUsage)
		ctl.xcheck(err, "delivering message")
		deliveredIDs = append(deliveredIDs, m.ID)
		ctl.log.Debug("delivered message", slog.Int64("id", m.ID))
		changes = append(changes, m.ChangeAddUID())
	}

	// todo: one goroutine for reading messages, one for parsing the message, one adding to database, one for junk filter training.
	n := 0
	a.WithWLock(func() {
		// Ensure mailbox exists.
		var mb store.Mailbox
		mb, changes, err = a.MailboxEnsure(tx, mailbox, true)
		ctl.xcheck(err, "ensuring mailbox exists")

		// We ensure keywords in messages make it to the mailbox as well.
		mailboxKeywords := map[string]bool{}

		jf, _, err := a.OpenJunkFilter(ctx, ctl.log)
		if err != nil && !errors.Is(err, store.ErrNoJunkFilter) {
			ctl.xcheck(err, "open junk filter")
		}
		defer func() {
			if jf != nil {
				err = jf.Close()
				ctl.xcheck(err, "close junk filter")
			}
		}()

		conf, _ := a.Conf()

		maxSize := a.QuotaMessageSize()
		var addSize int64
		du := store.DiskUsage{ID: 1}
		err = tx.Get(&du)
		ctl.xcheck(err, "get disk usage")

		process := func(m *store.Message, msgf *os.File, origPath string) {
			defer store.CloseRemoveTempFile(ctl.log, msgf, "message to import")

			addSize += m.Size
			if maxSize > 0 && du.MessageSize+addSize > maxSize {
				ctl.xcheck(fmt.Errorf("account over maximum total message size %d", maxSize), "checking quota")
			}

			for _, kw := range m.Keywords {
				mailboxKeywords[kw] = true
			}
			mb.Add(m.MailboxCounts())

			// Parse message and store parsed information for later fast retrieval.
			p, err := message.EnsurePart(ctl.log.Logger, false, msgf, m.Size)
			if err != nil {
				ctl.log.Infox("parsing message, continuing", err, slog.String("path", origPath))
			}
			m.ParsedBuf, err = json.Marshal(p)
			ctl.xcheck(err, "marshal parsed message structure")

			// Set fields needed for future threading. By doing it now, DeliverMessage won't
			// have to parse the Part again.
			p.SetReaderAt(store.FileMsgReader(m.MsgPrefix, msgf))
			m.PrepareThreading(ctl.log, &p)

			if m.Received.IsZero() {
				if p.Envelope != nil && !p.Envelope.Date.IsZero() {
					m.Received = p.Envelope.Date
				} else {
					m.Received = time.Now()
				}
			}

			// We set the flags that Deliver would set now and train ourselves. This prevents
			// Deliver from training, which would open the junk filter, change it, and write it
			// back to disk, for each message (slow).
			m.JunkFlagsForMailbox(mb, conf)
			if jf != nil && m.NeedsTraining() {
				if words, err := jf.ParseMessage(p); err != nil {
					ctl.log.Infox("parsing message for updating junk filter", err, slog.String("parse", ""), slog.String("path", origPath))
				} else {
					err = jf.Train(ctx, !m.Junk, words)
					ctl.xcheck(err, "training junk filter")
					m.TrainedJunk = &m.Junk
				}
			}

			if modseq == 0 {
				var err error
				modseq, err = a.NextModSeq(tx)
				ctl.xcheck(err, "assigning next modseq")
			}

			m.MailboxID = mb.ID
			m.MailboxOrigID = mb.ID
			m.CreateSeq = modseq
			m.ModSeq = modseq
			xdeliver(m, msgf)

			n++
			if n%1000 == 0 {
				ctl.xwrite(fmt.Sprintf("progress %d", n))
			}
		}

		for {
			m, msgf, origPath, err := msgreader.Next()
			if err == io.EOF {
				break
			}
			ctl.xcheck(err, "reading next message")

			process(m, msgf, origPath)
		}

		// Match threads.
		if len(deliveredIDs) > 0 {
			err = a.AssignThreads(ctx, ctl.log, tx, deliveredIDs[0], 0, io.Discard)
			ctl.xcheck(err, "assigning messages to threads")
		}

		// Get mailbox again, uidnext is likely updated.
		mc := mb.MailboxCounts
		err = tx.Get(&mb)
		ctl.xcheck(err, "get mailbox")
		mb.MailboxCounts = mc

		// If there are any new keywords, update the mailbox.
		var mbKwChanged bool
		mb.Keywords, mbKwChanged = store.MergeKeywords(mb.Keywords, maps.Keys(mailboxKeywords))
		if mbKwChanged {
			changes = append(changes, mb.ChangeKeywords())
		}

		err = tx.Update(&mb)
		ctl.xcheck(err, "updating message counts and keywords in mailbox")
		changes = append(changes, mb.ChangeCounts())

		err = a.AddMessageSize(ctl.log, tx, addSize)
		xcheckf(err, "updating total message size")

		err = tx.Commit()
		ctl.xcheck(err, "commit")
		tx = nil
		ctl.log.Info("delivered messages through import", slog.Int("count", len(deliveredIDs)))
		deliveredIDs = nil

		store.BroadcastChanges(a, changes)
	})

	err = a.Close()
	ctl.xcheck(err, "closing account")
	a = nil

	ctl.xwriteok()
	ctl.xwrite(fmt.Sprintf("%d", n))
}
