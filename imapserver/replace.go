package imapserver

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/store"
)

// Replace relaces a message for another, atomically, possibly in another mailbox,
// without needing a sequence of: append message, store \deleted flag, expunge.
//
// State: Selected
func (c *conn) cmdxReplace(isUID bool, tag, cmd string, p *parser) {
	// Command: ../rfc/8508:158 ../rfc/8508:198

	// Request syntax: ../rfc/8508:471
	p.xspace()
	star := p.take("*")
	var num uint32
	if !star {
		num = p.xnznumber()
	}
	p.xspace()
	name := p.xmailbox()

	// ../rfc/4466:473
	p.xspace()
	var storeFlags store.Flags
	var keywords []string
	if p.hasPrefix("(") {
		// Error must be a syntax error, to properly abort the connection due to literal.
		var err error
		storeFlags, keywords, err = store.ParseFlagsKeywords(p.xflagList())
		if err != nil {
			xsyntaxErrorf("parsing flags: %v", err)
		}
		p.xspace()
	}

	var tm time.Time
	if p.hasPrefix(`"`) {
		tm = p.xdateTime()
		p.xspace()
	} else {
		tm = time.Now()
	}

	// todo: only with utf8 should we we accept message headers with utf-8. we currently always accept them.
	// todo: this is only relevant if we also support the CATENATE extension?
	// ../rfc/6855:204
	utf8 := p.take("UTF8 (")
	if utf8 {
		p.xtake("~")
	}
	// Always allow literal8, for binary extension. ../rfc/4466:486
	// For utf8, we already consumed the required ~ above.
	size, synclit := p.xliteralSize(!utf8, false)

	// Check the request, including old message in database, whether the message fits
	// in quota. If a non-nil func is returned, an error was found. Calling the
	// function aborts handling this command.
	var uidOld store.UID
	checkMessage := func(tx *bstore.Tx) func() {
		if c.readonly {
			return func() { xuserErrorf("mailbox open in read-only mode") }
		}

		mb, err := c.account.MailboxFind(tx, name)
		if err != nil {
			return func() { xserverErrorf("finding mailbox: %v", err) }
		}
		if mb == nil {
			xusercodeErrorf("TRYCREATE", "%w", store.ErrUnknownMailbox)
		}

		// Resolve "*" for UID or message sequence.
		if star {
			if len(c.uids) == 0 {
				return func() { xuserErrorf("cannot use * on empty mailbox") }
			}
			if isUID {
				num = uint32(c.uids[len(c.uids)-1])
			} else {
				num = uint32(len(c.uids))
			}
			star = false
		}

		// Find or verify UID of message to replace.
		var seq msgseq
		if isUID {
			seq = c.sequence(store.UID(num))
			if seq <= 0 {
				return func() { xuserErrorf("unknown uid %d", num) }
			}
		} else if num > uint32(len(c.uids)) {
			return func() { xuserErrorf("invalid msgseq") }
		} else {
			seq = msgseq(num)
		}

		uidOld = c.uids[int(seq)-1]

		// Check the message still exists in the database. If it doesn't, it may have been
		// deleted just now and we won't check the quota. We'll raise an error later on,
		// when we are not possibly reading a sync literal and can respond with unsolicited
		// expunges.
		q := bstore.QueryTx[store.Message](tx)
		q.FilterNonzero(store.Message{MailboxID: c.mailboxID, UID: uidOld})
		q.FilterEqual("Expunged", false)
		om, err := q.Get()
		if err == bstore.ErrAbsent {
			return nil
		}
		if err != nil {
			return func() { xserverErrorf("get message to replace: %v", err) }
		}

		delta := size - om.Size
		ok, maxSize, err := c.account.CanAddMessageSize(tx, delta)
		if err != nil {
			return func() { xserverErrorf("check quota: %v", err) }
		}
		if !ok {
			// ../rfc/9208:472
			return func() { xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize) }
		}
		return nil
	}

	var errfn func()
	if synclit {
		// Check request, if it cannot succeed, fail it now before client is sending the data.

		name = xcheckmailboxname(name, true)

		c.account.WithRLock(func() {
			c.xdbread(func(tx *bstore.Tx) {
				errfn = checkMessage(tx)
				if errfn != nil {
					errfn()
				}
			})
		})

		c.writelinef("+ ")
	} else {
		var err error
		name, _, err = store.CheckMailboxName(name, true)
		if err != nil {
			errfn = func() { xusercodeErrorf("CANNOT", "%s", err) }
		} else {
			c.account.WithRLock(func() {
				c.xdbread(func(tx *bstore.Tx) {
					errfn = checkMessage(tx)
				})
			})
		}
	}

	var file *os.File
	var newMsgPath string
	var f io.Writer
	var committed bool

	var oldMsgPath string // To remove on success.

	if errfn != nil {
		// We got a non-sync literal, we will consume some data, but abort if there's too
		// much. We draw the line at 1mb. Client should have used synchronizing literal.
		if size > 1000*1000 {
			// ../rfc/9051:357 ../rfc/3501:347
			err := errors.New("error condition and non-synchronizing literal too big")
			bye := "* BYE [ALERT] " + err.Error()
			panic(syntaxError{bye, "TOOBIG", err.Error(), err})
		}
		// Message will not be accepted.
		f = io.Discard
	} else {
		// Read the message into a temporary file.
		var err error
		file, err = store.CreateMessageTemp(c.log, "imap-replace")
		xcheckf(err, "creating temp file for message")
		newMsgPath = file.Name()
		f = file

		defer func() {
			if file != nil {
				err := file.Close()
				c.xsanity(err, "close temporary file for replace")
			}
			if newMsgPath != "" && !committed {
				err := os.Remove(newMsgPath)
				c.xsanity(err, "remove temporary file for replace")
			}
			if committed {
				err := os.Remove(oldMsgPath)
				c.xsanity(err, "remove old message")
			}
		}()
	}

	// Read the message data.
	defer c.xtrace(mlog.LevelTracedata)()
	mw := message.NewWriter(f)
	msize, err := io.Copy(mw, io.LimitReader(c.br, size))
	c.xtrace(mlog.LevelTrace) // Restore.
	if err != nil {
		// Cannot use xcheckf due to %w handling of errIO.
		c.xbrokenf("reading literal message: %s (%w)", err, errIO)
	}
	if msize != size {
		c.xbrokenf("read %d bytes for message, expected %d (%w)", msize, size, errIO)
	}

	// Finish reading the command.
	line := c.readline(false)
	p = newParser(line, c)
	if utf8 {
		p.xtake(")")
	}
	p.xempty()

	// If an error was found earlier, abort the command now that we've read the message.
	if errfn != nil {
		errfn()
	}

	var oldMsgExpunged bool

	var om, nm store.Message
	var mbSrc, mbDst store.Mailbox // Src and dst mailboxes can be different. ../rfc/8508:263
	var pendingChanges []store.Change

	c.account.WithWLock(func() {
		var changes []store.Change

		c.xdbwrite(func(tx *bstore.Tx) {
			mbSrc = c.xmailboxID(tx, c.mailboxID)

			// Get old message. If it has been expunged, we should have a pending change for
			// it. We'll send untagged responses and fail the command.
			var err error
			qom := bstore.QueryTx[store.Message](tx)
			qom.FilterNonzero(store.Message{MailboxID: mbSrc.ID, UID: uidOld})
			om, err = qom.Get()
			xcheckf(err, "get old message to replace from database")
			if om.Expunged {
				oldMsgExpunged = true
				return
			}

			// Check quota. Even if the delta is negative, the quota may have changed.
			ok, maxSize, err := c.account.CanAddMessageSize(tx, mw.Size-om.Size)
			xcheckf(err, "checking quota")
			if !ok {
				// ../rfc/9208:472
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize)
			}

			modseq, err := c.account.NextModSeq(tx)
			xcheckf(err, "get next mod seq")

			// Subtract counts for message from source mailbox.
			mbSrc.Sub(om.MailboxCounts())

			// Remove message recipients for old message.
			_, err = bstore.QueryTx[store.Recipient](tx).FilterNonzero(store.Recipient{MessageID: om.ID}).Delete()
			xcheckf(err, "removing message recipients")

			// Subtract size of old message from account.
			err = c.account.AddMessageSize(c.log, tx, -om.Size)
			xcheckf(err, "updating disk usage")

			// Undo any junk filter training for the old message.
			om.Junk = false
			om.Notjunk = false
			err = c.account.RetrainMessages(context.TODO(), c.log, tx, []store.Message{om})
			xcheckf(err, "untraining expunged messages")

			// Mark old message expunged.
			om.ModSeq = modseq
			om.PrepareExpunge()
			err = tx.Update(&om)
			xcheckf(err, "mark old message as expunged")

			// Update source mailbox.
			mbSrc.ModSeq = modseq
			err = tx.Update(&mbSrc)
			xcheckf(err, "updating source mailbox counts")

			mbDst = c.xmailbox(tx, name, "TRYCREATE")
			mbDst.ModSeq = modseq

			nkeywords := len(mbDst.Keywords)

			// Make new message to deliver.
			nm = store.Message{
				MailboxID:     mbDst.ID,
				MailboxOrigID: mbDst.ID,
				Received:      tm,
				Flags:         storeFlags,
				Keywords:      keywords,
				Size:          mw.Size,
				ModSeq:        modseq,
				CreateSeq:     modseq,
			}

			err = c.account.MessageAdd(c.log, tx, &mbDst, &nm, file, store.AddOpts{})
			xcheckf(err, "delivering message")

			changes = append(changes,
				store.ChangeRemoveUIDs{MailboxID: om.MailboxID, UIDs: []store.UID{om.UID}, ModSeq: om.ModSeq},
				nm.ChangeAddUID(),
				mbDst.ChangeCounts(),
			)
			if nkeywords != len(mbDst.Keywords) {
				changes = append(changes, mbDst.ChangeKeywords())
			}

			err = tx.Update(&mbDst)
			xcheckf(err, "updating destination mailbox")

			// Update path to what is stored in the account. We may still have to clean it up on errors.
			newMsgPath = c.account.MessagePath(nm.ID)
			oldMsgPath = c.account.MessagePath(om.ID)
		})

		// Fetch pending changes, possibly with new UIDs, so we can apply them before adding our own new UID.
		pendingChanges = c.comm.Get()

		if oldMsgExpunged {
			return
		}

		// Success, make sure messages aren't cleaned up anymore.
		committed = true

		// Broadcast the change to other connections.
		if mbSrc.ID != mbDst.ID {
			changes = append(changes, mbSrc.ChangeCounts())
		}
		c.broadcast(changes)
	})

	// Must update our msgseq/uids tracking with latest pending changes.
	c.applyChanges(pendingChanges, false)

	// If we couldn't find the message, send a NO response. We've just applied pending
	// changes, which should have expunged the absent message.
	if oldMsgExpunged {
		xuserErrorf("message to be replaced has been expunged")
	}

	// If the destination mailbox is our currently selected mailbox, we register and
	// announce the new message.
	if mbDst.ID == c.mailboxID {
		c.uidAppend(nm.UID)
		// We send an untagged OK with APPENDUID, for sane bookkeeping in clients. ../rfc/8508:401
		c.bwritelinef("* OK [APPENDUID %d %d] ", mbDst.UIDValidity, nm.UID)
		c.bwritelinef("* %d EXISTS", len(c.uids))
	}

	// We must return vanished instead of expunge, and also highestmodseq, when qresync
	// was enabled. ../rfc/8508:422 ../rfc/7162:1883
	qresync := c.enabled[capQresync]

	// Now that we are in sync with msgseq, we can find our old msgseq and say it is
	// expunged or vanished. ../rfc/7162:1900
	omsgseq := c.xsequence(om.UID)
	c.sequenceRemove(omsgseq, om.UID)
	if qresync {
		c.bwritelinef("* VANISHED %d", om.UID)
		// ../rfc/7162:1916
	} else {
		c.bwritelinef("* %d EXPUNGE", omsgseq)
	}
	c.writeresultf("%s OK [HIGHESTMODSEQ %d] replaced", tag, nm.ModSeq.Client())
}
