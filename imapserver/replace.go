package imapserver

import (
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
			return func() { xusercodeErrorf("TRYCREATE", "%w", store.ErrUnknownMailbox) }
		}

		// Resolve "*" for UID or message sequence.
		if star {
			if c.uidonly {
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
				q.FilterEqual("Expunged", false)
				q.FilterLess("UID", c.uidnext)
				q.SortDesc("UID")
				q.Limit(1)
				m, err := q.Get()
				if err == bstore.ErrAbsent {
					return func() { xsyntaxErrorf("cannot use * on empty mailbox") }
				}
				xcheckf(err, "get last message in mailbox")
				num = uint32(m.UID)
			} else if c.exists == 0 {
				return func() { xsyntaxErrorf("cannot use * on empty mailbox") }
			} else if isUID {
				num = uint32(c.uids[c.exists-1])
			} else {
				num = uint32(c.exists)
			}
			star = false
		}

		// Find or verify UID of message to replace.
		if isUID {
			uidOld = store.UID(num)
		} else if num > c.exists {
			return func() { xuserErrorf("invalid msgseq") }
		} else {
			uidOld = c.uids[int(num)-1]
		}

		// Check the message still exists in the database. If it doesn't, it may have been
		// deleted just now and we won't check the quota. We'll raise an error later on,
		// when we are not possibly reading a sync literal and can respond with unsolicited
		// expunges.
		q := bstore.QueryTx[store.Message](tx)
		q.FilterNonzero(store.Message{MailboxID: c.mailboxID, UID: uidOld})
		q.FilterEqual("Expunged", false)
		q.FilterLess("UID", c.uidnext)
		_, err = q.Get()
		if err == bstore.ErrAbsent {
			return nil
		}
		if err != nil {
			return func() { xserverErrorf("get message to replace: %v", err) }
		}

		// Check if we can add size bytes. We can't necessarily remove the current message yet.
		ok, maxSize, err := c.account.CanAddMessageSize(tx, size)
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

		c.xwritelinef("+ ")
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
	var newID int64 // Delivered message ID, file removed on error.
	var f io.Writer
	var commit bool

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
		defer store.CloseRemoveTempFile(c.log, file, "temporary message file")
		f = file

		defer func() {
			if !commit && newID != 0 {
				p := c.account.MessagePath(newID)
				err := os.Remove(p)
				c.xsanity(err, "remove message file for replace after error")
			}
		}()
	}

	// Read the message data.
	defer c.xtraceread(mlog.LevelTracedata)()
	mw := message.NewWriter(f)
	msize, err := io.Copy(mw, io.LimitReader(c.br, size))
	c.xtraceread(mlog.LevelTrace) // Restore.
	if err != nil {
		// Cannot use xcheckf due to %w handling of errIO.
		c.xbrokenf("reading literal message: %s (%w)", err, errIO)
	}
	if msize != size {
		c.xbrokenf("read %d bytes for message, expected %d (%w)", msize, size, errIO)
	}

	// Finish reading the command.
	line := c.xreadline(false)
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
	var overflow bool
	var pendingChanges []store.Change
	defer func() {
		// In case of panic.
		c.flushChanges(pendingChanges)
	}()

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

			// Check quota for addition of new message. We can't necessarily yet remove the old message.
			ok, maxSize, err := c.account.CanAddMessageSize(tx, mw.Size)
			xcheckf(err, "checking quota")
			if !ok {
				// ../rfc/9208:472
				xusercodeErrorf("OVERQUOTA", "account over maximum total message size %d", maxSize)
			}

			modseq, err := c.account.NextModSeq(tx)
			xcheckf(err, "get next mod seq")

			chremuids, _, err := c.account.MessageRemove(c.log, tx, modseq, &mbSrc, store.RemoveOpts{}, om)
			xcheckf(err, "expunge old message")
			changes = append(changes, chremuids)
			// Note: we only add a mbSrc counts change later on, if it is not equal to mbDst.

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
			newID = nm.ID

			changes = append(changes, nm.ChangeAddUID(mbDst), mbDst.ChangeCounts())
			if nkeywords != len(mbDst.Keywords) {
				changes = append(changes, mbDst.ChangeKeywords())
			}

			err = tx.Update(&mbDst)
			xcheckf(err, "updating destination mailbox")
		})

		// Fetch pending changes, possibly with new UIDs, so we can apply them before adding our own new UID.
		overflow, pendingChanges = c.comm.Get()

		if oldMsgExpunged {
			return
		}

		// Success, make sure messages aren't cleaned up anymore.
		commit = true

		// Broadcast the change to other connections.
		if mbSrc.ID != mbDst.ID {
			changes = append(changes, mbSrc.ChangeCounts())
		}
		c.broadcast(changes)
	})

	// Must update our msgseq/uids tracking with latest pending changes.
	l := pendingChanges
	pendingChanges = nil
	c.xapplyChanges(overflow, l, false)

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
		c.xbwritelinef("* OK [APPENDUID %d %d] ", mbDst.UIDValidity, nm.UID)
		c.xbwritelinef("* %d EXISTS", c.exists)
	}

	// We must return vanished instead of expunge, and also highestmodseq, when qresync
	// was enabled. ../rfc/8508:422 ../rfc/7162:1883
	qresync := c.enabled[capQresync]

	// Now that we are in sync with msgseq, we can find our old msgseq and say it is
	// expunged or vanished. ../rfc/7162:1900
	var oseq msgseq
	if c.uidonly {
		c.exists--
	} else {
		oseq = c.xsequence(om.UID)
		c.sequenceRemove(oseq, om.UID)
	}
	if qresync || c.uidonly {
		c.xbwritelinef("* VANISHED %d", om.UID)
		// ../rfc/7162:1916
	} else {
		c.xbwritelinef("* %d EXPUNGE", oseq)
	}
	c.xwriteresultf("%s OK [HIGHESTMODSEQ %d] replaced", tag, nm.ModSeq.Client())
}
