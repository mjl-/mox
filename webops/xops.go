// Package webops implements shared functionality between webapisrv and webmail.
package webops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
)

var ErrMessageNotFound = errors.New("no such message")

type XOps struct {
	DBWrite    func(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx))
	Checkf     func(ctx context.Context, err error, format string, args ...any)
	Checkuserf func(ctx context.Context, err error, format string, args ...any)
}

func (x XOps) mailboxID(ctx context.Context, tx *bstore.Tx, mailboxID int64) store.Mailbox {
	if mailboxID == 0 {
		x.Checkuserf(ctx, errors.New("invalid zero mailbox ID"), "getting mailbox")
	}
	mb, err := store.MailboxID(tx, mailboxID)
	if err == bstore.ErrAbsent || err == store.ErrMailboxExpunged {
		x.Checkuserf(ctx, err, "getting mailbox")
	}
	x.Checkf(ctx, err, "getting mailbox")
	return mb
}

// messageID returns a non-expunged message or panics with a sherpa error.
func (x XOps) messageID(ctx context.Context, tx *bstore.Tx, messageID int64) store.Message {
	if messageID == 0 {
		x.Checkuserf(ctx, errors.New("invalid zero message id"), "getting message")
	}
	m := store.Message{ID: messageID}
	err := tx.Get(&m)
	if err == bstore.ErrAbsent {
		x.Checkuserf(ctx, ErrMessageNotFound, "getting message")
	} else if err == nil && m.Expunged {
		x.Checkuserf(ctx, errors.New("message was removed"), "getting message")
	}
	x.Checkf(ctx, err, "getting message")
	return m
}

func (x XOps) MessageDelete(ctx context.Context, log mlog.Log, acc *store.Account, messageIDs []int64) {
	acc.WithWLock(func() {
		var changes []store.Change

		x.DBWrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			changes = x.MessageDeleteTx(ctx, log, tx, acc, messageIDs, &modseq)
		})

		store.BroadcastChanges(acc, changes)
	})
}

func (x XOps) MessageDeleteTx(ctx context.Context, log mlog.Log, tx *bstore.Tx, acc *store.Account, messageIDs []int64, modseq *store.ModSeq) []store.Change {
	changes := make([]store.Change, 0, 1+1) // 1 remove, 1 mailbox counts, optimistic that all messages are in 1 mailbox.

	var jf *junk.Filter
	defer func() {
		if jf != nil {
			err := jf.CloseDiscard()
			log.Check(err, "close junk filter")
		}
	}()

	conf, _ := acc.Conf()

	var mb store.Mailbox
	var changeRemoveUIDs store.ChangeRemoveUIDs
	xflushMailbox := func() {
		err := tx.Update(&mb)
		x.Checkf(ctx, err, "updating mailbox counts")
		slices.Sort(changeRemoveUIDs.UIDs)
		changeRemoveUIDs.UIDNext = mb.UIDNext
		changeRemoveUIDs.MessageCountIMAP = mb.MessageCountIMAP()
		changeRemoveUIDs.Unseen = uint32(mb.MailboxCounts.Unseen)
		changes = append(changes, mb.ChangeCounts(), changeRemoveUIDs)
	}

	for _, id := range messageIDs {
		m := x.messageID(ctx, tx, id)

		if *modseq == 0 {
			var err error
			*modseq, err = acc.NextModSeq(tx)
			x.Checkf(ctx, err, "assigning next modseq")
		}

		if m.MailboxID != mb.ID {
			if mb.ID != 0 {
				xflushMailbox()
			}
			mb = x.mailboxID(ctx, tx, m.MailboxID)
			mb.ModSeq = *modseq
			changeRemoveUIDs = store.ChangeRemoveUIDs{MailboxID: mb.ID, ModSeq: *modseq}
		}

		if m.Junk != m.Notjunk && jf == nil && conf.JunkFilter != nil {
			var err error
			jf, _, err = acc.OpenJunkFilter(ctx, log)
			x.Checkf(ctx, err, "open junk filter")
		}

		opts := store.RemoveOpts{JunkFilter: jf}
		_, _, err := acc.MessageRemove(log, tx, *modseq, &mb, opts, m)
		x.Checkf(ctx, err, "expunge message")

		changeRemoveUIDs.UIDs = append(changeRemoveUIDs.UIDs, m.UID)
		changeRemoveUIDs.MsgIDs = append(changeRemoveUIDs.MsgIDs, m.ID)
	}

	xflushMailbox()

	if jf != nil {
		err := jf.Close()
		jf = nil
		x.Checkf(ctx, err, "close junk filter")
	}

	return changes
}

func (x XOps) MessageFlagsAdd(ctx context.Context, log mlog.Log, acc *store.Account, messageIDs []int64, flaglist []string) {
	flags, keywords, err := store.ParseFlagsKeywords(flaglist)
	x.Checkuserf(ctx, err, "parsing flags")

	acc.WithRLock(func() {
		var changes []store.Change

		x.DBWrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			var retrain []store.Message
			var mb, origmb store.Mailbox

			for _, mid := range messageIDs {
				m := x.messageID(ctx, tx, mid)

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					x.Checkf(ctx, err, "assigning next modseq")
				}

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
						mb.ModSeq = modseq
						err := tx.Update(&mb)
						x.Checkf(ctx, err, "updating mailbox")
						if mb.MailboxCounts != origmb.MailboxCounts {
							changes = append(changes, mb.ChangeCounts())
						}
						if mb.KeywordsChanged(origmb) {
							changes = append(changes, mb.ChangeKeywords())
						}
					}
					mb = x.mailboxID(ctx, tx, m.MailboxID)
					origmb = mb
				}
				mb.Keywords, _ = store.MergeKeywords(mb.Keywords, keywords)

				mb.Sub(m.MailboxCounts())
				oflags := m.Flags
				m.Flags = m.Flags.Set(flags, flags)
				var kwChanged bool
				m.Keywords, kwChanged = store.MergeKeywords(m.Keywords, keywords)
				mb.Add(m.MailboxCounts())

				if m.Flags == oflags && !kwChanged {
					continue
				}

				m.ModSeq = modseq
				err = tx.Update(&m)
				x.Checkf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags, mb))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				mb.ModSeq = modseq
				err := tx.Update(&mb)
				x.Checkf(ctx, err, "updating mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				if mb.KeywordsChanged(origmb) {
					changes = append(changes, mb.ChangeKeywords())
				}
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain)
			x.Checkf(ctx, err, "retraining messages")
		})

		store.BroadcastChanges(acc, changes)
	})
}

func (x XOps) MessageFlagsClear(ctx context.Context, log mlog.Log, acc *store.Account, messageIDs []int64, flaglist []string) {
	flags, keywords, err := store.ParseFlagsKeywords(flaglist)
	x.Checkuserf(ctx, err, "parsing flags")

	acc.WithRLock(func() {
		var retrain []store.Message
		var changes []store.Change

		x.DBWrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			var mb, origmb store.Mailbox

			for _, mid := range messageIDs {
				m := x.messageID(ctx, tx, mid)

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					x.Checkf(ctx, err, "assigning next modseq")
				}

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
						mb.ModSeq = modseq
						err := tx.Update(&mb)
						x.Checkf(ctx, err, "updating counts for mailbox")
						if mb.MailboxCounts != origmb.MailboxCounts {
							changes = append(changes, mb.ChangeCounts())
						}
						// note: cannot remove keywords from mailbox by removing keywords from message.
					}
					mb = x.mailboxID(ctx, tx, m.MailboxID)
					origmb = mb
				}

				oflags := m.Flags
				mb.Sub(m.MailboxCounts())
				m.Flags = m.Flags.Set(flags, store.Flags{})
				var changed bool
				m.Keywords, changed = store.RemoveKeywords(m.Keywords, keywords)
				mb.Add(m.MailboxCounts())

				if m.Flags == oflags && !changed {
					continue
				}

				m.ModSeq = modseq
				err = tx.Update(&m)
				x.Checkf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags, mb))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				mb.ModSeq = modseq
				err := tx.Update(&mb)
				x.Checkf(ctx, err, "updating keywords in mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				// note: cannot remove keywords from mailbox by removing keywords from message.
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain)
			x.Checkf(ctx, err, "retraining messages")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxesMarkRead updates all messages in the referenced mailboxes as seen when
// they aren't yet. The mailboxes are updated with their unread messages counts,
// and the changes are propagated.
func (x XOps) MailboxesMarkRead(ctx context.Context, log mlog.Log, acc *store.Account, mailboxIDs []int64) {
	acc.WithRLock(func() {
		var changes []store.Change

		x.DBWrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq

			// Note: we don't need to retrain, changing the "seen" flag is not relevant.

			for _, mbID := range mailboxIDs {
				mb := x.mailboxID(ctx, tx, mbID)

				// Find messages to update.
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				q.FilterEqual("Seen", false)
				q.FilterEqual("Expunged", false)
				q.SortAsc("UID")
				var have bool
				err := q.ForEach(func(m store.Message) error {
					have = true // We need to update mailbox.

					oflags := m.Flags
					mb.Sub(m.MailboxCounts())
					m.Seen = true
					mb.Add(m.MailboxCounts())

					if modseq == 0 {
						var err error
						modseq, err = acc.NextModSeq(tx)
						x.Checkf(ctx, err, "assigning next modseq")
					}
					m.ModSeq = modseq
					err := tx.Update(&m)
					x.Checkf(ctx, err, "updating message")

					changes = append(changes, m.ChangeFlags(oflags, mb))
					return nil
				})
				x.Checkf(ctx, err, "listing messages to mark as read")

				if have {
					mb.ModSeq = modseq
					err := tx.Update(&mb)
					x.Checkf(ctx, err, "updating mailbox")
					changes = append(changes, mb.ChangeCounts())
				}
			}
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MessageMove moves messages to the mailbox represented by mailboxName, or to mailboxID if mailboxName is empty.
func (x XOps) MessageMove(ctx context.Context, log mlog.Log, acc *store.Account, messageIDs []int64, mailboxName string, mailboxID int64) {
	acc.WithWLock(func() {
		var changes []store.Change

		var newIDs []int64
		defer func() {
			for _, id := range newIDs {
				p := acc.MessagePath(id)
				err := os.Remove(p)
				log.Check(err, "removing delivered message after failure", slog.String("path", p))
			}
		}()

		x.DBWrite(ctx, acc, func(tx *bstore.Tx) {
			if mailboxName != "" {
				mb, err := acc.MailboxFind(tx, mailboxName)
				x.Checkf(ctx, err, "looking up mailbox name")
				if mb == nil {
					x.Checkuserf(ctx, errors.New("not found"), "looking up mailbox name")
				} else {
					mailboxID = mb.ID
				}
			}

			mbDst := x.mailboxID(ctx, tx, mailboxID)

			if len(messageIDs) == 0 {
				return
			}

			var modseq store.ModSeq
			newIDs, changes = x.MessageMoveTx(ctx, log, acc, tx, messageIDs, mbDst, &modseq)
		})
		newIDs = nil

		store.BroadcastChanges(acc, changes)
	})
}

// MessageMoveTx moves message to a new mailbox, which must be different than their
// current mailbox. Moving a message is done by changing the MailboxID and
// assigning an appriorate new UID, and then inserting a replacement Message record
// with new ID that is marked expunged in the original mailbox, along with a
// MessageErase record so the message gets erased when all sessions stopped
// referencing the message.
func (x XOps) MessageMoveTx(ctx context.Context, log mlog.Log, acc *store.Account, tx *bstore.Tx, messageIDs []int64, mbDst store.Mailbox, modseq *store.ModSeq) ([]int64, []store.Change) {
	var newIDs []int64
	var commit bool
	defer func() {
		if commit {
			return
		}
		for _, id := range newIDs {
			p := acc.MessagePath(id)
			err := os.Remove(p)
			log.Check(err, "removing delivered message after failure", slog.String("path", p))
		}
		newIDs = nil
	}()

	// n adds, 1 remove, 2 mailboxcounts, 1 mailboxkeywords, optimistic that messages are in a single source mailbox.
	changes := make([]store.Change, 0, len(messageIDs)+4)

	var err error
	if *modseq == 0 {
		*modseq, err = acc.NextModSeq(tx)
		x.Checkf(ctx, err, "assigning next modseq")
	}

	mbDst.ModSeq = *modseq

	// Get messages. group them by mailbox.
	l := make([]store.Message, len(messageIDs))
	for i, id := range messageIDs {
		l[i] = x.messageID(ctx, tx, id)
		if l[i].MailboxID == mbDst.ID {
			// Client should filter out messages that are already in mailbox.
			x.Checkuserf(ctx, fmt.Errorf("message %d already in destination mailbox", l[i].ID), "moving message")
		}
	}

	// Sort (group) by mailbox, sort by UID.
	sort.Slice(l, func(i, j int) bool {
		if l[i].MailboxID != l[j].MailboxID {
			return l[i].MailboxID < l[j].MailboxID
		}
		return l[i].UID < l[j].UID
	})

	var jf *junk.Filter
	defer func() {
		if jf != nil {
			err := jf.CloseDiscard()
			log.Check(err, "close junk filter")
		}
	}()

	accConf, _ := acc.Conf()

	var mbSrc store.Mailbox
	var changeRemoveUIDs store.ChangeRemoveUIDs
	xflushMailbox := func() {
		changeRemoveUIDs.UIDNext = mbSrc.UIDNext
		changeRemoveUIDs.MessageCountIMAP = mbSrc.MessageCountIMAP()
		changeRemoveUIDs.Unseen = uint32(mbSrc.MailboxCounts.Unseen)
		changes = append(changes, changeRemoveUIDs, mbSrc.ChangeCounts())

		err = tx.Update(&mbSrc)
		x.Checkf(ctx, err, "updating source mailbox counts")
	}

	nkeywords := len(mbDst.Keywords)
	now := time.Now()

	syncDirs := map[string]struct{}{}

	for _, om := range l {
		if om.MailboxID != mbSrc.ID {
			if mbSrc.ID != 0 {
				xflushMailbox()
			}
			mbSrc = x.mailboxID(ctx, tx, om.MailboxID)
			mbSrc.ModSeq = *modseq
			changeRemoveUIDs = store.ChangeRemoveUIDs{MailboxID: mbSrc.ID, ModSeq: *modseq}
		}

		nm := om
		nm.MailboxID = mbDst.ID
		nm.UID = mbDst.UIDNext
		err := mbDst.UIDNextAdd(1)
		x.Checkf(ctx, err, "adding uid")
		nm.ModSeq = *modseq
		nm.CreateSeq = *modseq
		nm.SaveDate = &now
		if nm.IsReject && nm.MailboxDestinedID != 0 {
			// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
			// is used for reputation calculation during future deliveries.
			nm.MailboxOrigID = nm.MailboxDestinedID
			nm.IsReject = false
			nm.Seen = false
		}
		if mbDst.Trash {
			nm.Seen = true
		}

		nm.JunkFlagsForMailbox(mbDst, accConf)

		err = tx.Update(&nm)
		x.Checkf(ctx, err, "updating message with new mailbox")

		mbDst.Add(nm.MailboxCounts())

		mbSrc.Sub(om.MailboxCounts())
		om.ID = 0
		om.Expunged = true
		om.ModSeq = *modseq
		om.TrainedJunk = nil
		err = tx.Insert(&om)
		x.Checkf(ctx, err, "inserting expunged message in old mailbox")

		dstPath := acc.MessagePath(om.ID)
		dstDir := filepath.Dir(dstPath)
		if _, ok := syncDirs[dstDir]; !ok {
			os.MkdirAll(dstDir, 0770)
			syncDirs[dstDir] = struct{}{}
		}

		err = moxio.LinkOrCopy(log, dstPath, acc.MessagePath(nm.ID), nil, false)
		x.Checkf(ctx, err, "duplicating message in old mailbox for current sessions")
		newIDs = append(newIDs, nm.ID)
		// We don't sync the directory. In case of a crash and files disappearing, the
		// eraser will simply not find the file at next startup.

		err = tx.Insert(&store.MessageErase{ID: om.ID, SkipUpdateDiskUsage: true})
		x.Checkf(ctx, err, "insert message erase")

		mbDst.Keywords, _ = store.MergeKeywords(mbDst.Keywords, nm.Keywords)

		if accConf.JunkFilter != nil && nm.NeedsTraining() {
			// Lazily open junk filter.
			if jf == nil {
				jf, _, err = acc.OpenJunkFilter(ctx, log)
				x.Checkf(ctx, err, "open junk filter")
			}
			err := acc.RetrainMessage(ctx, log, tx, jf, &nm)
			x.Checkf(ctx, err, "retrain message after moving")
		}

		changeRemoveUIDs.UIDs = append(changeRemoveUIDs.UIDs, om.UID)
		changeRemoveUIDs.MsgIDs = append(changeRemoveUIDs.MsgIDs, om.ID)
		changes = append(changes, nm.ChangeAddUID(mbDst))
	}

	for dir := range syncDirs {
		err := moxio.SyncDir(log, dir)
		x.Checkf(ctx, err, "sync directory")
	}

	xflushMailbox()

	changes = append(changes, mbDst.ChangeCounts())
	if nkeywords > len(mbDst.Keywords) {
		changes = append(changes, mbDst.ChangeKeywords())
	}

	err = tx.Update(&mbDst)
	x.Checkf(ctx, err, "updating destination mailbox with uidnext and modseq")

	if jf != nil {
		err := jf.Close()
		x.Checkf(ctx, err, "saving junk filter")
		jf = nil
	}

	commit = true
	return newIDs, changes
}

func isText(p message.Part) bool {
	return p.MediaType == "" && p.MediaSubType == "" || p.MediaType == "TEXT" && p.MediaSubType == "PLAIN"
}

func isHTML(p message.Part) bool {
	return p.MediaType == "" && p.MediaSubType == "" || p.MediaType == "TEXT" && p.MediaSubType == "HTML"
}

func isAlternative(p message.Part) bool {
	return p.MediaType == "MULTIPART" && p.MediaSubType == "ALTERNATIVE"
}

func readPart(p message.Part, maxSize int64) (string, error) {
	buf, err := io.ReadAll(io.LimitReader(p.ReaderUTF8OrBinary(), maxSize))
	if err != nil {
		return "", fmt.Errorf("reading part contents: %v", err)
	}
	return string(buf), nil
}

// ReadableParts returns the contents of the first text and/or html parts,
// descending into multiparts, truncated to maxSize bytes if longer.
func ReadableParts(p message.Part, maxSize int64) (text string, html string, found bool, err error) {
	// todo: may want to merge this logic with webmail's message parsing.

	// For non-multipart messages, top-level part.
	if isText(p) {
		data, err := readPart(p, maxSize)
		return data, "", true, err
	} else if isHTML(p) {
		data, err := readPart(p, maxSize)
		return "", data, true, err
	}

	// Look in sub-parts. Stop when we have a readable part, don't continue with other
	// subparts unless we have a multipart/alternative.
	// todo: we may have to look at disposition "inline".
	var haveText, haveHTML bool
	for _, pp := range p.Parts {
		if isText(pp) {
			haveText = true
			text, err = readPart(pp, maxSize)
			if !isAlternative(p) {
				break
			}
		} else if isHTML(pp) {
			haveHTML = true
			html, err = readPart(pp, maxSize)
			if !isAlternative(p) {
				break
			}
		}
	}
	if haveText || haveHTML {
		return text, html, true, err
	}

	// Descend into the subparts.
	for _, pp := range p.Parts {
		text, html, found, err = ReadableParts(pp, maxSize)
		if found {
			break
		}
	}
	return
}
