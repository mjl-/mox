// Package webops implements shared functionality between webapisrv and webmail.
package webops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
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
	mb := store.Mailbox{ID: mailboxID}
	err := tx.Get(&mb)
	if err == bstore.ErrAbsent {
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
			_, changes = x.MessageDeleteTx(ctx, log, tx, acc, messageIDs, 0)
		})

		store.BroadcastChanges(acc, changes)
	})

	for _, mID := range messageIDs {
		p := acc.MessagePath(mID)
		err := os.Remove(p)
		log.Check(err, "removing message file for expunge")
	}
}

func (x XOps) MessageDeleteTx(ctx context.Context, log mlog.Log, tx *bstore.Tx, acc *store.Account, messageIDs []int64, modseq store.ModSeq) (store.ModSeq, []store.Change) {
	removeChanges := map[int64]store.ChangeRemoveUIDs{}
	changes := make([]store.Change, 0, len(messageIDs)+1) // n remove, 1 mailbox counts

	var mb store.Mailbox
	remove := make([]store.Message, 0, len(messageIDs))

	var totalSize int64
	for _, mid := range messageIDs {
		m := x.messageID(ctx, tx, mid)
		totalSize += m.Size

		if m.MailboxID != mb.ID {
			if mb.ID != 0 {
				err := tx.Update(&mb)
				x.Checkf(ctx, err, "updating mailbox counts")
				changes = append(changes, mb.ChangeCounts())
			}
			mb = x.mailboxID(ctx, tx, m.MailboxID)
		}

		qmr := bstore.QueryTx[store.Recipient](tx)
		qmr.FilterEqual("MessageID", m.ID)
		_, err := qmr.Delete()
		x.Checkf(ctx, err, "removing message recipients")

		mb.Sub(m.MailboxCounts())

		if modseq == 0 {
			modseq, err = acc.NextModSeq(tx)
			x.Checkf(ctx, err, "assigning next modseq")
		}
		m.Expunged = true
		m.ModSeq = modseq
		err = tx.Update(&m)
		x.Checkf(ctx, err, "marking message as expunged")

		ch := removeChanges[m.MailboxID]
		ch.UIDs = append(ch.UIDs, m.UID)
		ch.MailboxID = m.MailboxID
		ch.ModSeq = modseq
		removeChanges[m.MailboxID] = ch
		remove = append(remove, m)
	}

	if mb.ID != 0 {
		err := tx.Update(&mb)
		x.Checkf(ctx, err, "updating count in mailbox")
		changes = append(changes, mb.ChangeCounts())
	}

	err := acc.AddMessageSize(log, tx, -totalSize)
	x.Checkf(ctx, err, "updating disk usage")

	// Mark removed messages as not needing training, then retrain them, so if they
	// were trained, they get untrained.
	for i := range remove {
		remove[i].Junk = false
		remove[i].Notjunk = false
	}
	err = acc.RetrainMessages(ctx, log, tx, remove, true)
	x.Checkf(ctx, err, "untraining deleted messages")

	for _, ch := range removeChanges {
		sort.Slice(ch.UIDs, func(i, j int) bool {
			return ch.UIDs[i] < ch.UIDs[j]
		})
		changes = append(changes, ch)
	}

	return modseq, changes
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

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
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

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					x.Checkf(ctx, err, "assigning next modseq")
				}
				m.ModSeq = modseq
				err = tx.Update(&m)
				x.Checkf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				err := tx.Update(&mb)
				x.Checkf(ctx, err, "updating mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				if mb.KeywordsChanged(origmb) {
					changes = append(changes, mb.ChangeKeywords())
				}
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain, false)
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

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
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

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					x.Checkf(ctx, err, "assigning next modseq")
				}
				m.ModSeq = modseq
				err = tx.Update(&m)
				x.Checkf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				err := tx.Update(&mb)
				x.Checkf(ctx, err, "updating keywords in mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				// note: cannot remove keywords from mailbox by removing keywords from message.
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain, false)
			x.Checkf(ctx, err, "retraining messages")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MessageMove moves messages to the mailbox represented by mailboxName, or to mailboxID if mailboxName is empty.
func (x XOps) MessageMove(ctx context.Context, log mlog.Log, acc *store.Account, messageIDs []int64, mailboxName string, mailboxID int64) {
	acc.WithRLock(func() {
		var changes []store.Change

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

			_, changes = x.MessageMoveTx(ctx, log, acc, tx, messageIDs, mbDst, 0)
		})

		store.BroadcastChanges(acc, changes)
	})
}

func (x XOps) MessageMoveTx(ctx context.Context, log mlog.Log, acc *store.Account, tx *bstore.Tx, messageIDs []int64, mbDst store.Mailbox, modseq store.ModSeq) (store.ModSeq, []store.Change) {
	retrain := make([]store.Message, 0, len(messageIDs))
	removeChanges := map[int64]store.ChangeRemoveUIDs{}
	// n adds, 1 remove, 2 mailboxcounts, optimistic and at least for a single message.
	changes := make([]store.Change, 0, len(messageIDs)+3)

	var mbSrc store.Mailbox

	keywords := map[string]struct{}{}

	for _, mid := range messageIDs {
		m := x.messageID(ctx, tx, mid)

		// We may have loaded this mailbox in the previous iteration of this loop.
		if m.MailboxID != mbSrc.ID {
			if mbSrc.ID != 0 {
				err := tx.Update(&mbSrc)
				x.Checkf(ctx, err, "updating source mailbox counts")
				changes = append(changes, mbSrc.ChangeCounts())
			}
			mbSrc = x.mailboxID(ctx, tx, m.MailboxID)
		}

		if mbSrc.ID == mbDst.ID {
			// Client should filter out messages that are already in mailbox.
			x.Checkuserf(ctx, errors.New("already in destination mailbox"), "moving message")
		}

		var err error
		if modseq == 0 {
			modseq, err = acc.NextModSeq(tx)
			x.Checkf(ctx, err, "assigning next modseq")
		}

		ch := removeChanges[m.MailboxID]
		ch.UIDs = append(ch.UIDs, m.UID)
		ch.ModSeq = modseq
		ch.MailboxID = m.MailboxID
		removeChanges[m.MailboxID] = ch

		// Copy of message record that we'll insert when UID is freed up.
		om := m
		om.PrepareExpunge()
		om.ID = 0 // Assign new ID.
		om.ModSeq = modseq

		mbSrc.Sub(m.MailboxCounts())

		if mbDst.Trash {
			m.Seen = true
		}
		conf, _ := acc.Conf()
		m.MailboxID = mbDst.ID
		if m.IsReject && m.MailboxDestinedID != 0 {
			// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
			// is used for reputation calculation during future deliveries.
			m.MailboxOrigID = m.MailboxDestinedID
			m.IsReject = false
			m.Seen = false
		}
		m.UID = mbDst.UIDNext
		m.ModSeq = modseq
		mbDst.UIDNext++
		m.JunkFlagsForMailbox(mbDst, conf)
		err = tx.Update(&m)
		x.Checkf(ctx, err, "updating moved message in database")

		// Now that UID is unused, we can insert the old record again.
		err = tx.Insert(&om)
		x.Checkf(ctx, err, "inserting record for expunge after moving message")

		mbDst.Add(m.MailboxCounts())

		changes = append(changes, m.ChangeAddUID())
		retrain = append(retrain, m)

		for _, kw := range m.Keywords {
			keywords[kw] = struct{}{}
		}
	}

	err := tx.Update(&mbSrc)
	x.Checkf(ctx, err, "updating source mailbox counts")

	changes = append(changes, mbSrc.ChangeCounts(), mbDst.ChangeCounts())

	// Ensure destination mailbox has keywords of the moved messages.
	var mbKwChanged bool
	mbDst.Keywords, mbKwChanged = store.MergeKeywords(mbDst.Keywords, maps.Keys(keywords))
	if mbKwChanged {
		changes = append(changes, mbDst.ChangeKeywords())
	}

	err = tx.Update(&mbDst)
	x.Checkf(ctx, err, "updating mailbox with uidnext")

	err = acc.RetrainMessages(ctx, log, tx, retrain, false)
	x.Checkf(ctx, err, "retraining messages after move")

	// Ensure UIDs of the removed message are in increasing order. It is quite common
	// for all messages to be from a single source mailbox, meaning this is just one
	// change, for which we preallocated space.
	for _, ch := range removeChanges {
		sort.Slice(ch.UIDs, func(i, j int) bool {
			return ch.UIDs[i] < ch.UIDs[j]
		})
		changes = append(changes, ch)
	}

	return modseq, changes
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
