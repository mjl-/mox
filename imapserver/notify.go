package imapserver

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/store"
)

// Max number of pending changes for selected-delayed mailbox before we write a
// NOTIFICATIONOVERFLOW message, flush changes and stop gathering more changes.
// Changed during tests.
var selectedDelayedChangesMax = 1000

// notify represents a configuration as passed to the notify command.
type notify struct {
	// "NOTIFY NONE" results in an empty list, matching no events.
	EventGroups []eventGroup

	// Changes for the selected mailbox in case of SELECTED-DELAYED, when we don't send
	// events asynchrously. These must still be processed later on for their
	// ChangeRemoveUIDs, to erase expunged message files. At the end of a command (e.g.
	// NOOP) or immediately upon IDLE we will send untagged responses for these
	// changes. If the connection breaks, we still process the ChangeRemoveUIDs.
	Delayed []store.Change
}

// match checks if an event for a mailbox id/name (optional depending on type)
// should be turned into a notification to the client.
func (n notify) match(c *conn, xtxfn func() *bstore.Tx, mailboxID int64, mailbox string, kind eventKind) (mailboxSpecifier, notifyEvent, bool) {
	// We look through the event groups, and won't stop looking until we've found a
	// confirmation the event should be notified. ../rfc/5465:756

	// Non-message-related events are only matched by non-"selected" mailbox
	// specifiers. ../rfc/5465:268
	// If you read the mailboxes matching paragraph in isolation, you would think only
	// "SELECTED" and "SELECTED-DELAYED" can match events for the selected mailbox. But
	// a few other places hint that that only applies to message events, not to mailbox
	// events, such as subscriptions and mailbox metadata changes. With a strict
	// interpretation, clients couldn't request notifications for such events for the
	// selection mailbox. ../rfc/5465:752

	for _, eg := range n.EventGroups {
		switch eg.MailboxSpecifier.Kind {
		case mbspecSelected, mbspecSelectedDelayed: // ../rfc/5465:800
			if mailboxID != c.mailboxID || !slices.Contains(messageEventKinds, kind) {
				continue
			}
			for _, ev := range eg.Events {
				if eventKind(ev.Kind) == kind {
					return eg.MailboxSpecifier, ev, true
				}
			}
			// We can only have a single selected for notify, so no point in continuing the search.
			return mailboxSpecifier{}, notifyEvent{}, false

		default:
			// The selected mailbox can only match for non-message events for specifiers other
			// than "selected"/"selected-delayed".
			if c.mailboxID == mailboxID && slices.Contains(messageEventKinds, kind) {
				continue
			}
		}

		var match bool
	Match:
		switch eg.MailboxSpecifier.Kind {
		case mbspecPersonal: // ../rfc/5465:817
			match = true

		case mbspecInboxes: // ../rfc/5465:822
			if mailbox == "Inbox" || strings.HasPrefix(mailbox, "Inbox/") {
				match = true
				break Match
			}

			if mailbox == "" {
				break Match
			}

			// Include mailboxes we may deliver to based on destinations, or based on rulesets,
			// not including deliveries for mailing lists.
			conf, _ := c.account.Conf()
			for _, dest := range conf.Destinations {
				if dest.Mailbox == mailbox {
					match = true
					break Match
				}

				for _, rs := range dest.Rulesets {
					if rs.ListAllowDomain == "" && rs.Mailbox == mailbox {
						match = true
						break Match
					}
				}
			}

		case mbspecSubscribed: // ../rfc/5465:831
			sub := store.Subscription{Name: mailbox}
			err := xtxfn().Get(&sub)
			if err != bstore.ErrAbsent {
				xcheckf(err, "lookup subscription")
			}
			match = err == nil

		case mbspecSubtree: // ../rfc/5465:847
			for _, name := range eg.MailboxSpecifier.Mailboxes {
				if mailbox == name || strings.HasPrefix(mailbox, name+"/") {
					match = true
					break
				}
			}

		case mbspecSubtreeOne: // ../rfc/7377:274
			ntoken := len(strings.Split(mailbox, "/"))
			for _, name := range eg.MailboxSpecifier.Mailboxes {
				if mailbox == name || (strings.HasPrefix(mailbox, name+"/") && len(strings.Split(name, "/"))+1 == ntoken) {
					match = true
					break
				}
			}

		case mbspecMailboxes: // ../rfc/5465:853
			match = slices.Contains(eg.MailboxSpecifier.Mailboxes, mailbox)

		default:
			panic("missing case for " + string(eg.MailboxSpecifier.Kind))
		}

		if !match {
			continue
		}

		// NONE is the signal we shouldn't return events for this mailbox. ../rfc/5465:455
		if len(eg.Events) == 0 {
			break
		}

		// If event kind matches, we will be notifying about this change. If not, we'll
		// look again at next mailbox specifiers.
		for _, ev := range eg.Events {
			if eventKind(ev.Kind) == kind {
				return eg.MailboxSpecifier, ev, true
			}
		}
	}
	return mailboxSpecifier{}, notifyEvent{}, false
}

// Notify enables continuous notifications from the server to the client, without
// the client issuing an IDLE command. The mailboxes and events to notify about are
// specified in the account. When notify is enabled, instead of being blocked
// waiting for a command from the client, we also wait for events from the account,
// and send events about it.
//
// State: Authenticated and selected.
func (c *conn) cmdNotify(tag, cmd string, p *parser) {
	// Command: ../rfc/5465:203
	// Request syntax: ../rfc/5465:923

	p.xspace()

	// NONE indicates client doesn't want any events, also not the "normal" events
	// without notify. ../rfc/5465:234
	// ../rfc/5465:930
	if p.take("NONE") {
		p.xempty()

		// If we have delayed changes for the selected mailbox, we are no longer going to
		// notify about them. The client can't know anymore whether messages still exist,
		// and trying to read them can cause errors if the messages have been expunged and
		// erased.
		var changes []store.Change
		if c.notify != nil {
			changes = c.notify.Delayed
		}
		c.notify = &notify{}
		c.flushChanges(changes)

		c.ok(tag, cmd)
		return
	}

	var n notify
	var status bool

	// ../rfc/5465:926
	p.xtake("SET")
	p.xspace()
	if p.take("STATUS") {
		status = true
		p.xspace()
	}
	for {
		eg := p.xeventGroup()
		n.EventGroups = append(n.EventGroups, eg)
		if !p.space() {
			break
		}
	}
	p.xempty()

	for _, eg := range n.EventGroups {
		var hasNew, hasExpunge, hasFlag, hasAnnotation bool
		for _, ev := range eg.Events {
			switch eventKind(ev.Kind) {
			case eventMessageNew:
				hasNew = true
			case eventMessageExpunge:
				hasExpunge = true
			case eventFlagChange:
				hasFlag = true
			case eventMailboxName, eventSubscriptionChange, eventMailboxMetadataChange, eventServerMetadataChange:
				// Nothing special.
			default: // Including eventAnnotationChange.
				hasAnnotation = true // Ineffective, we don't implement message annotations yet.
				// Result must be NO instead of BAD, and we must include BADEVENT and the events we
				// support. ../rfc/5465:343
				// ../rfc/5465:1033
				xusercodeErrorf("BADEVENT (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange MailboxMetadataChange ServerMetadataChange)", "unimplemented event %s", ev.Kind)
			}
		}
		if hasNew != hasExpunge {
			// ../rfc/5465:443 ../rfc/5465:987
			xsyntaxErrorf("MessageNew and MessageExpunge must be specified together")
		}
		if (hasFlag || hasAnnotation) && !hasNew {
			// ../rfc/5465:439
			xsyntaxErrorf("FlagChange and/or AnnotationChange requires MessageNew and MessageExpunge")
		}
	}

	for _, eg := range n.EventGroups {
		for i, name := range eg.MailboxSpecifier.Mailboxes {
			eg.MailboxSpecifier.Mailboxes[i] = xcheckmailboxname(name, true)
		}
	}

	// Only one selected/selected-delay mailbox filter is allowed. ../rfc/5465:779
	// Only message events are allowed for selected/selected-delayed. ../rfc/5465:796
	var haveSelected bool
	for _, eg := range n.EventGroups {
		switch eg.MailboxSpecifier.Kind {
		case mbspecSelected, mbspecSelectedDelayed:
			if haveSelected {
				xsyntaxErrorf("cannot have multiple selected/selected-delayed mailbox filters")
			}
			haveSelected = true

			// Only events from message-event are allowed with selected mailbox specifiers.
			// ../rfc/5465:977
			for _, ev := range eg.Events {
				if !slices.Contains(messageEventKinds, eventKind(ev.Kind)) {
					xsyntaxErrorf("selected/selected-delayed is only allowed with message events, not %s", ev.Kind)
				}
			}
		}
	}

	// We must apply any changes for delayed select. ../rfc/5465:248
	if c.notify != nil {
		delayed := c.notify.Delayed
		c.notify.Delayed = nil
		c.xapplyChangesNotify(delayed, true)
	}

	if status {
		var statuses []string

		// Flush new pending changes before we read the current state from the database.
		// Don't allow any concurrent changes for a consistent snapshot.
		c.account.WithRLock(func() {
			select {
			case <-c.comm.Pending:
				overflow, changes := c.comm.Get()
				c.xapplyChanges(overflow, changes, true)
			default:
			}

			c.xdbread(func(tx *bstore.Tx) {
				// Send STATUS responses for all matching mailboxes. ../rfc/5465:271
				q := bstore.QueryTx[store.Mailbox](tx)
				q.FilterEqual("Expunged", false)
				q.SortAsc("Name")
				for mb, err := range q.All() {
					xcheckf(err, "list mailboxes for status")

					if mb.ID == c.mailboxID {
						continue
					}
					_, _, ok := n.match(c, func() *bstore.Tx { return tx }, mb.ID, mb.Name, eventMessageNew)
					if !ok {
						continue
					}

					list := listspace{
						bare("MESSAGES"), number(mb.MessageCountIMAP()),
						bare("UIDNEXT"), number(mb.UIDNext),
						bare("UIDVALIDITY"), number(mb.UIDValidity),
						// Unseen is not mentioned for STATUS, but clients are able to parse it due to
						// FlagChange, and it will be useful to have.
						bare("UNSEEN"), number(mb.MailboxCounts.Unseen),
					}
					if c.enabled[capCondstore] || c.enabled[capQresync] {
						list = append(list, bare("HIGHESTMODSEQ"), number(mb.ModSeq))
					}

					status := fmt.Sprintf("* STATUS %s %s", mailboxt(mb.Name).pack(c), list.pack(c))
					statuses = append(statuses, status)
				}
			})
		})

		// Write outside of db transaction and lock.
		for _, s := range statuses {
			c.xbwritelinef("%s", s)
		}
	}

	// We replace the previous notify config. ../rfc/5465:245
	c.notify = &n

	// Writing OK will flush any other pending changes for the account according to the
	// new filters.
	c.ok(tag, cmd)
}
