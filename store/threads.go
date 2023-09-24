package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"time"

	"golang.org/x/exp/slices"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

// Assign a new/incoming message to a thread. Message does not yet have an ID. If
// this isn't a response, ThreadID should remain 0 (unless this is a message with
// existing message-id) and the caller must set ThreadID to ID.
// If the account is still busy upgrading messages with threadids in the background, parents
// may have a threadid 0. That results in this message getting threadid 0, which
// will handled by the background upgrade process assigning a threadid when it gets
// to this message.
func assignThread(log *mlog.Log, tx *bstore.Tx, m *Message, part *message.Part) error {
	if m.MessageID != "" {
		// Match against existing different message with same Message-ID.
		q := bstore.QueryTx[Message](tx)
		q.FilterNonzero(Message{MessageID: m.MessageID})
		q.FilterEqual("Expunged", false)
		q.FilterNotEqual("ID", m.ID)
		q.FilterNotEqual("ThreadID", int64(0))
		q.SortAsc("ID")
		q.Limit(1)
		em, err := q.Get()
		if err != nil && err != bstore.ErrAbsent {
			return fmt.Errorf("looking up existing message with message-id: %v", err)
		} else if err == nil {
			assignParent(m, em, true)
			return nil
		}
	}

	h, err := part.Header()
	if err != nil {
		log.Errorx("assigning threads: parsing references/in-reply-to headers, not matching by message-id", err, mlog.Field("msgid", m.ID))
	}
	messageIDs, err := message.ReferencedIDs(h.Values("References"), h.Values("In-Reply-To"))
	if err != nil {
		log.Errorx("assigning threads: parsing references/in-reply-to headers, not matching by message-id", err, mlog.Field("msgid", m.ID))
	}
	for i := len(messageIDs) - 1; i >= 0; i-- {
		messageID := messageIDs[i]
		if messageID == m.MessageID {
			continue
		}
		tm, _, err := lookupThreadMessage(tx, m.ID, messageID, m.SubjectBase)
		if err != nil {
			return fmt.Errorf("looking up thread message for new message: %v", err)
		} else if tm != nil {
			assignParent(m, *tm, true)
			return nil
		}
		m.ThreadMissingLink = true
	}
	if len(messageIDs) > 0 {
		return nil
	}

	var isResp bool
	if part != nil && part.Envelope != nil {
		m.SubjectBase, isResp = message.ThreadSubject(part.Envelope.Subject, false)
	}
	if !isResp || m.SubjectBase == "" {
		return nil
	}
	m.ThreadMissingLink = true
	tm, err := lookupThreadMessageSubject(tx, *m, m.SubjectBase)
	if err != nil {
		return fmt.Errorf("looking up thread message by subject: %v", err)
	} else if tm != nil {
		assignParent(m, *tm, true)
	}
	return nil
}

// assignParent assigns threading fields to m that make it a child of parent message pm.
// updateSeen indicates if m.Seen should be cleared if pm is thread-muted.
func assignParent(m *Message, pm Message, updateSeen bool) {
	if pm.ThreadID == 0 {
		panic(fmt.Sprintf("assigning message id %d/d%q to parent message id %d/%q which has threadid 0", m.ID, m.MessageID, pm.ID, pm.MessageID))
	}
	if m.ID == pm.ID {
		panic(fmt.Sprintf("trying to make message id %d/%q its own parent", m.ID, m.MessageID))
	}
	m.ThreadID = pm.ThreadID
	// Make sure we don't add cycles.
	if !slices.Contains(pm.ThreadParentIDs, m.ID) {
		m.ThreadParentIDs = append([]int64{pm.ID}, pm.ThreadParentIDs...)
	} else if pm.ID != m.ID {
		m.ThreadParentIDs = []int64{pm.ID}
	} else {
		m.ThreadParentIDs = nil
	}
	if m.MessageID != "" && m.MessageID == pm.MessageID {
		m.ThreadMissingLink = true
	}
	m.ThreadMuted = pm.ThreadMuted
	m.ThreadCollapsed = pm.ThreadCollapsed
	if updateSeen && m.ThreadMuted {
		m.Seen = true
	}
}

// ResetThreading resets the MessageID and SubjectBase fields for all messages in
// the account. If clearIDs is true, all Thread* fields are also cleared. Changes
// are made in transactions of batchSize changes. The total number of updated
// messages is returned.
//
// ModSeq is not changed. Calles should bump the uid validity of the mailboxes
// to propagate the changes to IMAP clients.
func (a *Account) ResetThreading(ctx context.Context, log *mlog.Log, batchSize int, clearIDs bool) (int, error) {
	// todo: should this send Change events for ThreadMuted and ThreadCollapsed? worth it?

	var lastID int64
	total := 0
	for {
		n := 0

		prepareMessages := func(in, out chan moxio.Work[Message, Message]) {
			for {
				w, ok := <-in
				if !ok {
					return
				}

				m := w.In

				// We have the Message-ID and Subject headers in ParsedBuf. We use a partial part
				// struct so we don't generate so much garbage for the garbage collector to sift
				// through.
				var part struct {
					Envelope *message.Envelope
				}
				if err := json.Unmarshal(m.ParsedBuf, &part); err != nil {
					log.Errorx("unmarshal json parsedbuf for setting message-id, skipping", err, mlog.Field("msgid", m.ID))
				} else {
					m.MessageID = ""
					if part.Envelope != nil && part.Envelope.MessageID != "" {
						s, _, err := message.MessageIDCanonical(part.Envelope.MessageID)
						if err != nil {
							log.Debugx("parsing message-id, skipping", err, mlog.Field("msgid", m.ID), mlog.Field("messageid", part.Envelope.MessageID))
						}
						m.MessageID = s
					}
					if part.Envelope != nil {
						m.SubjectBase, _ = message.ThreadSubject(part.Envelope.Subject, false)
					}
				}
				w.Out = m

				out <- w
			}
		}

		err := a.DB.Write(ctx, func(tx *bstore.Tx) error {
			processMessage := func(in, m Message) error {
				if clearIDs {
					m.ThreadID = 0
					m.ThreadParentIDs = nil
					m.ThreadMissingLink = false
				}
				return tx.Update(&m)
			}

			// JSON parsing is relatively heavy, we benefit from multiple goroutines.
			procs := runtime.GOMAXPROCS(0)
			wq := moxio.NewWorkQueue[Message, Message](procs, 2*procs, prepareMessages, processMessage)

			q := bstore.QueryTx[Message](tx)
			q.FilterEqual("Expunged", false)
			q.FilterGreater("ID", lastID)
			q.SortAsc("ID")
			err := q.ForEach(func(m Message) error {
				// We process in batches so we don't block other operations for a long time.
				if n >= batchSize {
					return bstore.StopForEach
				}
				// Update starting point for next batch.
				lastID = m.ID

				n++
				return wq.Add(m)
			})
			if err == nil {
				err = wq.Finish()
			}
			wq.Stop()
			return err
		})
		if err != nil {
			return total, fmt.Errorf("upgrading account to threads storage, step 1/2: %w", err)
		}
		total += n
		if n == 0 {
			break
		}
	}
	return total, nil
}

// AssignThreads assigns thread-related fields to messages with ID >=
// startMessageID. Changes are committed each batchSize changes if txOpt is nil
// (i.e. during automatic account upgrade, we don't want to block database access
// for a long time). If txOpt is not nil, all changes are made in that
// transaction.
//
// When resetting thread assignments, the caller must first clear the existing
// thread fields.
//
// Messages are processed in order of ID, so when added to the account, not
// necessarily by received/date. Most threaded messages can immediately be matched
// to their parent message. If not, we keep track of the missing message-id and
// resolve as soon as we encounter it. At the end, we resolve all remaining
// messages, they start with a cycle.
//
// Does not set Seen flag for muted threads.
//
// Progress is written to progressWriter, every 100k messages.
func (a *Account) AssignThreads(ctx context.Context, log *mlog.Log, txOpt *bstore.Tx, startMessageID int64, batchSize int, progressWriter io.Writer) error {
	// We use a more basic version of the thread-matching algorithm describe in:
	// ../rfc/5256:443
	// The algorithm assumes you'll select messages, then group into threads. We normally do
	// thread-calculation when messages are delivered. Here, we assign threads as soon
	// as we can, but will queue messages that reference known ancestors and resolve as
	// soon as we process them. We can handle large number of messages, but not very
	// quickly because we make lots of database queries.

	type childMsg struct {
		ID                int64  // This message will be fetched and updated with the threading fields once the parent is resolved.
		MessageID         string // Of child message. Once child is resolved, its own children can be resolved too.
		ThreadMissingLink bool
	}
	// Messages that have a References/In-Reply-To that we want to set as parent, but
	// where the parent doesn't have a ThreadID yet are added to pending. The key is
	// the normalized MessageID of the parent, and the value is a list of messages that
	// can get resolved once the parent gets its ThreadID. The kids will get the same
	// ThreadIDs, and they themselves may be parents to kids, and so on.
	// For duplicate messages (messages with identical Message-ID), the second
	// Message-ID to be added to pending is added under its own message-id, so it gets
	// its original as parent.
	pending := map[string][]childMsg{}

	// Current tx. If not equal to txOpt, we clean it up before we leave.
	var tx *bstore.Tx
	defer func() {
		if tx != nil && tx != txOpt {
			err := tx.Rollback()
			log.Check(err, "rolling back transaction")
		}
	}()

	// Set thread-related fields for a single message. Caller must save the message,
	// only if not an error and not added to the pending list.
	assign := func(m *Message, references, inReplyTo []string, subject string) (pend bool, rerr error) {
		if m.MessageID != "" {
			// Attempt to match against existing different message with same Message-ID that
			// already has a threadid.
			// If there are multiple messages for a message-id a future call to assign may use
			// its threadid, or it may end up in pending and we resolve it when we need to.
			q := bstore.QueryTx[Message](tx)
			q.FilterNonzero(Message{MessageID: m.MessageID})
			q.FilterEqual("Expunged", false)
			q.FilterLess("ID", m.ID)
			q.SortAsc("ID")
			q.Limit(1)
			em, err := q.Get()
			if err != nil && err != bstore.ErrAbsent {
				return false, fmt.Errorf("looking up existing message with message-id: %v", err)
			} else if err == nil {
				if em.ThreadID == 0 {
					pending[em.MessageID] = append(pending[em.MessageID], childMsg{m.ID, m.MessageID, true})
					return true, nil
				} else {
					assignParent(m, em, false)
					return false, nil
				}
			}
		}

		refids, err := message.ReferencedIDs(references, inReplyTo)
		if err != nil {
			log.Errorx("assigning threads: parsing references/in-reply-to headers, not matching by message-id", err, mlog.Field("msgid", m.ID))
		}

		for i := len(refids) - 1; i >= 0; i-- {
			messageID := refids[i]
			if messageID == m.MessageID {
				continue
			}
			tm, exists, err := lookupThreadMessage(tx, m.ID, messageID, m.SubjectBase)
			if err != nil {
				return false, fmt.Errorf("lookup up thread by message-id %s for message id %d: %w", messageID, m.ID, err)
			} else if tm != nil {
				assignParent(m, *tm, false)
				return false, nil
			} else if exists {
				pending[messageID] = append(pending[messageID], childMsg{m.ID, m.MessageID, i < len(refids)-1})
				return true, nil
			}
		}

		var subjectBase string
		var isResp bool
		if subject != "" {
			subjectBase, isResp = message.ThreadSubject(subject, false)
		}
		if len(refids) > 0 || !isResp || subjectBase == "" {
			m.ThreadID = m.ID
			m.ThreadMissingLink = len(refids) > 0
			return false, nil
		}

		// No references to use. If this is a reply/forward (based on subject), we'll match
		// against base subject, at most 4 weeks back so we don't match against ancient
		// messages and 1 day ahead so we can match against delayed deliveries.
		tm, err := lookupThreadMessageSubject(tx, *m, subjectBase)
		if err != nil {
			return false, fmt.Errorf("looking up recent messages by base subject %q: %w", subjectBase, err)
		} else if tm != nil {
			m.ThreadID = tm.ThreadID
			m.ThreadParentIDs = []int64{tm.ThreadID} // Always under root message with subject-match.
			m.ThreadMissingLink = true
			m.ThreadMuted = tm.ThreadMuted
			m.ThreadCollapsed = tm.ThreadCollapsed
		} else {
			m.ThreadID = m.ID
		}
		return false, nil
	}

	npendingResolved := 0

	// Resolve pending messages that wait on m.MessageID to be resolved, recursively.
	var resolvePending func(tm Message, cyclic bool) error
	resolvePending = func(tm Message, cyclic bool) error {
		if tm.MessageID == "" {
			return nil
		}
		l := pending[tm.MessageID]
		delete(pending, tm.MessageID)
		for _, mi := range l {
			m := Message{ID: mi.ID}
			if err := tx.Get(&m); err != nil {
				return fmt.Errorf("get message %d for resolving pending thread for message-id %s, %d: %w", mi.ID, tm.MessageID, tm.ID, err)
			}
			if m.ThreadID != 0 {
				// ThreadID already set because this is a cyclic message. If we would assign a
				// parent again, we would create a cycle.
				if m.MessageID != tm.MessageID && !cyclic {
					panic(fmt.Sprintf("threadid already set (%d) while handling non-cyclic message id %d/%q and with different message-id %q as parent message id %d", m.ThreadID, m.ID, m.MessageID, tm.MessageID, tm.ID))
				}
				continue
			}
			assignParent(&m, tm, false)
			m.ThreadMissingLink = mi.ThreadMissingLink
			if err := tx.Update(&m); err != nil {
				return fmt.Errorf("update message %d for resolving pending thread for message-id %s, %d: %w", mi.ID, tm.MessageID, tm.ID, err)
			}
			if err := resolvePending(m, cyclic); err != nil {
				return err
			}
			npendingResolved++
		}
		return nil
	}

	// Output of the worker goroutines.
	type threadPrep struct {
		references []string
		inReplyTo  []string
		subject    string
	}

	// Single allocation.
	threadingFields := [][]byte{
		[]byte("references"),
		[]byte("in-reply-to"),
		[]byte("subject"),
	}

	// Worker goroutine function. We start with a reasonably large buffer for reading
	// the header into. And we have scratch space to copy the needed headers into. That
	// means we normally won't allocate any more buffers.
	prepareMessages := func(in, out chan moxio.Work[Message, threadPrep]) {
		headerbuf := make([]byte, 8*1024)
		scratch := make([]byte, 4*1024)
		for {
			w, ok := <-in
			if !ok {
				return
			}

			m := w.In
			var partialPart struct {
				HeaderOffset int64
				BodyOffset   int64
			}
			if err := json.Unmarshal(m.ParsedBuf, &partialPart); err != nil {
				w.Err = fmt.Errorf("unmarshal part: %v", err)
			} else {
				size := partialPart.BodyOffset - partialPart.HeaderOffset
				if int(size) > len(headerbuf) {
					headerbuf = make([]byte, size)
				}
				if size > 0 {
					buf := headerbuf[:int(size)]
					err := func() error {
						mr := a.MessageReader(m)
						defer mr.Close()

						// ReadAt returns whole buffer or error. Single read should be fast.
						n, err := mr.ReadAt(buf, partialPart.HeaderOffset)
						if err != nil || n != len(buf) {
							return fmt.Errorf("read header: %v", err)
						}
						return nil
					}()
					if err != nil {
						w.Err = err
					} else if h, err := message.ParseHeaderFields(buf, scratch, threadingFields); err != nil {
						w.Err = err
					} else {
						w.Out.references = h["References"]
						w.Out.inReplyTo = h["In-Reply-To"]
						l := h["Subject"]
						if len(l) > 0 {
							w.Out.subject = l[0]
						}
					}
				}
			}

			out <- w
		}
	}

	// Assign threads to messages, possibly in batches.
	nassigned := 0
	for {
		n := 0
		tx = txOpt
		if tx == nil {
			var err error
			tx, err = a.DB.Begin(ctx, true)
			if err != nil {
				return fmt.Errorf("begin transaction: %w", err)
			}
		}

		processMessage := func(m Message, prep threadPrep) error {
			pend, err := assign(&m, prep.references, prep.inReplyTo, prep.subject)
			if err != nil {
				return fmt.Errorf("for msgid %d: %w", m.ID, err)
			} else if pend {
				return nil
			}
			if m.ThreadID == 0 {
				panic(fmt.Sprintf("no threadid after assign of message id %d/%q", m.ID, m.MessageID))
			}
			// Fields have been set, store in database and resolve messages waiting for this MessageID.
			if slices.Contains(m.ThreadParentIDs, m.ID) {
				panic(fmt.Sprintf("message id %d/%q contains itself in parent ids %v", m.ID, m.MessageID, m.ThreadParentIDs))
			}
			if err := tx.Update(&m); err != nil {
				return err
			}
			if err := resolvePending(m, false); err != nil {
				return fmt.Errorf("resolving pending message-id: %v", err)
			}
			return nil
		}

		// Use multiple worker goroutines to read parse headers from on-disk messages.
		procs := runtime.GOMAXPROCS(0)
		wq := moxio.NewWorkQueue[Message, threadPrep](2*procs, 4*procs, prepareMessages, processMessage)

		// We assign threads in order by ID, so messages delivered in between our
		// transaction will get assigned threads too: they'll have the highest id's.
		q := bstore.QueryTx[Message](tx)
		q.FilterGreaterEqual("ID", startMessageID)
		q.FilterEqual("Expunged", false)
		q.SortAsc("ID")
		err := q.ForEach(func(m Message) error {
			// Batch number of changes, so we give other users of account a change to run.
			if txOpt == nil && n >= batchSize {
				return bstore.StopForEach
			}
			// Starting point for next batch.
			startMessageID = m.ID + 1
			// Don't process again. Can happen when earlier upgrade was aborted.
			if m.ThreadID != 0 {
				return nil
			}

			n++
			return wq.Add(m)
		})
		if err == nil {
			err = wq.Finish()
		}
		wq.Stop()

		if err == nil && txOpt == nil {
			err = tx.Commit()
			tx = nil
		}
		if err != nil {
			return fmt.Errorf("assigning threads: %w", err)
		}
		if n == 0 {
			break
		}
		nassigned += n
		if nassigned%100000 == 0 {
			log.Debug("assigning threads, progress", mlog.Field("count", nassigned), mlog.Field("unresolved", len(pending)))
			if _, err := fmt.Fprintf(progressWriter, "assigning threads, progress: %d messages\n", nassigned); err != nil {
				return fmt.Errorf("writing progress: %v", err)
			}
		}
	}
	if _, err := fmt.Fprintf(progressWriter, "assigning threads, done: %d messages\n", nassigned); err != nil {
		return fmt.Errorf("writing progress: %v", err)
	}

	log.Debug("assigning threads, mostly done, finishing with resolving of cyclic messages", mlog.Field("count", nassigned), mlog.Field("unresolved", len(pending)))

	if _, err := fmt.Fprintf(progressWriter, "assigning threads, resolving %d cyclic pending message-ids\n", len(pending)); err != nil {
		return fmt.Errorf("writing progress: %v", err)
	}

	// Remaining messages in pending have cycles and possibly tails. The cycle is at
	// the head of the thread. Once we resolve that, the rest of the thread can be
	// resolved too. Ignoring self-references (duplicate messages), there can only be
	// one cycle, and it is at the head. So we look for cycles, ignoring
	// self-references, and resolve a message as soon as we see the cycle.

	parent := map[string]string{} // Child Message-ID pointing to the parent Message-ID, excluding self-references.
	pendlist := []string{}
	for pmsgid, l := range pending {
		pendlist = append(pendlist, pmsgid)
		for _, k := range l {
			if k.MessageID == pmsgid {
				// No self-references for duplicate messages.
				continue
			}
			if _, ok := parent[k.MessageID]; !ok {
				parent[k.MessageID] = pmsgid
			}
			// else, this message should be resolved by following pending.
		}
	}
	sort.Strings(pendlist)

	tx = txOpt
	if tx == nil {
		var err error
		tx, err = a.DB.Begin(ctx, true)
		if err != nil {
			return fmt.Errorf("begin transaction: %w", err)
		}
	}

	// We walk through all messages of pendlist, but some will already have been
	// resolved by the time we get to them.
	done := map[string]bool{}
	for _, msgid := range pendlist {
		if done[msgid] {
			continue
		}

		// We walk up to parent, until we see a message-id we've already seen, a cycle.
		seen := map[string]bool{}
		for {
			pmsgid, ok := parent[msgid]
			if !ok {
				panic(fmt.Sprintf("missing parent message-id %q, not a cycle?", msgid))
			}
			if !seen[pmsgid] {
				seen[pmsgid] = true
				msgid = pmsgid
				continue
			}

			// Cycle detected. Make this message-id the thread root.
			q := bstore.QueryTx[Message](tx)
			q.FilterNonzero(Message{MessageID: msgid})
			q.FilterEqual("ThreadID", int64(0))
			q.FilterEqual("Expunged", false)
			q.SortAsc("ID")
			l, err := q.List()
			if err == nil && len(l) == 0 {
				err = errors.New("no messages")
			}
			if err != nil {
				return fmt.Errorf("list message by message-id for cyclic thread root: %v", err)
			}
			for i, m := range l {
				m.ThreadID = l[0].ID
				m.ThreadMissingLink = true
				if i == 0 {
					m.ThreadParentIDs = nil
					l[0] = m // For resolvePending below.
				} else {
					assignParent(&m, l[0], false)
				}
				if slices.Contains(m.ThreadParentIDs, m.ID) {
					panic(fmt.Sprintf("message id %d/%q contains itself in parents %v", m.ID, m.MessageID, m.ThreadParentIDs))
				}
				if err := tx.Update(&m); err != nil {
					return fmt.Errorf("assigning threadid to cyclic thread root: %v", err)
				}
			}

			// Mark all children as done so we don't process these messages again.
			walk := map[string]struct{}{msgid: {}}
			for len(walk) > 0 {
				for msgid := range walk {
					delete(walk, msgid)
					if done[msgid] {
						continue
					}
					done[msgid] = true
					for _, mi := range pending[msgid] {
						if !done[mi.MessageID] {
							walk[mi.MessageID] = struct{}{}
						}
					}
				}
			}

			// Resolve all messages in this thread.
			if err := resolvePending(l[0], true); err != nil {
				return fmt.Errorf("resolving cyclic children of cyclic thread root: %v", err)
			}

			break
		}
	}

	// Check that there are no more messages without threadid.
	q := bstore.QueryTx[Message](tx)
	q.FilterEqual("ThreadID", int64(0))
	q.FilterEqual("Expunged", false)
	l, err := q.List()
	if err == nil && len(l) > 0 {
		err = errors.New("found messages without threadid")
	}
	if err != nil {
		return fmt.Errorf("listing messages without threadid: %v", err)
	}

	if txOpt == nil {
		err := tx.Commit()
		tx = nil
		if err != nil {
			return fmt.Errorf("commit resolving cyclic thread roots: %v", err)
		}
	}
	return nil
}

// lookupThreadMessage tries to find the parent message with messageID that must
// have a matching subjectBase.
//
// If the message isn't present (with a valid thread id), a nil message and nil
// error is returned. The bool return value indicates if a message with the
// message-id exists at all.
func lookupThreadMessage(tx *bstore.Tx, mID int64, messageID, subjectBase string) (*Message, bool, error) {
	q := bstore.QueryTx[Message](tx)
	q.FilterNonzero(Message{MessageID: messageID})
	q.FilterEqual("SubjectBase", subjectBase)
	q.FilterEqual("Expunged", false)
	q.FilterNotEqual("ID", mID)
	q.SortAsc("ID")
	l, err := q.List()
	if err != nil {
		return nil, false, fmt.Errorf("message-id %s: %w", messageID, err)
	}
	exists := len(l) > 0
	for _, tm := range l {
		if tm.ThreadID != 0 {
			return &tm, true, nil
		}
	}
	return nil, exists, nil
}

// lookupThreadMessageSubject looks up a parent/ancestor message for the message
// thread based on a matching subject. The message must have been delivered to the same mailbox originally.
//
// If no message (with a threadid) is found a nil message and nil error is returned.
func lookupThreadMessageSubject(tx *bstore.Tx, m Message, subjectBase string) (*Message, error) {
	q := bstore.QueryTx[Message](tx)
	q.FilterGreater("Received", m.Received.Add(-4*7*24*time.Hour))
	q.FilterLess("Received", m.Received.Add(1*24*time.Hour))
	q.FilterNonzero(Message{SubjectBase: subjectBase, MailboxOrigID: m.MailboxOrigID})
	q.FilterEqual("Expunged", false)
	q.FilterNotEqual("ID", m.ID)
	q.FilterNotEqual("ThreadID", int64(0))
	q.SortDesc("Received")
	q.Limit(1)
	tm, err := q.Get()
	if err == bstore.ErrAbsent {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &tm, nil
}

func upgradeThreads(ctx context.Context, acc *Account, up *Upgrade) error {
	log := xlog.Fields(mlog.Field("account", acc.Name))

	if up.Threads == 0 {
		// Step 1 in the threads upgrade is storing the canonicalized Message-ID for each
		// message and the base subject for thread matching. This allows efficient thread
		// lookup in the second step.

		log.Info("upgrading account for threading, step 1/2: updating all messages with message-id and base subject")
		t0 := time.Now()

		const batchSize = 10000
		total, err := acc.ResetThreading(ctx, log, batchSize, true)
		if err != nil {
			return fmt.Errorf("resetting message threading fields: %v", err)
		}

		up.Threads = 1
		if err := acc.DB.Update(ctx, up); err != nil {
			up.Threads = 0
			return fmt.Errorf("saving upgrade process while upgrading account to threads storage, step 1/2: %w", err)
		}
		log.Info("upgrading account for threading, step 1/2: completed", mlog.Field("duration", time.Since(t0)), mlog.Field("messages", total))
	}

	if up.Threads == 1 {
		// Step 2 of the upgrade is going through all messages and assigning threadid's.
		// Lookup of messageid and base subject is now fast through indexed database
		// access.

		log.Info("upgrading account for threading, step 2/2: matching messages to threads")
		t0 := time.Now()

		const batchSize = 10000
		if err := acc.AssignThreads(ctx, log, nil, 1, batchSize, io.Discard); err != nil {
			return fmt.Errorf("upgrading to threads storage, step 2/2: %w", err)
		}
		up.Threads = 2
		if err := acc.DB.Update(ctx, up); err != nil {
			up.Threads = 1
			return fmt.Errorf("saving upgrade process for thread storage, step 2/2: %w", err)
		}
		log.Info("upgrading account for threading, step 2/2: completed", mlog.Field("duration", time.Since(t0)))
	}

	// Note: Not bumping uidvalidity or setting modseq. Clients haven't been able to
	// use threadid's before, so there is nothing to be out of date.

	return nil
}
