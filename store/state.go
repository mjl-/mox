package store

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var (
	register   = make(chan *Comm)
	unregister = make(chan *Comm)
	broadcast  = make(chan changeReq)
	applied    = make(chan removalApplied)
)

type changeReq struct {
	acc     *Account
	comm    *Comm // Can be nil.
	changes []Change
	done    chan struct{}
}

type removalApplied struct {
	Account *Account
	MsgIDs  []int64
}

type UID uint32 // IMAP UID.

// Change to mailboxes/subscriptions/messages in an account. One of the Change*
// types in this package.
type Change any

// ChangeAddUID is sent for a new message in a mailbox.
type ChangeAddUID struct {
	MailboxID int64
	UID       UID
	ModSeq    ModSeq
	Flags     Flags    // System flags.
	Keywords  []string // Other flags.
}

// ChangeRemoveUIDs is sent for removal of one or more messages from a mailbox.
type ChangeRemoveUIDs struct {
	MailboxID int64
	UIDs      []UID // Must be in increasing UID order, for IMAP.
	ModSeq    ModSeq
	MsgIDs    []int64 // Message.ID, for erasing, order does not necessarily correspond with UIDs!
}

// ChangeFlags is sent for an update to flags for a message, e.g. "Seen".
type ChangeFlags struct {
	MailboxID int64
	UID       UID
	ModSeq    ModSeq
	Mask      Flags    // Which flags are actually modified.
	Flags     Flags    // New flag values. All are set, not just mask.
	Keywords  []string // Non-system/well-known flags/keywords/labels.
}

// ChangeThread is sent when muted/collapsed changes.
type ChangeThread struct {
	MessageIDs []int64
	Muted      bool
	Collapsed  bool
}

// ChangeRemoveMailbox is sent for a removed mailbox.
type ChangeRemoveMailbox struct {
	MailboxID int64
	Name      string
	ModSeq    ModSeq
}

// ChangeAddMailbox is sent for a newly created mailbox.
type ChangeAddMailbox struct {
	Mailbox Mailbox
	Flags   []string // For flags like \Subscribed.
	ModSeq  ModSeq
}

// ChangeRenameMailbox is sent for a rename mailbox.
type ChangeRenameMailbox struct {
	MailboxID int64
	OldName   string
	NewName   string
	Flags     []string
	ModSeq    ModSeq
}

// ChangeAddSubscription is sent for an added subscription to a mailbox.
type ChangeAddSubscription struct {
	Name  string
	Flags []string // For additional IMAP flags like \NonExistent.
}

// ChangeMailboxCounts is sent when the number of total/deleted/unseen/unread messages changes.
type ChangeMailboxCounts struct {
	MailboxID   int64
	MailboxName string
	MailboxCounts
}

// ChangeMailboxSpecialUse is sent when a special-use flag changes.
type ChangeMailboxSpecialUse struct {
	MailboxID   int64
	MailboxName string
	SpecialUse  SpecialUse
	ModSeq      ModSeq
}

// ChangeMailboxKeywords is sent when keywords are changed for a mailbox. For
// example, when a message is added with a previously unseen keyword.
type ChangeMailboxKeywords struct {
	MailboxID   int64
	MailboxName string
	Keywords    []string
}

// ChangeAnnotation is sent when an annotation is added/updated/removed, either for
// a mailbox or a global per-account annotation. The value is not included.
type ChangeAnnotation struct {
	MailboxID   int64  // Can be zero, meaning global (per-account) annotation.
	MailboxName string // Empty for global (per-account) annotation.
	Key         string // Also called "entry name", e.g. "/private/comment".
	ModSeq      ModSeq
}

func messageEraser(donec chan struct{}, cleanc chan map[*Account][]int64) {
	log := mlog.New("store", nil)

	for {
		clean, ok := <-cleanc
		if !ok {
			donec <- struct{}{}
			return
		}

		for acc, ids := range clean {
			eraseMessages(log, acc, ids)
		}
	}
}

func eraseMessages(log mlog.Log, acc *Account, ids []int64) {
	// We are responsible for closing the accounts.
	defer func() {
		err := acc.Close()
		log.Check(err, "close account after erasing expunged messages", slog.String("account", acc.Name))
	}()

	acc.Lock()
	defer acc.Unlock()
	err := acc.DB.Write(mox.Context, func(tx *bstore.Tx) error {
		du := DiskUsage{ID: 1}
		if err := tx.Get(&du); err != nil {
			return fmt.Errorf("get disk usage: %v", err)
		}
		var duchanged bool

		for _, id := range ids {
			me := MessageErase{ID: id}
			if err := tx.Get(&me); err != nil {
				return fmt.Errorf("delete message erase record %d: %v", id, err)
			}

			m := Message{ID: id}
			if err := tx.Get(&m); err != nil {
				return fmt.Errorf("get message %d to erase: %v", id, err)
			} else if !m.Expunged {
				return fmt.Errorf("message %d to erase is not marked expunged", id)
			}
			if !me.SkipUpdateDiskUsage {
				du.MessageSize -= m.Size
				duchanged = true
			}
			m.erase()
			if err := tx.Update(&m); err != nil {
				return fmt.Errorf("mark message %d erase in database: %v", id, err)
			}

			if err := tx.Delete(&me); err != nil {
				return fmt.Errorf("deleting message erase record %d: %v", id, err)
			}
		}

		if duchanged {
			if err := tx.Update(&du); err != nil {
				return fmt.Errorf("update disk usage after erasing: %v", err)
			}
		}

		return nil
	})
	if err != nil {
		log.Errorx("erasing expunged messages", err,
			slog.String("account", acc.Name),
			slog.Any("ids", ids),
		)
		return
	}

	// We remove the files after the database commit. It's better to have the files
	// still around without being referenced from the database than references in the
	// database to non-existent files.
	for _, id := range ids {
		p := acc.MessagePath(id)
		err := os.Remove(p)
		log.Check(err, "removing expunged message file from disk", slog.String("path", p))
	}
}

func switchboard(stopc, donec chan struct{}, cleanc chan map[*Account][]int64) {
	regs := map[*Account]map[*Comm]struct{}{}

	// We don't remove message files or clear fields in the Message stored in the
	// database until all references, from all sessions have gone away. When we see
	// an expunge of a message, we count how many comms are active (i.e. how many
	// sessions reference the message). We require each of them to tell us they are no
	// longer referencing that message. Once we've seen that from all Comms, we remove
	// the on-disk file and the fields from the database.
	//
	// During the initial account open (when there are no active sessions/Comms yet,
	// and we open the message database file), the message erases will also be applied.
	//
	// When we add an account to eraseRefs, we increase the refcount, and we decrease
	// it again when removing the account.
	eraseRefs := map[*Account]map[int64]int{}

	// We collect which messages can be erased per account, for sending them off to the
	// eraser goroutine. When an account is added to this map, its refcount is
	// increased. It is decreased again by the eraser goroutine.
	eraseIDs := map[*Account][]int64{}

	addEraseIDs := func(acc *Account, ids ...int64) {
		if _, ok := eraseIDs[acc]; !ok {
			openAccounts.Lock()
			acc.nused++
			openAccounts.Unlock()
		}
		eraseIDs[acc] = append(eraseIDs[acc], ids...)
	}

	decreaseEraseRefs := func(acc *Account, ids ...int64) {
		for _, id := range ids {
			v := eraseRefs[acc][id] - 1
			if v < 0 {
				metrics.PanicInc(metrics.Store) // For tests.
				panic(fmt.Sprintf("negative expunged message references for account %q, message id %d", acc.Name, id))
			}
			if v > 0 {
				eraseRefs[acc][id] = v
				continue
			}

			addEraseIDs(acc, id)
			delete(eraseRefs[acc], id)
			if len(eraseRefs[acc]) > 0 {
				continue
			}
			delete(eraseRefs, acc)
			// Note: cannot use acc.Close, it tries to lock acc, but someone broadcasting to
			// this goroutine will likely have the lock.
			openAccounts.Lock()
			acc.nused--
			n := acc.nused
			openAccounts.Unlock()
			if n < 0 {
				metrics.PanicInc(metrics.Store) // For tests.
				panic(fmt.Sprintf("negative reference count for account %q, after removing message id %d", acc.Name, id))
			}
		}
	}

	for {
		// If we have messages to clean, try sending to the eraser.
		cc := cleanc
		if len(eraseIDs) == 0 {
			cc = nil
		}

		select {
		case cc <- eraseIDs:
			eraseIDs = map[*Account][]int64{}

		case c := <-register:
			if _, ok := regs[c.acc]; !ok {
				regs[c.acc] = map[*Comm]struct{}{}
			}
			regs[c.acc][c] = struct{}{}

		case c := <-unregister:
			// Drain any ChangeRemoveUIDs references from the comm, to update our eraseRefs and
			// possibly queue messages for cleaning. No need to take a lock, the caller does
			// not use the comm anymore.
			for _, ch := range c.changes {
				rem, ok := ch.(ChangeRemoveUIDs)
				if !ok {
					continue
				}
				decreaseEraseRefs(c.acc, rem.MsgIDs...)
			}

			delete(regs[c.acc], c)
			if len(regs[c.acc]) == 0 {
				delete(regs, c.acc)
			}

		case chReq := <-broadcast:
			acc := chReq.acc

			// Track references to removed messages in sessions (mostly IMAP) so we can pass
			// them to the eraser.
			for _, ch := range chReq.changes {
				rem, ok := ch.(ChangeRemoveUIDs)
				if !ok {
					continue
				}

				refs := len(regs[acc])
				if chReq.comm != nil {
					// The sender does not get this change and doesn't have to notify us of having
					// processed the removal.
					refs--
				}
				if refs <= 0 {
					addEraseIDs(acc, rem.MsgIDs...)
					continue
				}

				// Comms/sessions still reference these messages, track how many.
				for _, id := range rem.MsgIDs {
					if _, ok := eraseRefs[acc]; !ok {
						openAccounts.Lock()
						acc.nused++
						openAccounts.Unlock()

						eraseRefs[acc] = map[int64]int{}
					}
					if _, ok := eraseRefs[acc][id]; ok {
						metrics.PanicInc(metrics.Store) // For tests.
						panic(fmt.Sprintf("already have eraseRef for message id %d, account %q", id, acc.Name))
					}
					eraseRefs[acc][id] = refs
				}
			}

			for c := range regs[acc] {
				// Do not send the broadcaster back their own changes. chReq.comm is nil if not
				// originating from a comm, so won't match in that case.
				if c == chReq.comm {
					continue
				}

				c.Lock()
				c.changes = append(c.changes, chReq.changes...)
				c.Unlock()

				select {
				case c.Pending <- struct{}{}:
				default:
				}
			}
			chReq.done <- struct{}{}

		case removal := <-applied:
			acc := removal.Account

			// Decrease references of messages, queueing for erasure when the last reference
			// goes away.
			decreaseEraseRefs(acc, removal.MsgIDs...)

		case <-stopc:
			// We may still have eraseRefs, messages currently referenced in a session. Those
			// messages will be erased when the database file is opened again in the future. If
			// we have messages ready to erase now, we'll do that first.

			if len(eraseIDs) > 0 {
				cleanc <- eraseIDs
				eraseIDs = nil
			}

			for acc := range eraseRefs {
				err := acc.Close()
				log := mlog.New("store", nil)
				log.Check(err, "closing account")
			}

			close(cleanc)       // Tell eraser to stop.
			donec <- struct{}{} // Say we are now done.
			return
		}
	}
}

var switchboardBusy atomic.Bool

// Switchboard distributes changes to accounts to interested listeners. See Comm and Change.
func Switchboard() (stop func()) {
	if !switchboardBusy.CompareAndSwap(false, true) {
		panic("switchboard already busy")
	}

	stopc := make(chan struct{})
	donec := make(chan struct{})
	cleanc := make(chan map[*Account][]int64)

	go messageEraser(donec, cleanc)
	go switchboard(stopc, donec, cleanc)

	return func() {
		stopc <- struct{}{}

		// Wait for switchboard and eraser goroutines to be ready.
		<-donec
		<-donec

		if !switchboardBusy.CompareAndSwap(true, false) {
			panic("switchboard already unregistered?")
		}
	}
}

// Comm handles communication with the goroutine that maintains the
// account/mailbox/message state.
type Comm struct {
	Pending chan struct{} // Receives block until changes come in, e.g. for IMAP IDLE.

	acc *Account

	sync.Mutex
	changes []Change
}

// Register starts a Comm for the account. Unregister must be called.
func RegisterComm(acc *Account) *Comm {
	c := &Comm{
		Pending: make(chan struct{}, 1), // Bufferend so Switchboard can just do a non-blocking send.
		acc:     acc,
	}
	register <- c
	return c
}

// Unregister stops this Comm.
func (c *Comm) Unregister() {
	unregister <- c
}

// Broadcast ensures changes are sent to other Comms.
func (c *Comm) Broadcast(ch []Change) {
	if len(ch) == 0 {
		return
	}
	done := make(chan struct{}, 1)
	broadcast <- changeReq{c.acc, c, ch, done}
	<-done
}

// Get retrieves all pending changes. If no changes are pending a nil or empty list
// is returned.
func (c *Comm) Get() []Change {
	c.Lock()
	defer c.Unlock()
	l := c.changes
	c.changes = nil
	return l
}

// RemovalSeen must be called by consumers when they have applied the removal to
// their session. The switchboard tracks references of expunged messages, and
// removes/cleans the message up when the last reference is gone.
func (c *Comm) RemovalSeen(ch ChangeRemoveUIDs) {
	applied <- removalApplied{c.acc, ch.MsgIDs}
}

// BroadcastChanges ensures changes are sent to all listeners on the accoount.
func BroadcastChanges(acc *Account, ch []Change) {
	if len(ch) == 0 {
		return
	}
	done := make(chan struct{}, 1)
	broadcast <- changeReq{acc, nil, ch, done}
	<-done
}
