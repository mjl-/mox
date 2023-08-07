package store

import (
	"sync"
	"sync/atomic"
)

var (
	register   = make(chan *Comm)
	unregister = make(chan *Comm)
	broadcast  = make(chan changeReq)
)

type changeReq struct {
	acc     *Account
	comm    *Comm // Can be nil.
	changes []Change
	done    chan struct{}
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

// ChangeRemoveMailbox is sent for a removed mailbox.
type ChangeRemoveMailbox struct {
	MailboxID int64
	Name      string
}

// ChangeAddMailbox is sent for a newly created mailbox.
type ChangeAddMailbox struct {
	Mailbox Mailbox
	Flags   []string // For flags like \Subscribed.
}

// ChangeRenameMailbox is sent for a rename mailbox.
type ChangeRenameMailbox struct {
	MailboxID int64
	OldName   string
	NewName   string
	Flags     []string
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
}

// ChangeMailboxKeywords is sent when keywords are changed for a mailbox. For
// example, when a message is added with a previously unseen keyword.
type ChangeMailboxKeywords struct {
	MailboxID   int64
	MailboxName string
	Keywords    []string
}

var switchboardBusy atomic.Bool

// Switchboard distributes changes to accounts to interested listeners. See Comm and Change.
func Switchboard() (stop func()) {
	regs := map[*Account]map[*Comm]struct{}{}
	done := make(chan struct{})

	if !switchboardBusy.CompareAndSwap(false, true) {
		panic("switchboard already busy")
	}

	go func() {
		for {
			select {
			case c := <-register:
				if _, ok := regs[c.acc]; !ok {
					regs[c.acc] = map[*Comm]struct{}{}
				}
				regs[c.acc][c] = struct{}{}

			case c := <-unregister:
				delete(regs[c.acc], c)
				if len(regs[c.acc]) == 0 {
					delete(regs, c.acc)
				}

			case chReq := <-broadcast:
				acc := chReq.acc
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

			case <-done:
				done <- struct{}{}
				return
			}
		}
	}()
	return func() {
		done <- struct{}{}
		<-done
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

// BroadcastChanges ensures changes are sent to all listeners on the accoount.
func BroadcastChanges(acc *Account, ch []Change) {
	if len(ch) == 0 {
		return
	}
	done := make(chan struct{}, 1)
	broadcast <- changeReq{acc, nil, ch, done}
	<-done
}
