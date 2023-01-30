package store

import (
	"sync/atomic"
)

var (
	register   = make(chan *Comm)
	unregister = make(chan *Comm)
	broadcast  = make(chan changeReq)
	get        = make(chan *Comm)
)

type changeReq struct {
	comm    *Comm
	changes []Change
}

type UID uint32 // IMAP UID.

// Change to mailboxes/subscriptions/messages in an account. One of the Change*
// types in this package.
type Change any

// ChangeAddUID is sent for a new message in a mailbox.
type ChangeAddUID struct {
	MailboxID int64
	UID       UID
	Flags     Flags
}

// ChangeRemoveUIDs is sent for removal of one or more messages from a mailbox.
type ChangeRemoveUIDs struct {
	MailboxID int64
	UIDs      []UID
}

// ChangeFlags is sent for an update to flags for a message, e.g. "Seen".
type ChangeFlags struct {
	MailboxID int64
	UID       UID
	Mask      Flags // Which flags are actually modified.
	Flags     Flags // New flag values. All are set, not just mask.
}

// ChangeRemoveMailbox is sent for a removed mailbox.
type ChangeRemoveMailbox struct {
	Name string
}

// ChangeAddMailbox is sent for a newly created mailbox.
type ChangeAddMailbox struct {
	Name  string
	Flags []string
}

// ChangeRenameMailbox is sent for a rename mailbox.
type ChangeRenameMailbox struct {
	OldName string
	NewName string
	Flags   []string
}

// ChangeAddSubscription is sent for an added subscription to a mailbox.
type ChangeAddSubscription struct {
	Name string
}

var switchboardBusy atomic.Bool

// Switchboard distributes changes to accounts to interested listeners. See Comm and Change.
func Switchboard() chan struct{} {
	regs := map[*Account]map[*Comm][]Change{}
	done := make(chan struct{})

	if !switchboardBusy.CompareAndSwap(false, true) {
		panic("switchboard already busy")
	}

	go func() {
		for {
			select {
			case c := <-register:
				if _, ok := regs[c.acc]; !ok {
					regs[c.acc] = map[*Comm][]Change{}
				}
				regs[c.acc][c] = nil
			case c := <-unregister:
				delete(regs[c.acc], c)
				if len(regs[c.acc]) == 0 {
					delete(regs, c.acc)
				}
			case chReq := <-broadcast:
				acc := chReq.comm.acc
				for c, changes := range regs[acc] {
					// Do not send the broadcaster back their own changes.
					if c == chReq.comm {
						continue
					}
					regs[acc][c] = append(changes, chReq.changes...)
					select {
					case c.Changes <- regs[acc][c]:
						regs[acc][c] = nil
					default:
					}
				}
				chReq.comm.r <- struct{}{}
			case c := <-get:
				c.Changes <- regs[c.acc][c]
				regs[c.acc][c] = nil
			case <-done:
				if !switchboardBusy.CompareAndSwap(true, false) {
					panic("switchboard already unregistered?")
				}
				return
			}
		}
	}()
	return done
}

// Comm handles communication with the goroutine that maintains the
// account/mailbox/message state.
type Comm struct {
	Changes chan []Change // Receives block until changes come in, e.g. for IMAP IDLE.
	acc     *Account
	r       chan struct{}
}

// Register starts a Comm for the account. Unregister must be called.
func RegisterComm(acc *Account) *Comm {
	c := &Comm{make(chan []Change), acc, make(chan struct{})}
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
	broadcast <- changeReq{c, ch}
	<-c.r
}

// Get retrieves pending changes. If no changes are pending a nil or empty list
// is returned.
func (c *Comm) Get() []Change {
	get <- c
	changes := <-c.Changes
	return changes
}
