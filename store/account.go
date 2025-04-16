/*
Package store implements storage for accounts, their mailboxes, IMAP
subscriptions and messages, and broadcasts updates (e.g. mail delivery) to
interested sessions (e.g. IMAP connections).

Layout of storage for accounts:

	<DataDir>/accounts/<name>/index.db
	<DataDir>/accounts/<name>/msg/[a-zA-Z0-9_-]+/<id>

Index.db holds tables for user information, mailboxes, and messages. Message contents
are stored in the msg/ subdirectory, each in their own file. The on-disk message
does not contain headers generated during an incoming SMTP transaction, such as
Received and Authentication-Results headers. Those are in the database to
prevent having to rewrite incoming messages (e.g. Authentication-Result for DKIM
signatures can only be determined after having read the message). Messages must
be read through MsgReader, which transparently adds the prefix from the
database.
*/
package store

// todo: make up a function naming scheme that indicates whether caller should broadcast changes.

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/secure/precis"
	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
)

// If true, each time an account is closed its database file is checked for
// consistency. If an inconsistency is found, panic is called. Set by default
// because of all the packages with tests, the mox main function sets it to
// false again.
var CheckConsistencyOnClose = true

var (
	ErrUnknownMailbox     = errors.New("no such mailbox")
	ErrUnknownCredentials = errors.New("credentials not found")
	ErrAccountUnknown     = errors.New("no such account")
	ErrOverQuota          = errors.New("account over quota")
	ErrLoginDisabled      = errors.New("login disabled for account")
)

var DefaultInitialMailboxes = config.InitialMailboxes{
	SpecialUse: config.SpecialUseMailboxes{
		Sent:    "Sent",
		Archive: "Archive",
		Trash:   "Trash",
		Draft:   "Drafts",
		Junk:    "Junk",
	},
}

type SCRAM struct {
	Salt           []byte
	Iterations     int
	SaltedPassword []byte
}

// CRAMMD5 holds HMAC ipad and opad hashes that are initialized with the first
// block with (a derivation of) the key/password, so we don't store the password in plain
// text.
type CRAMMD5 struct {
	Ipad hash.Hash
	Opad hash.Hash
}

// BinaryMarshal is used by bstore to store the ipad/opad hash states.
func (c CRAMMD5) MarshalBinary() ([]byte, error) {
	if c.Ipad == nil || c.Opad == nil {
		return nil, nil
	}

	ipad, err := c.Ipad.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal ipad: %v", err)
	}
	opad, err := c.Opad.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal opad: %v", err)
	}
	buf := make([]byte, 2+len(ipad)+len(opad))
	ipadlen := uint16(len(ipad))
	buf[0] = byte(ipadlen >> 8)
	buf[1] = byte(ipadlen >> 0)
	copy(buf[2:], ipad)
	copy(buf[2+len(ipad):], opad)
	return buf, nil
}

// BinaryUnmarshal is used by bstore to restore the ipad/opad hash states.
func (c *CRAMMD5) UnmarshalBinary(buf []byte) error {
	if len(buf) == 0 {
		*c = CRAMMD5{}
		return nil
	}
	if len(buf) < 2 {
		return fmt.Errorf("short buffer")
	}
	ipadlen := int(uint16(buf[0])<<8 | uint16(buf[1])<<0)
	if len(buf) < 2+ipadlen {
		return fmt.Errorf("buffer too short for ipadlen")
	}
	ipad := md5.New()
	opad := md5.New()
	if err := ipad.(encoding.BinaryUnmarshaler).UnmarshalBinary(buf[2 : 2+ipadlen]); err != nil {
		return fmt.Errorf("unmarshal ipad: %v", err)
	}
	if err := opad.(encoding.BinaryUnmarshaler).UnmarshalBinary(buf[2+ipadlen:]); err != nil {
		return fmt.Errorf("unmarshal opad: %v", err)
	}
	*c = CRAMMD5{ipad, opad}
	return nil
}

// Password holds credentials in various forms, for logging in with SMTP/IMAP.
type Password struct {
	Hash        string  // bcrypt hash for IMAP LOGIN, SASL PLAIN and HTTP basic authentication.
	CRAMMD5     CRAMMD5 // For SASL CRAM-MD5.
	SCRAMSHA1   SCRAM   // For SASL SCRAM-SHA-1.
	SCRAMSHA256 SCRAM   // For SASL SCRAM-SHA-256.
}

// Subjectpass holds the secret key used to sign subjectpass tokens.
type Subjectpass struct {
	Email string // Our destination address (canonical, with catchall localpart stripped).
	Key   string
}

// NextUIDValidity is a singleton record in the database with the next UIDValidity
// to use for the next mailbox.
type NextUIDValidity struct {
	ID   int // Just a single record with ID 1.
	Next uint32
}

// SyncState track ModSeqs.
type SyncState struct {
	ID int // Just a single record with ID 1.

	// Last used, next assigned will be one higher. The first value we hand out is 2.
	// That's because 0 (the default value for old existing messages, from before the
	// Message.ModSeq field) is special in IMAP, so we return it as 1.
	LastModSeq ModSeq `bstore:"nonzero"`

	// Highest ModSeq of expunged record that we deleted. When a clients synchronizes
	// and requests changes based on a modseq before this one, we don't have the
	// history to provide information about deletions. We normally keep these expunged
	// records around, but we may periodically truly delete them to reclaim storage
	// space. Initially set to -1 because we don't want to match with any ModSeq in the
	// database, which can be zero values.
	HighestDeletedModSeq ModSeq
}

// Mailbox is collection of messages, e.g. Inbox or Sent.
type Mailbox struct {
	ID int64

	CreateSeq ModSeq
	ModSeq    ModSeq `bstore:"index"` // Of last change, or when deleted.
	Expunged  bool

	ParentID int64 `bstore:"ref Mailbox"` // Zero for top-level mailbox.

	// "Inbox" is the name for the special IMAP "INBOX". Slash separated for hierarchy.
	// Names must be unique for mailboxes that are not expunged.
	Name string `bstore:"nonzero"`

	// If UIDs are invalidated, e.g. when renaming a mailbox to a previously existing
	// name, UIDValidity must be changed. Used by IMAP for synchronization.
	UIDValidity uint32

	// UID likely to be assigned to next message. Used by IMAP to detect messages
	// delivered to a mailbox.
	UIDNext UID

	SpecialUse

	// Keywords as used in messages. Storing a non-system keyword for a message
	// automatically adds it to this list. Used in the IMAP FLAGS response. Only
	// "atoms" are allowed (IMAP syntax), keywords are case-insensitive, only stored in
	// lower case (for JMAP), sorted.
	Keywords []string

	HaveCounts    bool // Deprecated. Covered by Upgrade.MailboxCounts. No longer read.
	MailboxCounts      // Statistics about messages, kept up to date whenever a change happens.
}

// Annotation is a per-mailbox or global (per-account) annotation for the IMAP
// metadata extension, currently always a private annotation.
type Annotation struct {
	ID int64

	CreateSeq ModSeq
	ModSeq    ModSeq `bstore:"index"`
	Expunged  bool

	// Can be zero, indicates global (per-account) annotation.
	MailboxID int64 `bstore:"ref Mailbox,index MailboxID+Key"`

	// "Entry name", always starts with "/private/" or "/shared/". Stored lower-case,
	// comparisons must be done case-insensitively.
	Key string `bstore:"nonzero"`

	IsString bool // If true, the value is a string instead of bytes.
	Value    []byte
}

// Change returns a broadcastable change for the annotation.
func (a Annotation) Change(mailboxName string) ChangeAnnotation {
	return ChangeAnnotation{a.MailboxID, mailboxName, a.Key, a.ModSeq}
}

// MailboxCounts tracks statistics about messages for a mailbox.
type MailboxCounts struct {
	Total   int64 // Total number of messages, excluding \Deleted. For JMAP.
	Deleted int64 // Number of messages with \Deleted flag. Used for IMAP message count that includes messages with \Deleted.
	Unread  int64 // Messages without \Seen, excluding those with \Deleted, for JMAP.
	Unseen  int64 // Messages without \Seen, including those with \Deleted, for IMAP.
	Size    int64 // Number of bytes for all messages.
}

// MessageCountIMAP returns the total message count for use in IMAP. In IMAP,
// message marked \Deleted are included, in JMAP they those messages are not
// visible at all.
func (mc MailboxCounts) MessageCountIMAP() uint32 {
	return uint32(mc.Total + mc.Deleted)
}

func (mc MailboxCounts) String() string {
	return fmt.Sprintf("%d total, %d deleted, %d unread, %d unseen, size %d bytes", mc.Total, mc.Deleted, mc.Unread, mc.Unseen, mc.Size)
}

// Add increases mailbox counts mc with those of delta.
func (mc *MailboxCounts) Add(delta MailboxCounts) {
	mc.Total += delta.Total
	mc.Deleted += delta.Deleted
	mc.Unread += delta.Unread
	mc.Unseen += delta.Unseen
	mc.Size += delta.Size
}

// Add decreases mailbox counts mc with those of delta.
func (mc *MailboxCounts) Sub(delta MailboxCounts) {
	mc.Total -= delta.Total
	mc.Deleted -= delta.Deleted
	mc.Unread -= delta.Unread
	mc.Unseen -= delta.Unseen
	mc.Size -= delta.Size
}

// SpecialUse identifies a specific role for a mailbox, used by clients to
// understand where messages should go.
type SpecialUse struct {
	Archive bool
	Draft   bool // "Drafts"
	Junk    bool
	Sent    bool
	Trash   bool
}

// UIDNextAdd increases the UIDNext value by n, returning an error on overflow.
func (mb *Mailbox) UIDNextAdd(n int) error {
	uidnext := mb.UIDNext + UID(n)
	if uidnext < mb.UIDNext {
		return fmt.Errorf("uid overflow on mailbox %q (id %d): uidnext %d, adding %d; consider recreating the mailbox and copying its messages to compact", mb.Name, mb.ID, mb.UIDNext, n)
	}
	mb.UIDNext = uidnext
	return nil
}

// CalculateCounts calculates the full current counts for messages in the mailbox.
func (mb *Mailbox) CalculateCounts(tx *bstore.Tx) (mc MailboxCounts, err error) {
	q := bstore.QueryTx[Message](tx)
	q.FilterNonzero(Message{MailboxID: mb.ID})
	q.FilterEqual("Expunged", false)
	err = q.ForEach(func(m Message) error {
		mc.Add(m.MailboxCounts())
		return nil
	})
	return
}

// ChangeSpecialUse returns a change for special-use flags, for broadcasting to
// other connections.
func (mb Mailbox) ChangeSpecialUse() ChangeMailboxSpecialUse {
	return ChangeMailboxSpecialUse{mb.ID, mb.Name, mb.SpecialUse, mb.ModSeq}
}

// ChangeKeywords returns a change with new keywords for a mailbox (e.g. after
// setting a new keyword on a message in the mailbox), for broadcasting to other
// connections.
func (mb Mailbox) ChangeKeywords() ChangeMailboxKeywords {
	return ChangeMailboxKeywords{mb.ID, mb.Name, mb.Keywords}
}

func (mb Mailbox) ChangeAddMailbox(flags []string) ChangeAddMailbox {
	return ChangeAddMailbox{Mailbox: mb, Flags: flags}
}

func (mb Mailbox) ChangeRemoveMailbox() ChangeRemoveMailbox {
	return ChangeRemoveMailbox{mb.ID, mb.Name, mb.ModSeq}
}

// KeywordsChanged returns whether the keywords in a mailbox have changed.
func (mb Mailbox) KeywordsChanged(origmb Mailbox) bool {
	if len(mb.Keywords) != len(origmb.Keywords) {
		return true
	}
	// Keywords are stored sorted.
	for i, kw := range mb.Keywords {
		if origmb.Keywords[i] != kw {
			return true
		}
	}
	return false
}

// CountsChange returns a change with mailbox counts.
func (mb Mailbox) ChangeCounts() ChangeMailboxCounts {
	return ChangeMailboxCounts{mb.ID, mb.Name, mb.MailboxCounts}
}

// Subscriptions are separate from existence of mailboxes.
type Subscription struct {
	Name string
}

// Flags for a mail message.
type Flags struct {
	Seen      bool
	Answered  bool
	Flagged   bool
	Forwarded bool
	Junk      bool
	Notjunk   bool
	Deleted   bool
	Draft     bool
	Phishing  bool
	MDNSent   bool
}

// FlagsAll is all flags set, for use as mask.
var FlagsAll = Flags{true, true, true, true, true, true, true, true, true, true}

// Validation of "message From" domain.
type Validation uint8

const (
	ValidationUnknown   Validation = 0
	ValidationStrict    Validation = 1 // Like DMARC, with strict policies.
	ValidationDMARC     Validation = 2 // Actual DMARC policy.
	ValidationRelaxed   Validation = 3 // Like DMARC, with relaxed policies.
	ValidationPass      Validation = 4 // For SPF.
	ValidationNeutral   Validation = 5 // For SPF.
	ValidationTemperror Validation = 6
	ValidationPermerror Validation = 7
	ValidationFail      Validation = 8
	ValidationSoftfail  Validation = 9  // For SPF.
	ValidationNone      Validation = 10 // E.g. No records.
)

// Message stored in database and per-message file on disk.
//
// Contents are always the combined data from MsgPrefix and the on-disk file named
// based on ID.
//
// Messages always have a header section, even if empty. Incoming messages without
// header section must get an empty header section added before inserting.
type Message struct {
	// ID of the message, determines path to on-disk message file. Set when adding to a
	// mailbox. When a message is moved to another mailbox, the mailbox ID is changed,
	// but for synchronization purposes, a new Message record is inserted (which gets a
	// new ID) with the Expunged field set and the MailboxID and UID copied.
	ID int64

	// UID, for IMAP. Set when adding to mailbox. Strictly increasing values, per
	// mailbox. The UID of a message can never change (though messages can be copied),
	// and the contents of a message/UID also never changes.
	UID UID `bstore:"nonzero"`

	MailboxID int64 `bstore:"nonzero,unique MailboxID+UID,index MailboxID+Received,index MailboxID+ModSeq,ref Mailbox"`

	// Modification sequence, for faster syncing with IMAP QRESYNC and JMAP.
	// ModSeq is the last modification. CreateSeq is the Seq the message was inserted,
	// always <= ModSeq. If Expunged is set, the message has been removed and should not
	// be returned to the user. In this case, ModSeq is the Seq where the message is
	// removed, and will never be changed again.
	// We have an index on both ModSeq (for JMAP that synchronizes per account) and
	// MailboxID+ModSeq (for IMAP that synchronizes per mailbox).
	// The index on CreateSeq helps efficiently finding created messages for JMAP.
	// The value of ModSeq is special for IMAP. Messages that existed before ModSeq was
	// added have 0 as value. But modseq 0 in IMAP is special, so we return it as 1. If
	// we get modseq 1 from a client, the IMAP server will translate it to 0. When we
	// return modseq to clients, we turn 0 into 1.
	ModSeq    ModSeq `bstore:"index"`
	CreateSeq ModSeq `bstore:"index"`
	Expunged  bool

	// If set, this message was delivered to a Rejects mailbox. When it is moved to a
	// different mailbox, its MailboxOrigID is set to the destination mailbox and this
	// flag cleared.
	IsReject bool

	// If set, this is a forwarded message (through a ruleset with IsForward). This
	// causes fields used during junk analysis to be moved to their Orig variants, and
	// masked IP fields cleared, so they aren't used in junk classifications for
	// incoming messages. This ensures the forwarded messages don't cause negative
	// reputation for the forwarding mail server, which may also be sending regular
	// messages.
	IsForward bool

	// MailboxOrigID is the mailbox the message was originally delivered to. Typically
	// Inbox or Rejects, but can also be a mailbox configured in a Ruleset, or
	// Postmaster, TLS/DMARC reporting addresses. MailboxOrigID is not changed when the
	// message is moved to another mailbox, e.g. Archive/Trash/Junk. Used for
	// per-mailbox reputation.
	//
	// MailboxDestinedID is normally 0, but when a message is delivered to the Rejects
	// mailbox, it is set to the intended mailbox according to delivery rules,
	// typically that of Inbox. When such a message is moved out of Rejects, the
	// MailboxOrigID is corrected by setting it to MailboxDestinedID. This ensures the
	// message is used for reputation calculation for future deliveries to that
	// mailbox.
	//
	// These are not bstore references to prevent having to update all messages in a
	// mailbox when the original mailbox is removed. Use of these fields requires
	// checking if the mailbox still exists.
	MailboxOrigID     int64
	MailboxDestinedID int64

	// Received indicates time of receival over SMTP, or of IMAP APPEND.
	Received time.Time `bstore:"default now,index"`

	// SaveDate is the time of copy/move/save to a mailbox, used with IMAP SAVEDATE
	// extension. Must be updated each time a message is copied/moved to another
	// mailbox. Can be nil for messages from before this functionality was introduced.
	SaveDate *time.Time `bstore:"default now"`

	// Full IP address of remote SMTP server. Empty if not delivered over SMTP. The
	// masked IPs are used to classify incoming messages. They are left empty for
	// messages matching a ruleset for forwarded messages.
	RemoteIP        string
	RemoteIPMasked1 string `bstore:"index RemoteIPMasked1+Received"` // For IPv4 /32, for IPv6 /64, for reputation.
	RemoteIPMasked2 string `bstore:"index RemoteIPMasked2+Received"` // For IPv4 /26, for IPv6 /48.
	RemoteIPMasked3 string `bstore:"index RemoteIPMasked3+Received"` // For IPv4 /21, for IPv6 /32.

	// Only set if present and not an IP address. Unicode string. Empty for forwarded
	// messages.
	EHLODomain        string         `bstore:"index EHLODomain+Received"`
	MailFrom          string         // With localpart and domain. Can be empty.
	MailFromLocalpart smtp.Localpart // SMTP "MAIL FROM", can be empty.
	// Only set if it is a domain, not an IP. Unicode string. Empty for forwarded
	// messages, but see OrigMailFromDomain.
	MailFromDomain  string         `bstore:"index MailFromDomain+Received"`
	RcptToLocalpart smtp.Localpart // SMTP "RCPT TO", can be empty.
	RcptToDomain    string         // Unicode string.

	// Parsed "From" message header, used for reputation along with domain validation.
	MsgFromLocalpart smtp.Localpart
	MsgFromDomain    string `bstore:"index MsgFromDomain+Received"`    // Unicode string.
	MsgFromOrgDomain string `bstore:"index MsgFromOrgDomain+Received"` // Unicode string.

	// Simplified statements of the Validation fields below, used for incoming messages
	// to check reputation.
	EHLOValidated     bool
	MailFromValidated bool
	MsgFromValidated  bool

	EHLOValidation     Validation // Validation can also take reverse IP lookup into account, not only SPF.
	MailFromValidation Validation // Can have SPF-specific validations like ValidationSoftfail.
	MsgFromValidation  Validation // Desirable validations: Strict, DMARC, Relaxed. Will not be just Pass.

	// Domains with verified DKIM signatures. Unicode string. For forwarded messages, a
	// DKIM domain that matched a ruleset's verified domain is left out, but included
	// in OrigDKIMDomains.
	DKIMDomains []string `bstore:"index DKIMDomains+Received"`

	// For forwarded messages,
	OrigEHLODomain  string
	OrigDKIMDomains []string

	// Canonicalized Message-Id, always lower-case and normalized quoting, without
	// <>'s. Empty if missing. Used for matching message threads, and to prevent
	// duplicate reject delivery.
	MessageID string `bstore:"index"`
	// lower-case: ../rfc/5256:495

	// For matching threads in case there is no References/In-Reply-To header. It is
	// lower-cased, white-space collapsed, mailing list tags and re/fwd tags removed.
	SubjectBase string `bstore:"index"`
	// ../rfc/5256:90

	// Hash of message. For rejects delivery in case there is no Message-ID, only set
	// when delivered as reject.
	MessageHash []byte

	// ID of message starting this thread.
	ThreadID int64 `bstore:"index"`
	// IDs of parent messages, from closest parent to the root message. Parent messages
	// may be in a different mailbox, or may no longer exist. ThreadParentIDs must
	// never contain the message id itself (a cycle), and parent messages must
	// reference the same ancestors. Moving a message to another mailbox keeps the
	// message ID and changes the MailboxID (and UID) of the message, leaving threading
	// parent ids intact.
	ThreadParentIDs []int64
	// ThreadMissingLink is true if there is no match with a direct parent. E.g. first
	// ID in ThreadParentIDs is not the direct ancestor (an intermediate message may
	// have been deleted), or subject-based matching was done.
	ThreadMissingLink bool
	// If set, newly delivered child messages are automatically marked as read. This
	// field is copied to new child messages. Changes are propagated to the webmail
	// client.
	ThreadMuted bool
	// If set, this (sub)thread is collapsed in the webmail client, for threading mode
	// "on" (mode "unread" ignores it). This field is copied to new child message.
	// Changes are propagated to the webmail client.
	ThreadCollapsed bool

	// If received message was known to match a mailing list rule (with modified junk
	// filtering).
	IsMailingList bool

	// If this message is a DSN, generated by us or received. For DSNs, we don't look
	// at the subject when matching threads.
	DSN bool

	ReceivedTLSVersion     uint16 // 0 if unknown, 1 if plaintext/no TLS, otherwise TLS cipher suite.
	ReceivedTLSCipherSuite uint16
	ReceivedRequireTLS     bool // Whether RequireTLS was known to be used for incoming delivery.

	Flags
	// For keywords other than system flags or the basic well-known $-flags. Only in
	// "atom" syntax (IMAP), they are case-insensitive, always stored in lower-case
	// (for JMAP), sorted.
	Keywords    []string `bstore:"index"`
	Size        int64
	TrainedJunk *bool  // If nil, no training done yet. Otherwise, true is trained as junk, false trained as nonjunk.
	MsgPrefix   []byte // Typically holds received headers and/or header separator.

	// If non-nil, a preview of the message based on text and/or html parts of the
	// message. Used in the webmail and IMAP PREVIEW extension. If non-nil, it is empty
	// if no preview could be created, or the message has not textual content or
	// couldn't be parsed.
	// Previews are typically created when delivering a message, but not when importing
	// messages, for speed. Previews are generated on first request (in the webmail, or
	// through the IMAP fetch attribute "PREVIEW" (without "LAZY")), and stored with
	// the message at that time.
	// The preview is at most 256 characters (can be more bytes), with detected quoted
	// text replaced with "[...]". Previews typically end with a newline, callers may
	// want to strip whitespace.
	Preview *string

	// ParsedBuf message structure. Currently saved as JSON of message.Part because
	// bstore wasn't able to store recursive types when this was implemented. Created
	// when first needed, and saved in the database.
	// todo: once replaced with non-json storage, remove date fixup in ../message/part.go.
	ParsedBuf []byte
}

// MailboxCounts returns the delta to counts this message means for its
// mailbox.
func (m Message) MailboxCounts() (mc MailboxCounts) {
	if m.Expunged {
		return
	}
	if m.Deleted {
		mc.Deleted++
	} else {
		mc.Total++
	}
	if !m.Seen {
		mc.Unseen++
		if !m.Deleted {
			mc.Unread++
		}
	}
	mc.Size += m.Size
	return
}

func (m Message) ChangeAddUID(mb Mailbox) ChangeAddUID {
	return ChangeAddUID{m.MailboxID, m.UID, m.ModSeq, m.Flags, m.Keywords, mb.MessageCountIMAP(), uint32(mb.MailboxCounts.Unseen)}
}

func (m Message) ChangeFlags(orig Flags, mb Mailbox) ChangeFlags {
	mask := m.Flags.Changed(orig)
	return ChangeFlags{m.MailboxID, m.UID, m.ModSeq, mask, m.Flags, m.Keywords, mb.UIDValidity, uint32(mb.MailboxCounts.Unseen)}
}

func (m Message) ChangeThread() ChangeThread {
	return ChangeThread{[]int64{m.ID}, m.ThreadMuted, m.ThreadCollapsed}
}

// ModSeq represents a modseq as stored in the database. ModSeq 0 in the
// database is sent to the client as 1, because modseq 0 is special in IMAP.
// ModSeq coming from the client are of type int64.
type ModSeq int64

func (ms ModSeq) Client() int64 {
	if ms == 0 {
		return 1
	}
	return int64(ms)
}

// ModSeqFromClient converts a modseq from a client to a modseq for internal
// use, e.g. in a database query.
// ModSeq 1 is turned into 0 (the Go zero value for ModSeq).
func ModSeqFromClient(modseq int64) ModSeq {
	if modseq == 1 {
		return 0
	}
	return ModSeq(modseq)
}

// Erase clears fields from a Message that are no longer needed after actually
// removing the message file from the file system, after all references to the
// message have gone away. Only the fields necessary for synchronisation are kept.
func (m *Message) erase() {
	if !m.Expunged {
		panic("erase called on non-expunged message")
	}
	*m = Message{
		ID:        m.ID,
		UID:       m.UID,
		MailboxID: m.MailboxID,
		CreateSeq: m.CreateSeq,
		ModSeq:    m.ModSeq,
		Expunged:  true,
		ThreadID:  m.ThreadID,
	}
}

// PrepareThreading sets MessageID, SubjectBase and DSN (used in threading) based
// on the part.
func (m *Message) PrepareThreading(log mlog.Log, part *message.Part) {
	m.DSN = part.IsDSN()

	if part.Envelope == nil {
		return
	}
	messageID, raw, err := message.MessageIDCanonical(part.Envelope.MessageID)
	if err != nil {
		log.Debugx("parsing message-id, ignoring", err, slog.String("messageid", part.Envelope.MessageID))
	} else if raw {
		log.Debug("could not parse message-id as address, continuing with raw value", slog.String("messageid", part.Envelope.MessageID))
	}
	m.MessageID = messageID
	m.SubjectBase, _ = message.ThreadSubject(part.Envelope.Subject, false)
}

// LoadPart returns a message.Part by reading from m.ParsedBuf.
func (m Message) LoadPart(r io.ReaderAt) (message.Part, error) {
	if m.ParsedBuf == nil {
		return message.Part{}, fmt.Errorf("message not parsed")
	}
	var p message.Part
	err := json.Unmarshal(m.ParsedBuf, &p)
	if err != nil {
		return p, fmt.Errorf("unmarshal message part")
	}
	p.SetReaderAt(r)
	return p, nil
}

// NeedsTraining returns whether message needs a training update, based on
// TrainedJunk (current training status) and new Junk/Notjunk flags.
func (m Message) NeedsTraining() bool {
	needs, _, _, _, _ := m.needsTraining()
	return needs
}

func (m Message) needsTraining() (needs, untrain, untrainJunk, train, trainJunk bool) {
	untrain = m.TrainedJunk != nil
	untrainJunk = untrain && *m.TrainedJunk
	train = m.Junk != m.Notjunk
	trainJunk = m.Junk
	needs = untrain != train || untrain && train && untrainJunk != trainJunk
	return
}

// JunkFlagsForMailbox sets Junk and Notjunk flags based on mailbox name if configured. Often
// used when delivering/moving/copying messages to a mailbox. Mail clients are not
// very helpful with setting junk/notjunk flags. But clients can move/copy messages
// to other mailboxes. So we set flags when clients move a message.
func (m *Message) JunkFlagsForMailbox(mb Mailbox, conf config.Account) {
	if mb.Junk {
		m.Junk = true
		m.Notjunk = false
		return
	}

	if !conf.AutomaticJunkFlags.Enabled {
		return
	}

	lmailbox := strings.ToLower(mb.Name)

	if conf.JunkMailbox != nil && conf.JunkMailbox.MatchString(lmailbox) {
		m.Junk = true
		m.Notjunk = false
	} else if conf.NeutralMailbox != nil && conf.NeutralMailbox.MatchString(lmailbox) {
		m.Junk = false
		m.Notjunk = false
	} else if conf.NotJunkMailbox != nil && conf.NotJunkMailbox.MatchString(lmailbox) {
		m.Junk = false
		m.Notjunk = true
	} else if conf.JunkMailbox == nil && conf.NeutralMailbox != nil && conf.NotJunkMailbox != nil {
		m.Junk = true
		m.Notjunk = false
	} else if conf.JunkMailbox != nil && conf.NeutralMailbox == nil && conf.NotJunkMailbox != nil {
		m.Junk = false
		m.Notjunk = false
	} else if conf.JunkMailbox != nil && conf.NeutralMailbox != nil && conf.NotJunkMailbox == nil {
		m.Junk = false
		m.Notjunk = true
	}
}

// Recipient represents the recipient of a message. It is tracked to allow
// first-time incoming replies from users this account has sent messages to. When a
// mailbox is added to the Sent mailbox the message is parsed and recipients are
// inserted as recipient. Recipients are never removed other than for removing the
// message. On move/copy of a message, recipients aren't modified either. For IMAP,
// this assumes a client simply appends messages to the Sent mailbox (as opposed to
// copying messages from some place).
type Recipient struct {
	ID        int64
	MessageID int64     `bstore:"nonzero,ref Message"`            // Ref gives it its own index, useful for fast removal as well.
	Localpart string    `bstore:"nonzero"`                        // Encoded localpart.
	Domain    string    `bstore:"nonzero,index Domain+Localpart"` // Unicode string.
	OrgDomain string    `bstore:"nonzero,index"`                  // Unicode string.
	Sent      time.Time `bstore:"nonzero"`
}

// Outgoing is a message submitted for delivery from the queue. Used to enforce
// maximum outgoing messages.
type Outgoing struct {
	ID        int64
	Recipient string    `bstore:"nonzero,index"` // Canonical international address with utf8 domain.
	Submitted time.Time `bstore:"nonzero,default now"`
}

// RecipientDomainTLS stores TLS capabilities of a recipient domain as encountered
// during most recent connection (delivery attempt).
type RecipientDomainTLS struct {
	Domain     string    // Unicode.
	Updated    time.Time `bstore:"default now"`
	STARTTLS   bool      // Supports STARTTLS.
	RequireTLS bool      // Supports RequireTLS SMTP extension.
}

// DiskUsage tracks quota use.
type DiskUsage struct {
	ID          int64 // Always one record with ID 1.
	MessageSize int64 // Sum of all messages, for quota accounting.
}

// SessionToken and CSRFToken are types to prevent mixing them up.
// Base64 raw url encoded.
type SessionToken string
type CSRFToken string

// LoginSession represents a login session. We keep a limited number of sessions
// for a user, removing the oldest session when a new one is created.
type LoginSession struct {
	ID                 int64
	Created            time.Time `bstore:"nonzero,default now"` // Of original login.
	Expires            time.Time `bstore:"nonzero"`             // Extended each time it is used.
	SessionTokenBinary [16]byte  `bstore:"nonzero"`             // Stored in cookie, like "webmailsession" or "webaccountsession".
	CSRFTokenBinary    [16]byte  // For API requests, in "x-mox-csrf" header.
	AccountName        string    `bstore:"nonzero"`
	LoginAddress       string    `bstore:"nonzero"`

	// Set when loading from database.
	sessionToken SessionToken
	csrfToken    CSRFToken
}

// Quoting is a setting for how to quote in replies/forwards.
type Quoting string

const (
	Default Quoting = "" // Bottom-quote if text is selected, top-quote otherwise.
	Bottom  Quoting = "bottom"
	Top     Quoting = "top"
)

// Settings are webmail client settings.
type Settings struct {
	ID uint8 // Singleton ID 1.

	Signature string
	Quoting   Quoting

	// Whether to show the bars underneath the address input fields indicating
	// starttls/dnssec/dane/mtasts/requiretls support by address.
	ShowAddressSecurity bool

	// Show HTML version of message by default, instead of plain text.
	ShowHTML bool

	// If true, don't show shortcuts in webmail after mouse interaction.
	NoShowShortcuts bool

	// Additional headers to display in message view. E.g. Delivered-To, User-Agent, X-Mox-Reason.
	ShowHeaders []string
}

// ViewMode how a message should be viewed: its text parts, html parts, or html
// with loading external resources.
type ViewMode string

const (
	ModeText    ViewMode = "text"
	ModeHTML    ViewMode = "html"
	ModeHTMLExt ViewMode = "htmlext" // HTML with external resources.
)

// FromAddressSettings are webmail client settings per "From" address.
type FromAddressSettings struct {
	FromAddress string // Unicode.
	ViewMode    ViewMode
}

// RulesetNoListID records a user "no" response to the question of
// creating/removing a ruleset after moving a message with list-id header from/to
// the inbox.
type RulesetNoListID struct {
	ID            int64
	RcptToAddress string `bstore:"nonzero"`
	ListID        string `bstore:"nonzero"`
	ToInbox       bool   // Otherwise from Inbox to other mailbox.
}

// RulesetNoMsgFrom records a user "no" response to the question of
// creating/moveing a ruleset after moving a mesage with message "from" address
// from/to the inbox.
type RulesetNoMsgFrom struct {
	ID             int64
	RcptToAddress  string `bstore:"nonzero"`
	MsgFromAddress string `bstore:"nonzero"` // Unicode.
	ToInbox        bool   // Otherwise from Inbox to other mailbox.
}

// RulesetNoMailbox represents a "never from/to this mailbox" response to the
// question of adding/removing a ruleset after moving a message.
type RulesetNoMailbox struct {
	ID int64

	// The mailbox from/to which the move has happened.
	// Not a references, if mailbox is deleted, an entry becomes ineffective.
	MailboxID int64 `bstore:"nonzero"`
	ToMailbox bool  // Whether MailboxID is the destination of the move (instead of source).
}

// MessageErase represents the need to remove a message file from disk, and clear
// message fields from the database, but only when the last reference to the
// message is gone (all IMAP sessions need to have applied the changes indicating
// message removal).
type MessageErase struct {
	ID int64 // Same ID as Message.ID.

	// Whether to subtract the size from the total disk usage. Useful for moving
	// messages, which involves duplicating the message temporarily, while there are
	// still references in the old mailbox, but which isn't counted as using twice the
	// disk space..
	SkipUpdateDiskUsage bool
}

// Types stored in DB.
var DBTypes = []any{
	NextUIDValidity{},
	Message{},
	Recipient{},
	Mailbox{},
	Subscription{},
	Outgoing{},
	Password{},
	Subjectpass{},
	SyncState{},
	Upgrade{},
	RecipientDomainTLS{},
	DiskUsage{},
	LoginSession{},
	Settings{},
	FromAddressSettings{},
	RulesetNoListID{},
	RulesetNoMsgFrom{},
	RulesetNoMailbox{},
	Annotation{},
	MessageErase{},
}

// Account holds the information about a user, includings mailboxes, messages, imap subscriptions.
type Account struct {
	Name   string     // Name, according to configuration.
	Dir    string     // Directory where account files, including the database, bloom filter, and mail messages, are stored for this account.
	DBPath string     // Path to database with mailboxes, messages, etc.
	DB     *bstore.DB // Open database connection.

	// Channel that is closed if/when account has/gets "threads" accounting (see
	// Upgrade.Threads).
	threadsCompleted chan struct{}
	// If threads upgrade completed with error, this is set. Used for warning during
	// delivery, or aborting when importing.
	threadsErr error

	// Message directory of last delivery. Used to check we don't have to make that
	// directory when delivering.
	lastMsgDir string

	// If set, consistency checks won't fail on message ModSeq/CreateSeq being zero.
	skipMessageZeroSeqCheck bool

	// Write lock must be held when modifying account/mailbox/message/flags/annotations
	// if the change needs to be synchronized with client connections by broadcasting
	// the changes. Changes that are not protocol-visible do not require a lock, the
	// database transactions isolate activity, though locking may be necessary to
	// protect in-memory-only access.
	//
	// Read lock for reading mailboxes/messages as a consistent snapsnot (i.e. not
	// concurrent changes). For longer transactions, e.g. when reading many messages,
	// the lock can be released while continuing to read from the transaction.
	//
	// When making changes to mailboxes/messages, changes must be broadcasted before
	// releasing the lock to ensure proper UID ordering.
	sync.RWMutex

	// Reference count, while >0, this account is alive and shared. Protected by
	// openAccounts, not by account wlock.
	nused   int
	removed bool          // Marked for removal. Last close removes the account directory.
	closed  chan struct{} // Closed when last reference is gone.
}

type Upgrade struct {
	ID                  byte
	Threads             byte // 0: None, 1: Adding MessageID's completed, 2: Adding ThreadID's completed.
	MailboxModSeq       bool // Whether mailboxes have been assigned modseqs.
	MailboxParentID     bool // Setting ParentID on mailboxes.
	MailboxCounts       bool // Global flag about whether we have mailbox flags. Instead of previous per-mailbox boolean.
	MessageParseVersion int  // If different than latest, all messages will be reparsed.
}

const MessageParseVersionLatest = 1

// upgradeInit is the value for new account database, which don't need any upgrading.
var upgradeInit = Upgrade{
	ID:                  1, // Singleton.
	Threads:             2,
	MailboxModSeq:       true,
	MailboxParentID:     true,
	MailboxCounts:       true,
	MessageParseVersion: MessageParseVersionLatest,
}

// InitialUIDValidity returns a UIDValidity used for initializing an account.
// It can be replaced during tests with a predictable value.
var InitialUIDValidity = func() uint32 {
	return uint32(time.Now().Unix() >> 1) // A 2-second resolution will get us far enough beyond 2038.
}

var openAccounts = struct {
	sync.Mutex
	names map[string]*Account
}{
	names: map[string]*Account{},
}

func closeAccount(acc *Account) (rerr error) {
	// If we need to remove the account files, we do so without the accounts lock.
	remove := false
	defer func() {
		if remove {
			log := mlog.New("store", nil)
			err := removeAccount(log, acc.Name)
			if rerr == nil {
				rerr = err
			}
			close(acc.closed)
		}
	}()

	openAccounts.Lock()
	defer openAccounts.Unlock()
	acc.nused--
	if acc.nused > 0 {
		return
	}
	remove = acc.removed

	defer func() {
		err := acc.DB.Close()
		acc.DB = nil
		delete(openAccounts.names, acc.Name)
		if !remove {
			close(acc.closed)
		}

		if rerr == nil {
			rerr = err
		}
	}()

	// Verify there are no more pending MessageErase records.
	l, err := bstore.QueryDB[MessageErase](context.TODO(), acc.DB).List()
	if err != nil {
		return fmt.Errorf("listing messageerase records: %v", err)
	} else if len(l) > 0 {
		return fmt.Errorf("messageerase records still present after last account reference is gone: %v", l)
	}

	return nil
}

// removeAccount moves the account directory for an account away and removes
// all files, and removes the AccountRemove struct from the database.
func removeAccount(log mlog.Log, accountName string) error {
	log = log.With(slog.String("account", accountName))
	log.Info("removing account directory and files")

	// First move the account directory away.
	odir := filepath.Join(mox.DataDirPath("accounts"), accountName)
	tmpdir := filepath.Join(mox.DataDirPath("tmp"), "oldaccount-"+accountName)
	if err := os.Rename(odir, tmpdir); err != nil {
		return fmt.Errorf("moving account data directory %q out of the way to %q (account not removed): %v", odir, tmpdir, err)
	}

	var errs []error

	// Commit removal to database.
	err := AuthDB.Write(context.Background(), func(tx *bstore.Tx) error {
		if err := tx.Delete(&AccountRemove{accountName}); err != nil {
			return fmt.Errorf("deleting account removal request: %v", err)
		}
		if err := tlsPublicKeyRemoveForAccount(tx, accountName); err != nil {
			return fmt.Errorf("removing tls public keys for account: %v", err)
		}

		if err := loginAttemptRemoveAccount(tx, accountName); err != nil {
			return fmt.Errorf("removing historic login attempts for account: %v", err)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("remove account from database: %w", err))
	}

	// Remove the account directory and its message and other files.
	if err := os.RemoveAll(tmpdir); err != nil {
		errs = append(errs, fmt.Errorf("removing account data directory %q that was moved to %q: %v", odir, tmpdir, err))
	}

	return errors.Join(errs...)
}

// OpenAccount opens an account by name.
//
// No additional data path prefix or ".db" suffix should be added to the name.
// A single shared account exists per name.
func OpenAccount(log mlog.Log, name string, checkLoginDisabled bool) (*Account, error) {
	openAccounts.Lock()
	defer openAccounts.Unlock()
	if acc, ok := openAccounts.names[name]; ok {
		if acc.removed {
			return nil, fmt.Errorf("account has been removed")
		}

		acc.nused++
		return acc, nil
	}

	if a, ok := mox.Conf.Account(name); !ok {
		return nil, ErrAccountUnknown
	} else if checkLoginDisabled && a.LoginDisabled != "" {
		return nil, fmt.Errorf("%w: %s", ErrLoginDisabled, a.LoginDisabled)
	}

	acc, err := openAccount(log, name)
	if err != nil {
		return nil, err
	}
	openAccounts.names[name] = acc
	return acc, nil
}

// openAccount opens an existing account, or creates it if it is missing.
// Called with openAccounts lock held.
func openAccount(log mlog.Log, name string) (a *Account, rerr error) {
	dir := filepath.Join(mox.DataDirPath("accounts"), name)
	return OpenAccountDB(log, dir, name)
}

// OpenAccountDB opens an account database file and returns an initialized account
// or error. Only exported for use by subcommands that verify the database file.
// Almost all account opens must go through OpenAccount/OpenEmail/OpenEmailAuth.
func OpenAccountDB(log mlog.Log, accountDir, accountName string) (a *Account, rerr error) {
	log = log.With(slog.String("account", accountName))

	dbpath := filepath.Join(accountDir, "index.db")

	// Create account if it doesn't exist yet.
	isNew := false
	if _, err := os.Stat(dbpath); err != nil && os.IsNotExist(err) {
		isNew = true
		os.MkdirAll(accountDir, 0770)
	}

	opts := bstore.Options{Timeout: 5 * time.Second, Perm: 0660, RegisterLogger: moxvar.RegisterLogger(dbpath, log.Logger)}
	db, err := bstore.Open(context.TODO(), dbpath, &opts, DBTypes...)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			err := db.Close()
			log.Check(err, "closing database file after error")
			if isNew {
				err := os.Remove(dbpath)
				log.Check(err, "removing new database file after error")
			}
		}
	}()

	acc := &Account{
		Name:             accountName,
		Dir:              accountDir,
		DBPath:           dbpath,
		DB:               db,
		nused:            1,
		closed:           make(chan struct{}),
		threadsCompleted: make(chan struct{}),
	}

	if isNew {
		if err := initAccount(db); err != nil {
			return nil, fmt.Errorf("initializing account: %v", err)
		}

		close(acc.threadsCompleted)
		return acc, nil
	}

	// Ensure singletons are present, like DiskUsage and Settings.
	// Process pending MessageErase records. Check that next the message ID assigned by
	// the database does not already have a file on disk, or increase the sequence so
	// it doesn't.
	err = db.Write(context.TODO(), func(tx *bstore.Tx) error {
		if tx.Get(&Settings{ID: 1}) == bstore.ErrAbsent {
			if err := tx.Insert(&Settings{ID: 1, ShowAddressSecurity: true}); err != nil {
				return err
			}
		}

		du := DiskUsage{ID: 1}
		err = tx.Get(&du)
		if err == bstore.ErrAbsent {
			// No DiskUsage record yet, calculate total size and insert.
			err := bstore.QueryTx[Mailbox](tx).FilterEqual("Expunged", false).ForEach(func(mb Mailbox) error {
				du.MessageSize += mb.Size
				return nil
			})
			if err != nil {
				return err
			}
			if err := tx.Insert(&du); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		var erase []MessageErase
		if _, err := bstore.QueryTx[MessageErase](tx).Gather(&erase).Delete(); err != nil {
			return fmt.Errorf("fetching messages to erase: %w", err)
		}
		if len(erase) > 0 {
			log.Debug("deleting message files from message erase records", slog.Int("count", len(erase)))
		}
		var duChanged bool
		for _, me := range erase {
			// Clear the fields from the message not needed for synchronization.
			m := Message{ID: me.ID}
			if err := tx.Get(&m); err != nil {
				return fmt.Errorf("get message %d to expunge: %w", me.ID, err)
			} else if !m.Expunged {
				return fmt.Errorf("message %d to erase is not expunged", m.ID)
			}

			// We remove before we update/commit the database, so we are sure we don't leave
			// files behind in case of an error/crash.
			p := acc.MessagePath(me.ID)
			err := os.Remove(p)
			log.Check(err, "removing message file for expunged message", slog.String("path", p))

			if !me.SkipUpdateDiskUsage {
				du.MessageSize -= m.Size
				duChanged = true
			}

			m.erase()
			if err := tx.Update(&m); err != nil {
				return fmt.Errorf("save erase of message %d in database: %w", m.ID, err)
			}
		}

		if duChanged {
			if err := tx.Update(&du); err != nil {
				return fmt.Errorf("saving disk usage after erasing messages: %w", err)
			}
		}

		// Ensure the message directories don't have a higher message ID than occurs in our
		// database. If so, increase the next ID used for inserting a message to prevent
		// clash during delivery.
		last, err := bstore.QueryTx[Message](tx).SortDesc("ID").Limit(1).Get()
		if err != nil && err != bstore.ErrAbsent {
			return fmt.Errorf("querying last message: %v", err)
		}

		// We look in the directory where the message is stored (the id can be 0, which is fine).
		maxDBID := last.ID
		p := acc.MessagePath(maxDBID)
		dir := filepath.Dir(p)
		maxFSID := maxDBID
		// We also try looking for the next directories that would be created for messages,
		// until one doesn't exist anymore. We never delete these directories.
		for {
			np := acc.MessagePath(maxFSID + msgFilesPerDir)
			ndir := filepath.Dir(np)
			if _, err := os.Stat(ndir); err == nil {
				maxFSID = (maxFSID + msgFilesPerDir) &^ (msgFilesPerDir - 1) // First ID for dir.
				dir = ndir
			} else if errors.Is(err, fs.ErrNotExist) {
				break
			} else {
				return fmt.Errorf("stat next message directory %q: %v", ndir, err)
			}
		}
		// Find highest numbered file within the directory.
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read message directory %q: %v", dir, err)
		}
		dirFirstID := maxFSID &^ (msgFilesPerDir - 1)
		for _, e := range entries {
			id, err := strconv.ParseInt(e.Name(), 10, 64)
			if err == nil && (id < dirFirstID || id >= dirFirstID+msgFilesPerDir) {
				err = fmt.Errorf("directory %s has message id %d outside of range [%d - %d), ignoring", dir, id, dirFirstID, dirFirstID+msgFilesPerDir)
			}
			if err != nil {
				p := filepath.Join(dir, e.Name())
				log.Errorx("unrecognized file in message directory, parsing filename as number", err, slog.String("path", p))
			} else {
				maxFSID = max(maxFSID, id)
			}
		}
		// Warn if we need to increase the message ID in the database.
		var mailboxID int64
		if maxFSID > maxDBID {
			log.Warn("unexpected message file with higher message id than highest id in database, moving database id sequence forward to prevent clashes during future deliveries", slog.Int64("maxdbmsgid", maxDBID), slog.Int64("maxfilemsgid", maxFSID))

			mb, err := bstore.QueryTx[Mailbox](tx).Limit(1).Get()
			if err != nil {
				return fmt.Errorf("get a mailbox: %v", err)
			}
			mailboxID = mb.ID
		}
		for maxFSID > maxDBID {
			// Set fields that must be non-zero.
			m := Message{
				UID:       ^UID(0),
				MailboxID: mailboxID,
			}
			// Insert and delete to increase the sequence, silly but effective.
			if err := tx.Insert(&m); err != nil {
				return fmt.Errorf("inserting message to increase id: %v", err)
			}
			if err := tx.Delete(&m); err != nil {
				return fmt.Errorf("deleting message after increasing id: %v", err)
			}
			maxDBID = m.ID
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("calculating counts for mailbox, inserting settings, expunging messages: %v", err)
	}

	up := Upgrade{ID: 1}
	err = db.Write(context.TODO(), func(tx *bstore.Tx) error {
		err := tx.Get(&up)
		if err == bstore.ErrAbsent {
			if err := tx.Insert(&up); err != nil {
				return fmt.Errorf("inserting initial upgrade record: %v", err)
			}
			err = nil
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("checking message threading: %v", err)
	}

	// Ensure all mailboxes have a modseq based on highest modseq message in each
	// mailbox, and a createseq.
	if !up.MailboxModSeq {
		log.Debug("upgrade: adding modseq to each mailbox")
		err := acc.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
			var modseq ModSeq

			mbl, err := bstore.QueryTx[Mailbox](tx).FilterEqual("Expunged", false).List()
			if err != nil {
				return fmt.Errorf("listing mailboxes: %v", err)
			}
			for _, mb := range mbl {
				// Get current highest modseq of message in account.
				qms := bstore.QueryTx[Message](tx)
				qms.FilterNonzero(Message{MailboxID: mb.ID})
				qms.SortDesc("ModSeq")
				qms.Limit(1)
				m, err := qms.Get()
				if err == nil {
					mb.ModSeq = ModSeq(m.ModSeq.Client())
				} else if err == bstore.ErrAbsent {
					if modseq == 0 {
						modseq, err = acc.NextModSeq(tx)
						if err != nil {
							return fmt.Errorf("get next mod seq for mailbox without messages: %v", err)
						}
					}
					mb.ModSeq = modseq
				} else {
					return fmt.Errorf("looking up highest modseq for mailbox: %v", err)
				}
				mb.CreateSeq = 1
				if err := tx.Update(&mb); err != nil {
					return fmt.Errorf("updating mailbox with modseq: %v", err)
				}
			}

			up.MailboxModSeq = true
			if err := tx.Update(&up); err != nil {
				return fmt.Errorf("marking upgrade done: %v", err)
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("upgrade: adding modseq to each mailbox: %v", err)
		}
	}

	// Add ParentID to mailboxes.
	if !up.MailboxParentID {
		log.Debug("upgrade: setting parentid on each mailbox")

		err := acc.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
			mbl, err := bstore.QueryTx[Mailbox](tx).FilterEqual("Expunged", false).SortAsc("Name").List()
			if err != nil {
				return fmt.Errorf("listing mailboxes: %w", err)
			}

			names := map[string]Mailbox{}
			for _, mb := range mbl {
				names[mb.Name] = mb
			}

			var modseq ModSeq

			// Ensure a parent mailbox for name exists, creating it if needed, including any
			// grandparents, up to the top.
			var ensureParentMailboxID func(name string) (int64, error)
			ensureParentMailboxID = func(name string) (int64, error) {
				parentName := mox.ParentMailboxName(name)
				if parentName == "" {
					return 0, nil
				}
				parent := names[parentName]
				if parent.ID != 0 {
					return parent.ID, nil
				}

				parentParentID, err := ensureParentMailboxID(parentName)
				if err != nil {
					return 0, fmt.Errorf("creating parent mailbox %q: %w", parentName, err)
				}

				if modseq == 0 {
					modseq, err = a.NextModSeq(tx)
					if err != nil {
						return 0, fmt.Errorf("get next modseq: %w", err)
					}
				}

				uidvalidity, err := a.NextUIDValidity(tx)
				if err != nil {
					return 0, fmt.Errorf("next uid validity: %w", err)
				}

				parent = Mailbox{
					CreateSeq:   modseq,
					ModSeq:      modseq,
					ParentID:    parentParentID,
					Name:        parentName,
					UIDValidity: uidvalidity,
					UIDNext:     1,
					SpecialUse:  SpecialUse{},
					HaveCounts:  true,
				}
				if err := tx.Insert(&parent); err != nil {
					return 0, fmt.Errorf("creating parent mailbox: %w", err)
				}
				return parent.ID, nil
			}

			for _, mb := range mbl {
				parentID, err := ensureParentMailboxID(mb.Name)
				if err != nil {
					return fmt.Errorf("creating missing parent mailbox for mailbox %q: %w", mb.Name, err)
				}
				mb.ParentID = parentID
				if err := tx.Update(&mb); err != nil {
					return fmt.Errorf("update mailbox with parentid: %w", err)
				}
			}

			up.MailboxParentID = true
			if err := tx.Update(&up); err != nil {
				return fmt.Errorf("marking upgrade done: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("upgrade: setting parentid on each mailbox: %w", err)
		}
	}

	if !up.MailboxCounts {
		log.Debug("upgrade: ensuring all mailboxes have message counts")

		err := acc.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
			err := bstore.QueryTx[Mailbox](tx).FilterEqual("HaveCounts", false).ForEach(func(mb Mailbox) error {
				mc, err := mb.CalculateCounts(tx)
				if err != nil {
					return err
				}
				mb.HaveCounts = true
				mb.MailboxCounts = mc
				return tx.Update(&mb)
			})
			if err != nil {
				return err
			}

			up.MailboxCounts = true
			if err := tx.Update(&up); err != nil {
				return fmt.Errorf("marking upgrade done: %w", err)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("upgrade: ensuring message counts on all mailboxes")
		}
	}

	if up.MessageParseVersion != MessageParseVersionLatest {
		log.Debug("upgrade: reparsing message for mime structures for new message parse version", slog.Int("current", up.MessageParseVersion), slog.Int("latest", MessageParseVersionLatest))

		// Unless we also need to upgrade threading, we'll be reparsing messages in the
		// background so opening of the account is quick.
		done := make(chan error, 1)
		bg := up.Threads == 2

		// Increase account use before holding on to account in background.
		// Caller holds the lock. The goroutine below decreases nused by calling
		// closeAccount.
		acc.nused++

		go func() {
			start := time.Now()

			var rerr error
			defer func() {
				x := recover()
				if x != nil {
					rerr = fmt.Errorf("unhandled panic: %v", x)
					log.Error("unhandled panic reparsing messages", slog.Any("err", x))
					debug.PrintStack()
					metrics.PanicInc(metrics.Store)
				}

				if bg && rerr != nil {
					log.Errorx("upgrade failed: reparsing message for mime structures for new message parse version", rerr, slog.Duration("duration", time.Since(start)))
				}
				done <- rerr

				// Must be done at end of defer. Our parent context/goroutine has openAccounts lock
				// held, so we won't make progress until after the enclosing method has returned.
				err := closeAccount(acc)
				log.Check(err, "closing account after reparsing messages")
			}()

			var total int
			total, rerr = acc.ReparseMessages(mox.Shutdown, log)
			if rerr != nil {
				rerr = fmt.Errorf("reparsing messages and updating mime structures in message index: %w", rerr)
				return
			}

			up.MessageParseVersion = MessageParseVersionLatest
			rerr = acc.DB.Update(context.TODO(), &up)
			if rerr != nil {
				rerr = fmt.Errorf("marking latest message parse version: %w", rerr)
				return
			}

			log.Info("upgrade completed: reparsing message for mime structures for new message parse version", slog.Int("total", total), slog.Duration("duration", time.Since(start)))
		}()

		if !bg {
			err := <-done
			if err != nil {
				return nil, err
			}
		}
	}

	if up.Threads == 2 {
		close(acc.threadsCompleted)
		return acc, nil
	}

	// Increase account use before holding on to account in background.
	// Caller holds the lock. The goroutine below decreases nused by calling
	// closeAccount.
	acc.nused++

	// Ensure all messages have a MessageID and SubjectBase, which are needed when
	// matching threads.
	// Then assign messages to threads, in the same way we do during imports.
	log.Info("upgrading account for threading, in background")
	go func() {
		defer func() {
			err := closeAccount(acc)
			log.Check(err, "closing use of account after upgrading account storage for threads")

			// Mark that upgrade has finished, possibly error is indicated in threadsErr.
			close(acc.threadsCompleted)
		}()

		defer func() {
			x := recover() // Should not happen, but don't take program down if it does.
			if x != nil {
				log.Error("upgradeThreads panic", slog.Any("err", x))
				debug.PrintStack()
				metrics.PanicInc(metrics.Upgradethreads)
				acc.threadsErr = fmt.Errorf("panic during upgradeThreads: %v", x)
			}
		}()

		err := upgradeThreads(mox.Shutdown, log, acc, up)
		if err != nil {
			a.threadsErr = err
			log.Errorx("upgrading account for threading, aborted", err)
		} else {
			log.Info("upgrading account for threading, completed")
		}
	}()
	return acc, nil
}

// ThreadingWait blocks until the one-time account threading upgrade for the
// account has completed, and returns an error if not successful.
//
// To be used before starting an import of messages.
func (a *Account) ThreadingWait(log mlog.Log) error {
	select {
	case <-a.threadsCompleted:
		return a.threadsErr
	default:
	}
	log.Debug("waiting for account upgrade to complete")

	<-a.threadsCompleted
	return a.threadsErr
}

func initAccount(db *bstore.DB) error {
	return db.Write(context.TODO(), func(tx *bstore.Tx) error {
		uidvalidity := InitialUIDValidity()

		if err := tx.Insert(&upgradeInit); err != nil {
			return err
		}
		if err := tx.Insert(&DiskUsage{ID: 1}); err != nil {
			return err
		}
		if err := tx.Insert(&Settings{ID: 1}); err != nil {
			return err
		}

		modseq, err := nextModSeq(tx)
		if err != nil {
			return fmt.Errorf("get next modseq: %v", err)
		}

		if len(mox.Conf.Static.DefaultMailboxes) > 0 {
			// Deprecated in favor of InitialMailboxes.
			defaultMailboxes := mox.Conf.Static.DefaultMailboxes
			mailboxes := []string{"Inbox"}
			for _, name := range defaultMailboxes {
				if strings.EqualFold(name, "Inbox") {
					continue
				}
				mailboxes = append(mailboxes, name)
			}
			for _, name := range mailboxes {
				mb := Mailbox{
					CreateSeq:   modseq,
					ModSeq:      modseq,
					ParentID:    0,
					Name:        name,
					UIDValidity: uidvalidity,
					UIDNext:     1,
					HaveCounts:  true,
				}
				if strings.HasPrefix(name, "Archive") {
					mb.Archive = true
				} else if strings.HasPrefix(name, "Drafts") {
					mb.Draft = true
				} else if strings.HasPrefix(name, "Junk") {
					mb.Junk = true
				} else if strings.HasPrefix(name, "Sent") {
					mb.Sent = true
				} else if strings.HasPrefix(name, "Trash") {
					mb.Trash = true
				}
				if err := tx.Insert(&mb); err != nil {
					return fmt.Errorf("creating mailbox: %w", err)
				}
				if err := tx.Insert(&Subscription{name}); err != nil {
					return fmt.Errorf("adding subscription: %w", err)
				}
			}
		} else {
			mailboxes := mox.Conf.Static.InitialMailboxes
			var zerouse config.SpecialUseMailboxes
			if mailboxes.SpecialUse == zerouse && len(mailboxes.Regular) == 0 {
				mailboxes = DefaultInitialMailboxes
			}

			add := func(name string, use SpecialUse) error {
				mb := Mailbox{
					CreateSeq:   modseq,
					ModSeq:      modseq,
					ParentID:    0,
					Name:        name,
					UIDValidity: uidvalidity,
					UIDNext:     1,
					SpecialUse:  use,
					HaveCounts:  true,
				}
				if err := tx.Insert(&mb); err != nil {
					return fmt.Errorf("creating mailbox: %w", err)
				}
				if err := tx.Insert(&Subscription{name}); err != nil {
					return fmt.Errorf("adding subscription: %w", err)
				}
				return nil
			}
			addSpecialOpt := func(nameOpt string, use SpecialUse) error {
				if nameOpt == "" {
					return nil
				}
				return add(nameOpt, use)
			}
			l := []struct {
				nameOpt string
				use     SpecialUse
			}{
				{"Inbox", SpecialUse{}},
				{mailboxes.SpecialUse.Archive, SpecialUse{Archive: true}},
				{mailboxes.SpecialUse.Draft, SpecialUse{Draft: true}},
				{mailboxes.SpecialUse.Junk, SpecialUse{Junk: true}},
				{mailboxes.SpecialUse.Sent, SpecialUse{Sent: true}},
				{mailboxes.SpecialUse.Trash, SpecialUse{Trash: true}},
			}
			for _, e := range l {
				if err := addSpecialOpt(e.nameOpt, e.use); err != nil {
					return err
				}
			}
			for _, name := range mailboxes.Regular {
				if err := add(name, SpecialUse{}); err != nil {
					return err
				}
			}
		}

		uidvalidity++
		if err := tx.Insert(&NextUIDValidity{1, uidvalidity}); err != nil {
			return fmt.Errorf("inserting nextuidvalidity: %w", err)
		}
		return nil
	})
}

// Remove schedules an account for removal. New opens will fail. When the last
// reference is closed, the account files are removed.
func (a *Account) Remove(ctx context.Context) error {
	openAccounts.Lock()
	defer openAccounts.Unlock()

	if err := AuthDB.Insert(ctx, &AccountRemove{AccountName: a.Name}); err != nil {
		return fmt.Errorf("inserting account removal: %w", err)
	}
	a.removed = true

	return nil
}

// WaitClosed waits until the last reference to this account is gone and the
// account is closed. Used during tests, to ensure the consistency checks run after
// expunged messages have been erased.
func (a *Account) WaitClosed() {
	<-a.closed
}

// Close reduces the reference count, and closes the database connection when
// it was the last user.
func (a *Account) Close() error {
	if CheckConsistencyOnClose {
		xerr := a.CheckConsistency()
		err := closeAccount(a)
		if xerr != nil {
			panic(xerr)
		}
		return err
	}
	return closeAccount(a)
}

// SetSkipMessageModSeqZeroCheck skips consistency checks for Message.ModSeq and
// Message.CreateSeq being zero.
func (a *Account) SetSkipMessageModSeqZeroCheck(skip bool) {
	a.Lock()
	defer a.Unlock()
	a.skipMessageZeroSeqCheck = true
}

// CheckConsistency checks the consistency of the database and returns a non-nil
// error for these cases:
//
// - Missing or unexpected on-disk message files.
// - Mismatch between message size and length of MsgPrefix and on-disk file.
// - Incorrect mailbox counts.
// - Incorrect total message size.
// - Message with UID >= mailbox uid next.
// - Mailbox uidvalidity >= account uid validity.
// - Mailbox ModSeq > 0, CreateSeq > 0, CreateSeq <= ModSeq, and Modseq >= highest message ModSeq.
// - Mailbox must have a live parent ID if they are live themselves, live names must be unique.
// - Message ModSeq > 0, CreateSeq > 0, CreateSeq <= ModSeq.
// - All messages have a nonzero ThreadID, and no cycles in ThreadParentID, and parent messages the same ThreadParentIDs tail.
// - Annotations must have ModSeq > 0, CreateSeq > 0, ModSeq >= CreateSeq and live keys must be unique per mailbox.
// - Recalculate junk filter (words and counts) and check they are the same.
func (a *Account) CheckConsistency() error {
	a.Lock()
	defer a.Unlock()

	var uidErrors []string            // With a limit, could be many.
	var modseqErrors []string         // With limit.
	var fileErrors []string           // With limit.
	var threadidErrors []string       // With limit.
	var threadParentErrors []string   // With limit.
	var threadAncestorErrors []string // With limit.
	var errmsgs []string

	ctx := context.Background()
	log := mlog.New("store", nil)

	err := a.DB.Read(ctx, func(tx *bstore.Tx) error {
		nuv := NextUIDValidity{ID: 1}
		err := tx.Get(&nuv)
		if err != nil {
			return fmt.Errorf("fetching next uid validity: %v", err)
		}

		mailboxes := map[int64]Mailbox{}     // Also expunged mailboxes.
		mailboxNames := map[string]Mailbox{} // Only live names.
		err = bstore.QueryTx[Mailbox](tx).ForEach(func(mb Mailbox) error {
			mailboxes[mb.ID] = mb
			if !mb.Expunged {
				if xmb, ok := mailboxNames[mb.Name]; ok {
					errmsg := fmt.Sprintf("mailbox %q exists as id %d and id %d", mb.Name, mb.ID, xmb.ID)
					errmsgs = append(errmsgs, errmsg)
				}
				mailboxNames[mb.Name] = mb
			}

			if mb.UIDValidity >= nuv.Next {
				errmsg := fmt.Sprintf("mailbox %q (id %d) has uidvalidity %d >= account next uidvalidity %d", mb.Name, mb.ID, mb.UIDValidity, nuv.Next)
				errmsgs = append(errmsgs, errmsg)
			}

			if mb.ModSeq == 0 || mb.CreateSeq == 0 || mb.CreateSeq > mb.ModSeq {
				errmsg := fmt.Sprintf("mailbox %q (id %d) has invalid modseq %d or createseq %d, both must be > 0 and createseq <= modseq", mb.Name, mb.ID, mb.ModSeq, mb.CreateSeq)
				errmsgs = append(errmsgs, errmsg)
				return nil
			}
			m, err := bstore.QueryTx[Message](tx).FilterNonzero(Message{MailboxID: mb.ID}).SortDesc("ModSeq").Limit(1).Get()
			if err == bstore.ErrAbsent {
				return nil
			} else if err != nil {
				return fmt.Errorf("get message with highest modseq for mailbox: %v", err)
			} else if mb.ModSeq < m.ModSeq {
				errmsg := fmt.Sprintf("mailbox %q (id %d) has modseq %d < highest message modseq is %d", mb.Name, mb.ID, mb.ModSeq, m.ModSeq)
				errmsgs = append(errmsgs, errmsg)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("checking mailboxes: %v", err)
		}

		// Check ParentID and name of parent.
		for _, mb := range mailboxNames {
			if mox.ParentMailboxName(mb.Name) == "" {
				if mb.ParentID == 0 {
					continue
				}
				errmsg := fmt.Sprintf("mailbox %q (id %d) is a root mailbox but has parentid %d", mb.Name, mb.ID, mb.ParentID)
				errmsgs = append(errmsgs, errmsg)
			} else if mb.ParentID == 0 {
				errmsg := fmt.Sprintf("mailbox %q (id %d) is not a root mailbox but has a zero parentid", mb.Name, mb.ID)
				errmsgs = append(errmsgs, errmsg)
			} else if mox.ParentMailboxName(mb.Name) != mailboxes[mb.ParentID].Name {
				errmsg := fmt.Sprintf("mailbox %q (id %d) has parent mailbox id %d with name %q, but parent name should be %q", mb.Name, mb.ID, mb.ParentID, mailboxes[mb.ParentID].Name, mox.ParentMailboxName(mb.Name))
				errmsgs = append(errmsgs, errmsg)
			}
		}

		type annotation struct {
			mailboxID int64 // Can be 0.
			key       string
		}
		annotations := map[annotation]struct{}{}
		err = bstore.QueryTx[Annotation](tx).ForEach(func(a Annotation) error {
			if !a.Expunged {
				k := annotation{a.MailboxID, a.Key}
				if _, ok := annotations[k]; ok {
					errmsg := fmt.Sprintf("duplicate live annotation key %q for mailbox id %d", a.Key, a.MailboxID)
					errmsgs = append(errmsgs, errmsg)
				}
				annotations[k] = struct{}{}
			}
			if a.ModSeq == 0 || a.CreateSeq == 0 || a.CreateSeq > a.ModSeq {
				errmsg := fmt.Sprintf("annotation %d in mailbox %q (id %d) has invalid modseq %d or createseq %d, both must be > 0 and modseq >= createseq", a.ID, mailboxes[a.MailboxID].Name, a.MailboxID, a.ModSeq, a.CreateSeq)
				errmsgs = append(errmsgs, errmsg)
			} else if a.MailboxID > 0 && mailboxes[a.MailboxID].ModSeq < a.ModSeq {
				errmsg := fmt.Sprintf("annotation %d in mailbox %q (id %d) has invalid modseq %d > mailbox modseq %d", a.ID, mailboxes[a.MailboxID].Name, a.MailboxID, a.ModSeq, mailboxes[a.MailboxID].ModSeq)
				errmsgs = append(errmsgs, errmsg)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("checking mailbox annotations: %v", err)
		}

		// All message id's from database. For checking for unexpected files afterwards.
		messageIDs := map[int64]struct{}{}
		eraseMessageIDs := map[int64]bool{} // Value indicates whether to skip updating disk usage.

		// If configured, we'll be building up the junk filter for the messages, to compare
		// against the on-disk junk filter.
		var jf *junk.Filter
		conf, _ := a.Conf()
		if conf.JunkFilter != nil {
			random := make([]byte, 16)
			if _, err := cryptorand.Read(random); err != nil {
				return fmt.Errorf("reading random: %v", err)
			}
			dbpath := filepath.Join(mox.DataDirPath("tmp"), fmt.Sprintf("junkfilter-check-%x.db", random))
			bloompath := filepath.Join(mox.DataDirPath("tmp"), fmt.Sprintf("junkfilter-check-%x.bloom", random))
			os.MkdirAll(filepath.Dir(dbpath), 0700)
			defer func() {
				err := os.Remove(bloompath)
				log.Check(err, "removing temp bloom file")
				err = os.Remove(dbpath)
				log.Check(err, "removing temp junk filter database file")
			}()
			jf, err = junk.NewFilter(ctx, log, conf.JunkFilter.Params, dbpath, bloompath)
			if err != nil {
				return fmt.Errorf("new junk filter: %v", err)
			}
			defer func() {
				err := jf.Close()
				log.Check(err, "closing junk filter")
			}()
		}
		var ntrained int

		// Get IDs of erase messages not yet removed, they'll have a message file.
		err = bstore.QueryTx[MessageErase](tx).ForEach(func(me MessageErase) error {
			eraseMessageIDs[me.ID] = me.SkipUpdateDiskUsage
			return nil
		})
		if err != nil {
			return fmt.Errorf("listing message erase records")
		}

		counts := map[int64]MailboxCounts{}
		var totalExpungedSize int64
		err = bstore.QueryTx[Message](tx).ForEach(func(m Message) error {
			mc := counts[m.MailboxID]
			mc.Add(m.MailboxCounts())
			counts[m.MailboxID] = mc

			mb := mailboxes[m.MailboxID]

			if (!a.skipMessageZeroSeqCheck && (m.ModSeq == 0 || m.CreateSeq == 0) || m.CreateSeq > m.ModSeq) && len(modseqErrors) < 20 {
				modseqerr := fmt.Sprintf("message %d in mailbox %q (id %d) has invalid modseq %d or createseq %d, both must be > 0 and createseq <= modseq", m.ID, mb.Name, mb.ID, m.ModSeq, m.CreateSeq)
				modseqErrors = append(modseqErrors, modseqerr)
			}
			if m.UID >= mb.UIDNext && len(uidErrors) < 20 {
				uiderr := fmt.Sprintf("message %d in mailbox %q (id %d) has uid %d >= mailbox uidnext %d", m.ID, mb.Name, mb.ID, m.UID, mb.UIDNext)
				uidErrors = append(uidErrors, uiderr)
			}
			if m.Expunged {
				if skip := eraseMessageIDs[m.ID]; !skip {
					totalExpungedSize += m.Size
				}
				return nil
			}

			messageIDs[m.ID] = struct{}{}
			p := a.MessagePath(m.ID)
			st, err := os.Stat(p)
			if err != nil {
				existserr := fmt.Sprintf("message %d in mailbox %q (id %d) on-disk file %s: %v", m.ID, mb.Name, mb.ID, p, err)
				fileErrors = append(fileErrors, existserr)
			} else if len(fileErrors) < 20 && m.Size != int64(len(m.MsgPrefix))+st.Size() {
				sizeerr := fmt.Sprintf("message %d in mailbox %q (id %d) has size %d != len msgprefix %d + on-disk file size %d = %d", m.ID, mb.Name, mb.ID, m.Size, len(m.MsgPrefix), st.Size(), int64(len(m.MsgPrefix))+st.Size())
				fileErrors = append(fileErrors, sizeerr)
			}

			if m.ThreadID <= 0 && len(threadidErrors) < 20 {
				err := fmt.Sprintf("message %d in mailbox %q (id %d) has threadid 0", m.ID, mb.Name, mb.ID)
				threadidErrors = append(threadidErrors, err)
			}
			if slices.Contains(m.ThreadParentIDs, m.ID) && len(threadParentErrors) < 20 {
				err := fmt.Sprintf("message %d in mailbox %q (id %d) references itself in threadparentids", m.ID, mb.Name, mb.ID)
				threadParentErrors = append(threadParentErrors, err)
			}
			for i, pid := range m.ThreadParentIDs {
				am := Message{ID: pid}
				if err := tx.Get(&am); err == bstore.ErrAbsent || err == nil && am.Expunged {
					continue
				} else if err != nil {
					return fmt.Errorf("get ancestor message: %v", err)
				} else if !slices.Equal(m.ThreadParentIDs[i+1:], am.ThreadParentIDs) && len(threadAncestorErrors) < 20 {
					err := fmt.Sprintf("message %d, thread %d has ancestor ids %v, and ancestor at index %d with id %d should have the same tail but has %v\n", m.ID, m.ThreadID, m.ThreadParentIDs, i, am.ID, am.ThreadParentIDs)
					threadAncestorErrors = append(threadAncestorErrors, err)
				} else {
					break
				}
			}

			if jf != nil {
				if m.Junk != m.Notjunk {
					ntrained++
					if _, err := a.TrainMessage(ctx, log, jf, m.Notjunk, m); err != nil {
						return fmt.Errorf("train message: %v", err)
					}
					// We are not setting m.TrainedJunk, we were only recalculating the words.
				}
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("reading messages: %v", err)
		}

		msgdir := filepath.Join(a.Dir, "msg")
		err = filepath.WalkDir(msgdir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				if path == msgdir && errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if entry.IsDir() {
				return nil
			}
			id, err := strconv.ParseInt(filepath.Base(path), 10, 64)
			if err != nil {
				return fmt.Errorf("parsing message id from path %q: %v", path, err)
			}
			_, mok := messageIDs[id]
			_, meok := eraseMessageIDs[id]
			if !mok && !meok {
				return fmt.Errorf("unexpected message file %q", path)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking message dir: %v", err)
		}

		var totalMailboxSize int64
		for _, mb := range mailboxNames {
			totalMailboxSize += mb.Size
			if mb.MailboxCounts != counts[mb.ID] {
				mbcounterr := fmt.Sprintf("mailbox %q (id %d) has wrong counts %s, should be %s", mb.Name, mb.ID, mb.MailboxCounts, counts[mb.ID])
				errmsgs = append(errmsgs, mbcounterr)
			}
		}

		du := DiskUsage{ID: 1}
		if err := tx.Get(&du); err != nil {
			return fmt.Errorf("get diskusage")
		}
		if du.MessageSize != totalMailboxSize+totalExpungedSize {
			errmsg := fmt.Sprintf("total disk usage message size in database is %d != sum of mailbox message sizes %d + sum unerased expunged message sizes %d", du.MessageSize, totalMailboxSize, totalExpungedSize)
			errmsgs = append(errmsgs, errmsg)
		}

		// Compare on-disk junk filter with our recalculated filter.
		if jf != nil {
			load := func(f *junk.Filter) (map[junk.Wordscore]struct{}, error) {
				words := map[junk.Wordscore]struct{}{}
				err := bstore.QueryDB[junk.Wordscore](ctx, f.DB()).ForEach(func(w junk.Wordscore) error {
					if w.Ham != 0 || w.Spam != 0 {
						words[w] = struct{}{}
					}
					return nil
				})
				if err != nil {
					return nil, fmt.Errorf("read junk filter wordscores: %v", err)
				}
				return words, nil
			}
			if err := jf.Save(); err != nil {
				return fmt.Errorf("save recalculated junk filter: %v", err)
			}
			wordsExp, err := load(jf)
			if err != nil {
				return fmt.Errorf("read recalculated junk filter: %v", err)
			}

			ajf, _, err := a.OpenJunkFilter(ctx, log)
			if err != nil {
				return fmt.Errorf("open account junk filter: %v", err)
			}
			defer func() {
				err := ajf.Close()
				log.Check(err, "closing junk filter")
			}()
			wordsGot, err := load(ajf)
			if err != nil {
				return fmt.Errorf("read account junk filter: %v", err)
			}

			if !reflect.DeepEqual(wordsGot, wordsExp) {
				errmsg := fmt.Sprintf("unexpected values in junk filter, trained %d of %d\ngot:\n%v\nexpected:\n%v", ntrained, len(messageIDs), wordsGot, wordsExp)
				errmsgs = append(errmsgs, errmsg)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}
	errmsgs = append(errmsgs, uidErrors...)
	errmsgs = append(errmsgs, modseqErrors...)
	errmsgs = append(errmsgs, fileErrors...)
	errmsgs = append(errmsgs, threadidErrors...)
	errmsgs = append(errmsgs, threadParentErrors...)
	errmsgs = append(errmsgs, threadAncestorErrors...)
	if len(errmsgs) > 0 {
		return fmt.Errorf("%s", strings.Join(errmsgs, "; "))
	}
	return nil
}

// Conf returns the configuration for this account if it still exists. During
// an SMTP session, a configuration update may drop an account.
func (a *Account) Conf() (config.Account, bool) {
	return mox.Conf.Account(a.Name)
}

// NextUIDValidity returns the next new/unique uidvalidity to use for this account.
func (a *Account) NextUIDValidity(tx *bstore.Tx) (uint32, error) {
	nuv := NextUIDValidity{ID: 1}
	if err := tx.Get(&nuv); err != nil {
		return 0, err
	}
	v := nuv.Next
	nuv.Next++
	if err := tx.Update(&nuv); err != nil {
		return 0, err
	}
	return v, nil
}

// NextModSeq returns the next modification sequence, which is global per account,
// over all types.
func (a *Account) NextModSeq(tx *bstore.Tx) (ModSeq, error) {
	return nextModSeq(tx)
}

func nextModSeq(tx *bstore.Tx) (ModSeq, error) {
	v := SyncState{ID: 1}
	if err := tx.Get(&v); err == bstore.ErrAbsent {
		// We start assigning from modseq 2. Modseq 0 is not usable, so returned as 1, so
		// already used.
		// HighestDeletedModSeq is -1 so comparison against the default ModSeq zero value
		// makes sense.
		v = SyncState{1, 2, -1}
		return v.LastModSeq, tx.Insert(&v)
	} else if err != nil {
		return 0, err
	}
	v.LastModSeq++
	return v.LastModSeq, tx.Update(&v)
}

func (a *Account) HighestDeletedModSeq(tx *bstore.Tx) (ModSeq, error) {
	v := SyncState{ID: 1}
	err := tx.Get(&v)
	if err == bstore.ErrAbsent {
		return 0, nil
	}
	return v.HighestDeletedModSeq, err
}

// WithWLock runs fn with account writelock held. Necessary for account/mailbox
// modification. For message delivery, a read lock is required.
func (a *Account) WithWLock(fn func()) {
	a.Lock()
	defer a.Unlock()
	fn()
}

// WithRLock runs fn with account read lock held. Needed for message delivery.
func (a *Account) WithRLock(fn func()) {
	a.RLock()
	defer a.RUnlock()
	fn()
}

// AddOpts influence which work MessageAdd does. Some callers can batch
// checks/operations efficiently. For convenience and safety, a zero AddOpts does
// all the checks and work.
type AddOpts struct {
	SkipCheckQuota bool

	// If set, the message size is not added to the disk usage. Caller must do that,
	// e.g. for many messages at once. If used together with SkipCheckQuota, the
	// DiskUsage is not read for database when adding a message.
	SkipUpdateDiskUsage bool

	// Do not fsync the delivered message file. Useful when copying message files from
	// another mailbox. The hardlink created during delivery only needs a directory
	// fsync.
	SkipSourceFileSync bool

	// The directory in which the message file is delivered, typically with a hard
	// link, is not fsynced. Useful when delivering many files. A single or few
	// directory fsyncs are more efficient.
	SkipDirSync bool

	// Do not assign thread information to a message. Useful when importing many
	// messages and assigning threads efficiently after importing messages.
	SkipThreads bool

	// If JunkFilter is set, it is used for training. If not set, and the filter must
	// be trained for a message, the junk filter is opened, modified and saved to disk.
	JunkFilter *junk.Filter

	SkipTraining bool

	// If true, a preview will be generated if the Message doesn't already have one.
	SkipPreview bool
}

// todo optimization: when moving files, we open the original, call MessageAdd() which hardlinks it and close the file gain. when passing the filename, we could just use os.Link, saves 2 syscalls.

// MessageAdd delivers a mail message to the account.
//
// The file is hardlinked or copied, the caller must clean up the original file. If
// this call succeeds, but the database transaction with the change can't be
// committed, the caller must clean up the delivered message file identified by
// m.ID.
//
// If the message does not fit in the quota, an error with ErrOverQuota is returned
// and the mailbox and message are unchanged and the transaction can continue. For
// other errors, the caller must abort the transaction.
//
// The message, with msg.MsgPrefix and msgFile combined, must have a header
// section. The caller is responsible for adding a header separator to
// msg.MsgPrefix if missing from an incoming message.
//
// If UID is not set, it is assigned automatically.
//
// If the message ModSeq is zero, it is assigned automatically. If the message
// CreateSeq is zero, it is set to ModSeq. The mailbox ModSeq is set to the message
// ModSeq.
//
// If the message does not fit in the quota, an error with ErrOverQuota is returned
// and the mailbox and message are unchanged and the transaction can continue. For
// other errors, the caller must abort the transaction.
//
// If the destination mailbox has the Sent special-use flag, the message is parsed
// for its recipients (to/cc/bcc). Their domains are added to Recipients for use in
// reputation classification.
//
// Must be called with account write lock held.
//
// Caller must save the mailbox after MessageAdd returns, and broadcast changes for
// new the message, updated mailbox counts and possibly new mailbox keywords.
func (a *Account) MessageAdd(log mlog.Log, tx *bstore.Tx, mb *Mailbox, m *Message, msgFile *os.File, opts AddOpts) (rerr error) {
	if m.Expunged {
		return fmt.Errorf("cannot deliver expunged message")
	}

	if !opts.SkipUpdateDiskUsage || !opts.SkipCheckQuota {
		du := DiskUsage{ID: 1}
		if err := tx.Get(&du); err != nil {
			return fmt.Errorf("get disk usage: %v", err)
		}

		if !opts.SkipCheckQuota {
			maxSize := a.QuotaMessageSize()
			if maxSize > 0 && m.Size > maxSize-du.MessageSize {
				return fmt.Errorf("%w: max size %d bytes", ErrOverQuota, maxSize)
			}
		}

		if !opts.SkipUpdateDiskUsage {
			du.MessageSize += m.Size
			if err := tx.Update(&du); err != nil {
				return fmt.Errorf("update disk usage: %v", err)
			}
		}
	}

	m.MailboxID = mb.ID
	if m.MailboxOrigID == 0 {
		m.MailboxOrigID = mb.ID
	}
	if m.UID == 0 {
		m.UID = mb.UIDNext
		if err := mb.UIDNextAdd(1); err != nil {
			return fmt.Errorf("adding uid: %v", err)
		}
	}
	if m.ModSeq == 0 {
		modseq, err := a.NextModSeq(tx)
		if err != nil {
			return fmt.Errorf("assigning next modseq: %w", err)
		}
		m.ModSeq = modseq
	} else if m.ModSeq < mb.ModSeq {
		return fmt.Errorf("cannot deliver message with modseq %d < mailbox modseq %d", m.ModSeq, mb.ModSeq)
	}
	if m.CreateSeq == 0 {
		m.CreateSeq = m.ModSeq
	}
	mb.ModSeq = m.ModSeq

	if m.SaveDate == nil {
		now := time.Now()
		m.SaveDate = &now
	}
	if m.Received.IsZero() {
		m.Received = time.Now()
	}

	if len(m.Keywords) > 0 {
		mb.Keywords, _ = MergeKeywords(mb.Keywords, m.Keywords)
	}

	conf, _ := a.Conf()
	m.JunkFlagsForMailbox(*mb, conf)

	var part *message.Part
	if m.ParsedBuf == nil {
		mr := FileMsgReader(m.MsgPrefix, msgFile) // We don't close, it would close the msgFile.
		p, err := message.EnsurePart(log.Logger, false, mr, m.Size)
		if err != nil {
			log.Infox("parsing delivered message", err, slog.String("parse", ""), slog.Int64("message", m.ID))
			// We continue, p is still valid.
		}
		part = &p
		buf, err := json.Marshal(part)
		if err != nil {
			return fmt.Errorf("marshal parsed message: %w", err)
		}
		m.ParsedBuf = buf
	}

	var partTried bool
	getPart := func() *message.Part {
		if part != nil {
			return part
		}
		if partTried {
			return nil
		}
		partTried = true
		var p message.Part
		if err := json.Unmarshal(m.ParsedBuf, &p); err != nil {
			log.Errorx("unmarshal parsed message, continuing", err, slog.String("parse", ""))
		} else {
			mr := FileMsgReader(m.MsgPrefix, msgFile)
			p.SetReaderAt(mr)
			part = &p
		}
		return part
	}

	// If we are delivering to the originally intended mailbox, no need to store the mailbox ID again.
	if m.MailboxDestinedID != 0 && m.MailboxDestinedID == m.MailboxOrigID {
		m.MailboxDestinedID = 0
	}

	if m.MessageID == "" && m.SubjectBase == "" && getPart() != nil {
		m.PrepareThreading(log, part)
	}

	if !opts.SkipPreview && m.Preview == nil {
		if p := getPart(); p != nil {
			s, err := p.Preview(log)
			if err != nil {
				return fmt.Errorf("generating preview: %v", err)
			}
			m.Preview = &s
		}
	}

	// Assign to thread (if upgrade has completed).
	noThreadID := opts.SkipThreads
	if m.ThreadID == 0 && !opts.SkipThreads && getPart() != nil {
		select {
		case <-a.threadsCompleted:
			if a.threadsErr != nil {
				log.Info("not assigning threads for new delivery, upgrading to threads failed")
				noThreadID = true
			} else {
				if err := assignThread(log, tx, m, part); err != nil {
					return fmt.Errorf("assigning thread: %w", err)
				}
			}
		default:
			// note: since we have a write transaction to get here, we can't wait for the
			// thread upgrade to finish.
			// If we don't assign a threadid the upgrade process will do it.
			log.Info("not assigning threads for new delivery, upgrading to threads in progress which will assign this message")
			noThreadID = true
		}
	}

	if err := tx.Insert(m); err != nil {
		return fmt.Errorf("inserting message: %w", err)
	}
	if !noThreadID && m.ThreadID == 0 {
		m.ThreadID = m.ID
		if err := tx.Update(m); err != nil {
			return fmt.Errorf("updating message for its own thread id: %w", err)
		}
	}

	// todo: perhaps we should match the recipients based on smtp submission and a matching message-id? we now miss the addresses in bcc's if the mail client doesn't save a message that includes the bcc header in the sent mailbox.
	if mb.Sent && getPart() != nil && part.Envelope != nil {
		e := part.Envelope
		sent := e.Date
		if sent.IsZero() {
			sent = m.Received
		}
		if sent.IsZero() {
			sent = time.Now()
		}
		addrs := append(append(e.To, e.CC...), e.BCC...)
		for _, addr := range addrs {
			if addr.User == "" {
				// Would trigger error because Recipient.Localpart must be nonzero. todo: we could allow empty localpart in db, and filter by not using FilterNonzero.
				log.Info("to/cc/bcc address with empty localpart, not inserting as recipient", slog.Any("address", addr))
				continue
			}
			d, err := dns.ParseDomain(addr.Host)
			if err != nil {
				log.Debugx("parsing domain in to/cc/bcc address", err, slog.Any("address", addr))
				continue
			}
			lp, err := smtp.ParseLocalpart(addr.User)
			if err != nil {
				log.Debugx("parsing localpart in to/cc/bcc address", err, slog.Any("address", addr))
				continue
			}
			mr := Recipient{
				MessageID: m.ID,
				Localpart: lp.String(),
				Domain:    d.Name(),
				OrgDomain: publicsuffix.Lookup(context.TODO(), log.Logger, d).Name(),
				Sent:      sent,
			}
			if err := tx.Insert(&mr); err != nil {
				return fmt.Errorf("inserting sent message recipients: %w", err)
			}
		}
	}

	msgPath := a.MessagePath(m.ID)
	msgDir := filepath.Dir(msgPath)
	if a.lastMsgDir != msgDir {
		os.MkdirAll(msgDir, 0770)
		if err := moxio.SyncDir(log, msgDir); err != nil {
			return fmt.Errorf("sync message dir: %w", err)
		}
		a.lastMsgDir = msgDir
	}

	// Sync file data to disk.
	if !opts.SkipSourceFileSync {
		if err := msgFile.Sync(); err != nil {
			return fmt.Errorf("fsync message file: %w", err)
		}
	}

	if err := moxio.LinkOrCopy(log, msgPath, msgFile.Name(), &moxio.AtReader{R: msgFile}, true); err != nil {
		return fmt.Errorf("linking/copying message to new file: %w", err)
	}

	defer func() {
		if rerr != nil {
			err := os.Remove(msgPath)
			log.Check(err, "removing delivered message file", slog.String("path", msgPath))
		}
	}()

	if !opts.SkipDirSync {
		if err := moxio.SyncDir(log, msgDir); err != nil {
			return fmt.Errorf("sync directory: %w", err)
		}
	}

	if !opts.SkipTraining && m.NeedsTraining() && a.HasJunkFilter() {
		jf, opened, err := a.ensureJunkFilter(context.TODO(), log, opts.JunkFilter)
		if err != nil {
			return fmt.Errorf("open junk filter: %w", err)
		}
		defer func() {
			if jf != nil && opened {
				err := jf.CloseDiscard()
				log.Check(err, "closing junk filter without saving")
			}
		}()

		// todo optimize: should let us do the tx.Update of m if needed. we should at least merge it with the common case of setting a thread id. and we should try to merge that with the insert by expliciting getting the next id from bstore.

		if err := a.RetrainMessage(context.TODO(), log, tx, jf, m); err != nil {
			return fmt.Errorf("training junkfilter: %w", err)
		}

		if opened {
			err := jf.Close()
			jf = nil
			if err != nil {
				return fmt.Errorf("close junk filter: %w", err)
			}
		}
	}

	mb.MailboxCounts.Add(m.MailboxCounts())

	return nil
}

// SetPassword saves a new password for this account. This password is used for
// IMAP, SMTP (submission) sessions and the HTTP account web page.
//
// Callers are responsible for checking if the account has NoCustomPassword set.
func (a *Account) SetPassword(log mlog.Log, password string) error {
	password, err := precis.OpaqueString.String(password)
	if err != nil {
		return fmt.Errorf(`password not allowed by "precis"`)
	}

	if len(password) < 8 {
		// We actually check for bytes...
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generating password hash: %w", err)
	}

	err = a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		if _, err := bstore.QueryTx[Password](tx).Delete(); err != nil {
			return fmt.Errorf("deleting existing password: %v", err)
		}
		var pw Password
		pw.Hash = string(hash)

		// CRAM-MD5 calculates an HMAC-MD5, with the password as key, over a per-attempt
		// unique text that includes a timestamp. HMAC performs two hashes. Both times, the
		// first block is based on the key/password. We hash those first blocks now, and
		// store the hash state in the database. When we actually authenticate, we'll
		// complete the HMAC by hashing only the text. We cannot store crypto/hmac's hash,
		// because it does not expose its internal state and isn't a BinaryMarshaler.
		// ../rfc/2104:121
		pw.CRAMMD5.Ipad = md5.New()
		pw.CRAMMD5.Opad = md5.New()
		key := []byte(password)
		if len(key) > 64 {
			t := md5.Sum(key)
			key = t[:]
		}
		ipad := make([]byte, md5.BlockSize)
		opad := make([]byte, md5.BlockSize)
		copy(ipad, key)
		copy(opad, key)
		for i := range ipad {
			ipad[i] ^= 0x36
			opad[i] ^= 0x5c
		}
		pw.CRAMMD5.Ipad.Write(ipad)
		pw.CRAMMD5.Opad.Write(opad)

		pw.SCRAMSHA1.Salt = scram.MakeRandom()
		pw.SCRAMSHA1.Iterations = 2 * 4096
		pw.SCRAMSHA1.SaltedPassword = scram.SaltPassword(sha1.New, password, pw.SCRAMSHA1.Salt, pw.SCRAMSHA1.Iterations)

		pw.SCRAMSHA256.Salt = scram.MakeRandom()
		pw.SCRAMSHA256.Iterations = 4096
		pw.SCRAMSHA256.SaltedPassword = scram.SaltPassword(sha256.New, password, pw.SCRAMSHA256.Salt, pw.SCRAMSHA256.Iterations)

		if err := tx.Insert(&pw); err != nil {
			return fmt.Errorf("inserting new password: %v", err)
		}

		return sessionRemoveAll(context.TODO(), log, tx, a.Name)
	})
	if err == nil {
		log.Info("new password set for account", slog.String("account", a.Name))
	}
	return err
}

// SessionsClear invalidates all (web) login sessions for the account.
func (a *Account) SessionsClear(ctx context.Context, log mlog.Log) error {
	return a.DB.Write(ctx, func(tx *bstore.Tx) error {
		return sessionRemoveAll(ctx, log, tx, a.Name)
	})
}

// Subjectpass returns the signing key for use with subjectpass for the given
// email address with canonical localpart.
func (a *Account) Subjectpass(email string) (key string, err error) {
	return key, a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		v := Subjectpass{Email: email}
		err := tx.Get(&v)
		if err == nil {
			key = v.Key
			return nil
		}
		if !errors.Is(err, bstore.ErrAbsent) {
			return fmt.Errorf("get subjectpass key from accounts database: %w", err)
		}
		key = ""
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		buf := make([]byte, 16)
		if _, err := cryptorand.Read(buf); err != nil {
			return err
		}
		for _, b := range buf {
			key += string(chars[int(b)%len(chars)])
		}
		v.Key = key
		return tx.Insert(&v)
	})
}

// Ensure mailbox is present in database, adding records for the mailbox and its
// parents if they aren't present.
//
// If subscribe is true, any mailboxes that were created will also be subscribed to.
//
// The leaf mailbox is created with special-use flags, taking the flags away from
// other mailboxes, and reflecting that in the returned changes.
//
// Modseq is used, and initialized if 0, for created mailboxes.
//
// Name must be in normalized form, see CheckMailboxName.
//
// Caller must hold account wlock.
// Caller must propagate changes if any.
func (a *Account) MailboxEnsure(tx *bstore.Tx, name string, subscribe bool, specialUse SpecialUse, modseq *ModSeq) (mb Mailbox, changes []Change, rerr error) {
	if norm.NFC.String(name) != name {
		return Mailbox{}, nil, fmt.Errorf("mailbox name not normalized")
	}

	// Quick sanity check.
	if strings.EqualFold(name, "inbox") && name != "Inbox" {
		return Mailbox{}, nil, fmt.Errorf("bad casing for inbox")
	}

	// Get mailboxes with same name or prefix (parents).
	elems := strings.Split(name, "/")
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Expunged", false)
	q.FilterFn(func(xmb Mailbox) bool {
		t := strings.Split(xmb.Name, "/")
		return len(t) <= len(elems) && slices.Equal(t, elems[:len(t)])
	})
	l, err := q.List()
	if err != nil {
		return Mailbox{}, nil, fmt.Errorf("list mailboxes: %v", err)
	}

	mailboxes := map[string]Mailbox{}
	for _, xmb := range l {
		mailboxes[xmb.Name] = xmb
	}

	p := ""
	var exists bool
	var parentID int64
	for _, elem := range elems {
		if p != "" {
			p += "/"
		}
		p += elem
		mb, exists = mailboxes[p]
		if exists {
			parentID = mb.ID
			continue
		}
		uidval, err := a.NextUIDValidity(tx)
		if err != nil {
			return Mailbox{}, nil, fmt.Errorf("next uid validity: %v", err)
		}
		if *modseq == 0 {
			*modseq, err = a.NextModSeq(tx)
			if err != nil {
				return Mailbox{}, nil, fmt.Errorf("next modseq: %v", err)
			}
		}
		mb = Mailbox{
			CreateSeq:   *modseq,
			ModSeq:      *modseq,
			ParentID:    parentID,
			Name:        p,
			UIDValidity: uidval,
			UIDNext:     1,
			HaveCounts:  true,
		}
		err = tx.Insert(&mb)
		if err != nil {
			return Mailbox{}, nil, fmt.Errorf("creating new mailbox %q: %v", p, err)
		}
		parentID = mb.ID

		var flags []string
		if subscribe {
			if tx.Get(&Subscription{p}) != nil {
				err := tx.Insert(&Subscription{p})
				if err != nil {
					return Mailbox{}, nil, fmt.Errorf("subscribing to mailbox %q: %v", p, err)
				}
			}
			flags = []string{`\Subscribed`}
		} else if err := tx.Get(&Subscription{p}); err == nil {
			flags = []string{`\Subscribed`}
		} else if err != bstore.ErrAbsent {
			return Mailbox{}, nil, fmt.Errorf("looking up subscription for %q: %v", p, err)
		}

		changes = append(changes, ChangeAddMailbox{mb, flags})
	}

	// Clear any special-use flags from existing mailboxes and assign them to this mailbox.
	var zeroSpecialUse SpecialUse
	if !exists && specialUse != zeroSpecialUse {
		var qerr error
		clearSpecialUse := func(b bool, fn func(*Mailbox) *bool) {
			if !b || qerr != nil {
				return
			}
			qs := bstore.QueryTx[Mailbox](tx)
			qs.FilterFn(func(xmb Mailbox) bool {
				return *fn(&xmb)
			})
			xmb, err := qs.Get()
			if err == bstore.ErrAbsent {
				return
			} else if err != nil {
				qerr = fmt.Errorf("looking up mailbox with special-use flag: %v", err)
				return
			}
			p := fn(&xmb)
			*p = false
			xmb.ModSeq = *modseq
			if err := tx.Update(&xmb); err != nil {
				qerr = fmt.Errorf("clearing special-use flag: %v", err)
			} else {
				changes = append(changes, xmb.ChangeSpecialUse())
			}
		}
		clearSpecialUse(specialUse.Archive, func(xmb *Mailbox) *bool { return &xmb.Archive })
		clearSpecialUse(specialUse.Draft, func(xmb *Mailbox) *bool { return &xmb.Draft })
		clearSpecialUse(specialUse.Junk, func(xmb *Mailbox) *bool { return &xmb.Junk })
		clearSpecialUse(specialUse.Sent, func(xmb *Mailbox) *bool { return &xmb.Sent })
		clearSpecialUse(specialUse.Trash, func(xmb *Mailbox) *bool { return &xmb.Trash })
		if qerr != nil {
			return Mailbox{}, nil, qerr
		}

		mb.SpecialUse = specialUse
		mb.ModSeq = *modseq
		if err := tx.Update(&mb); err != nil {
			return Mailbox{}, nil, fmt.Errorf("setting special-use flag for new mailbox: %v", err)
		}
		changes = append(changes, mb.ChangeSpecialUse())
	}
	return mb, changes, nil
}

// MailboxExists checks if mailbox exists.
// Caller must hold account rlock.
func (a *Account) MailboxExists(tx *bstore.Tx, name string) (bool, error) {
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Expunged", false)
	q.FilterEqual("Name", name)
	return q.Exists()
}

// MailboxFind finds a mailbox by name, returning a nil mailbox and nil error if mailbox does not exist.
func (a *Account) MailboxFind(tx *bstore.Tx, name string) (*Mailbox, error) {
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Expunged", false)
	q.FilterEqual("Name", name)
	mb, err := q.Get()
	if err == bstore.ErrAbsent {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up mailbox: %w", err)
	}
	return &mb, nil
}

// SubscriptionEnsure ensures a subscription for name exists. The mailbox does not
// have to exist. Any parents are not automatically subscribed.
// Changes are returned and must be broadcasted by the caller.
func (a *Account) SubscriptionEnsure(tx *bstore.Tx, name string) ([]Change, error) {
	if err := tx.Get(&Subscription{name}); err == nil {
		return nil, nil
	}

	if err := tx.Insert(&Subscription{name}); err != nil {
		return nil, fmt.Errorf("inserting subscription: %w", err)
	}

	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Expunged", false)
	q.FilterEqual("Name", name)
	_, err := q.Get()
	if err == nil {
		return []Change{ChangeAddSubscription{name, nil}}, nil
	} else if err != bstore.ErrAbsent {
		return nil, fmt.Errorf("looking up mailbox for subscription: %w", err)
	}
	return []Change{ChangeAddSubscription{name, []string{`\NonExistent`}}}, nil
}

// MessageRuleset returns the first ruleset (if any) that matches the message
// represented by msgPrefix and msgFile, with smtp and validation fields from m.
func MessageRuleset(log mlog.Log, dest config.Destination, m *Message, msgPrefix []byte, msgFile *os.File) *config.Ruleset {
	if len(dest.Rulesets) == 0 {
		return nil
	}

	mr := FileMsgReader(msgPrefix, msgFile) // We don't close, it would close the msgFile.
	p, err := message.Parse(log.Logger, false, mr)
	if err != nil {
		log.Errorx("parsing message for evaluating rulesets, continuing with headers", err, slog.String("parse", ""))
		// note: part is still set.
	}
	// todo optimize: only parse header if needed for rulesets. and probably reuse an earlier parsing.
	header, err := p.Header()
	if err != nil {
		log.Errorx("parsing message headers for evaluating rulesets, delivering to default mailbox", err, slog.String("parse", ""))
		// todo: reject message?
		return nil
	}

ruleset:
	for _, rs := range dest.Rulesets {
		if rs.SMTPMailFromRegexpCompiled != nil {
			if !rs.SMTPMailFromRegexpCompiled.MatchString(m.MailFrom) {
				continue ruleset
			}
		}
		if rs.MsgFromRegexpCompiled != nil {
			if m.MsgFromLocalpart == "" && m.MsgFromDomain == "" || !rs.MsgFromRegexpCompiled.MatchString(m.MsgFromLocalpart.String()+"@"+m.MsgFromDomain) {
				continue ruleset
			}
		}

		if !rs.VerifiedDNSDomain.IsZero() {
			d := rs.VerifiedDNSDomain.Name()
			suffix := "." + d
			matchDomain := func(s string) bool {
				return s == d || strings.HasSuffix(s, suffix)
			}
			var ok bool
			if m.EHLOValidated && matchDomain(m.EHLODomain) {
				ok = true
			}
			if m.MailFromValidated && matchDomain(m.MailFromDomain) {
				ok = true
			}
			for _, d := range m.DKIMDomains {
				if matchDomain(d) {
					ok = true
					break
				}
			}
			if !ok {
				continue ruleset
			}
		}

	header:
		for _, t := range rs.HeadersRegexpCompiled {
			for k, vl := range header {
				k = strings.ToLower(k)
				if !t[0].MatchString(k) {
					continue
				}
				for _, v := range vl {
					v = strings.ToLower(strings.TrimSpace(v))
					if t[1].MatchString(v) {
						continue header
					}
				}
			}
			continue ruleset
		}
		return &rs
	}
	return nil
}

// MessagePath returns the file system path of a message.
func (a *Account) MessagePath(messageID int64) string {
	return strings.Join(append([]string{a.Dir, "msg"}, messagePathElems(messageID)...), string(filepath.Separator))
}

// MessageReader opens a message for reading, transparently combining the
// message prefix with the original incoming message.
func (a *Account) MessageReader(m Message) *MsgReader {
	return &MsgReader{prefix: m.MsgPrefix, path: a.MessagePath(m.ID), size: m.Size}
}

// DeliverDestination delivers an email to dest, based on the configured rulesets.
//
// Returns ErrOverQuota when account would be over quota after adding message.
//
// Caller must hold account wlock (mailbox may be created).
// Message delivery, possible mailbox creation, and updated mailbox counts are
// broadcasted.
func (a *Account) DeliverDestination(log mlog.Log, dest config.Destination, m *Message, msgFile *os.File) error {
	var mailbox string
	rs := MessageRuleset(log, dest, m, m.MsgPrefix, msgFile)
	if rs != nil {
		mailbox = rs.Mailbox
	} else if dest.Mailbox == "" {
		mailbox = "Inbox"
	} else {
		mailbox = dest.Mailbox
	}
	return a.DeliverMailbox(log, mailbox, m, msgFile)
}

// DeliverMailbox delivers an email to the specified mailbox.
//
// Returns ErrOverQuota when account would be over quota after adding message.
//
// Caller must hold account wlock (mailbox may be created).
// Message delivery, possible mailbox creation, and updated mailbox counts are
// broadcasted.
func (a *Account) DeliverMailbox(log mlog.Log, mailbox string, m *Message, msgFile *os.File) (rerr error) {
	var changes []Change

	var commit bool
	defer func() {
		if !commit && m.ID != 0 {
			p := a.MessagePath(m.ID)
			err := os.Remove(p)
			log.Check(err, "remove delivered message file", slog.String("path", p))
			m.ID = 0
		}
	}()

	err := a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		mb, chl, err := a.MailboxEnsure(tx, mailbox, true, SpecialUse{}, &m.ModSeq)
		if err != nil {
			return fmt.Errorf("ensuring mailbox: %w", err)
		}
		if m.CreateSeq == 0 {
			m.CreateSeq = m.ModSeq
		}

		nmbkeywords := len(mb.Keywords)

		if err := a.MessageAdd(log, tx, &mb, m, msgFile, AddOpts{}); err != nil {
			return err
		}

		if err := tx.Update(&mb); err != nil {
			return fmt.Errorf("updating mailbox for delivery: %w", err)
		}

		changes = append(changes, chl...)
		changes = append(changes, m.ChangeAddUID(mb), mb.ChangeCounts())
		if nmbkeywords != len(mb.Keywords) {
			changes = append(changes, mb.ChangeKeywords())
		}
		return nil
	})
	if err != nil {
		return err
	}
	commit = true
	BroadcastChanges(a, changes)
	return nil
}

type RemoveOpts struct {
	JunkFilter *junk.Filter // If set, this filter is used for training, instead of opening and saving the junk filter.
}

// MessageRemove markes messages as expunged, updates mailbox counts for the
// messages, sets a new modseq on the messages and mailbox, untrains the junk
// filter and queues the messages for erasing when the last reference has gone.
//
// Caller must save the modified mailbox to the database.
//
// The disk usage is not immediately updated. That will happen when the message
// is actually removed from disk.
//
// The junk filter is untrained for the messages if it was trained.
// Useful as optimization when messages are moved and the junk/nonjunk flags do not
// change (which can happen due to automatic junk/nonjunk flags for mailboxes).
//
// An empty list of messages results in an error.
//
// Caller must broadcast changes.
//
// Must be called with wlock held.
func (a *Account) MessageRemove(log mlog.Log, tx *bstore.Tx, modseq ModSeq, mb *Mailbox, opts RemoveOpts, l ...Message) (chremuids ChangeRemoveUIDs, chmbc ChangeMailboxCounts, rerr error) {
	if len(l) == 0 {
		return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("must expunge at least one message")
	}

	mb.ModSeq = modseq

	// Remove any message recipients.
	anyIDs := make([]any, len(l))
	for i, m := range l {
		anyIDs[i] = m.ID
	}
	qmr := bstore.QueryTx[Recipient](tx)
	qmr.FilterEqual("MessageID", anyIDs...)
	if _, err := qmr.Delete(); err != nil {
		return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("deleting message recipients for messages: %w", err)
	}

	// Loaded lazily.
	jf := opts.JunkFilter

	// Mark messages expunged.
	ids := make([]int64, 0, len(l))
	uids := make([]UID, 0, len(l))
	for _, m := range l {
		ids = append(ids, m.ID)
		uids = append(uids, m.UID)

		if m.Expunged {
			return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("message %d is already expunged", m.ID)
		}

		mb.Sub(m.MailboxCounts())

		m.ModSeq = modseq
		m.Expunged = true
		m.Junk = false
		m.Notjunk = false

		if err := tx.Update(&m); err != nil {
			return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("marking message %d expunged: %v", m.ID, err)
		}

		// Ensure message gets erased in future.
		if err := tx.Insert(&MessageErase{m.ID, false}); err != nil {
			return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("inserting message erase %d : %v", m.ID, err)
		}

		if m.TrainedJunk == nil || !a.HasJunkFilter() {
			continue
		}
		// Untrain, as needed by updated flags Junk/Notjunk to false.
		if jf == nil {
			var err error
			jf, _, err = a.OpenJunkFilter(context.TODO(), log)
			if err != nil {
				return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("open junk filter: %v", err)
			}
			defer func() {
				err := jf.Close()
				if rerr == nil {
					rerr = err
				} else {
					log.Check(err, "closing junk filter")
				}
			}()
		}
		if err := a.RetrainMessage(context.TODO(), log, tx, jf, &m); err != nil {
			return ChangeRemoveUIDs{}, ChangeMailboxCounts{}, fmt.Errorf("retraining expunged messages: %w", err)
		}
	}

	return ChangeRemoveUIDs{mb.ID, uids, modseq, ids, mb.UIDNext, mb.MessageCountIMAP(), uint32(mb.MailboxCounts.Unseen)}, mb.ChangeCounts(), nil
}

// TidyRejectsMailbox removes old reject emails, and returns whether there is space for a new delivery.
//
// The changed mailbox is saved to the database.
//
// Caller most hold account wlock.
// Caller must broadcast changes.
func (a *Account) TidyRejectsMailbox(log mlog.Log, tx *bstore.Tx, mbRej *Mailbox) (changes []Change, hasSpace bool, rerr error) {
	// Gather old messages to expunge.
	old := time.Now().Add(-14 * 24 * time.Hour)
	qdel := bstore.QueryTx[Message](tx)
	qdel.FilterNonzero(Message{MailboxID: mbRej.ID})
	qdel.FilterEqual("Expunged", false)
	qdel.FilterLess("Received", old)
	qdel.SortAsc("UID")
	expunge, err := qdel.List()
	if err != nil {
		return nil, false, fmt.Errorf("listing old messages: %w", err)
	}

	if len(expunge) > 0 {
		modseq, err := a.NextModSeq(tx)
		if err != nil {
			return nil, false, fmt.Errorf("next mod seq: %v", err)
		}

		chremuids, chmbcounts, err := a.MessageRemove(log, tx, modseq, mbRej, RemoveOpts{}, expunge...)
		if err != nil {
			return nil, false, fmt.Errorf("removing messages: %w", err)
		}
		if err := tx.Update(mbRej); err != nil {
			return nil, false, fmt.Errorf("updating mailbox: %v", err)
		}
		changes = append(changes, chremuids, chmbcounts)
	}

	// We allow up to n messages.
	qcount := bstore.QueryTx[Message](tx)
	qcount.FilterNonzero(Message{MailboxID: mbRej.ID})
	qcount.FilterEqual("Expunged", false)
	qcount.Limit(1000)
	n, err := qcount.Count()
	if err != nil {
		return nil, false, fmt.Errorf("counting rejects: %w", err)
	}
	hasSpace = n < 1000

	return changes, hasSpace, nil
}

// RejectsRemove removes a message from the rejects mailbox if present.
//
// Caller most hold account wlock.
// Changes are broadcasted.
func (a *Account) RejectsRemove(log mlog.Log, rejectsMailbox, messageID string) error {
	var changes []Change

	err := a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		mb, err := a.MailboxFind(tx, rejectsMailbox)
		if err != nil {
			return fmt.Errorf("finding mailbox: %w", err)
		}
		if mb == nil {
			return nil
		}

		q := bstore.QueryTx[Message](tx)
		q.FilterNonzero(Message{MailboxID: mb.ID, MessageID: messageID})
		q.FilterEqual("Expunged", false)
		expunge, err := q.List()
		if err != nil {
			return fmt.Errorf("listing messages to remove: %w", err)
		}

		if len(expunge) == 0 {
			return nil
		}

		modseq, err := a.NextModSeq(tx)
		if err != nil {
			return fmt.Errorf("get next mod seq: %v", err)
		}

		chremuids, chmbcounts, err := a.MessageRemove(log, tx, modseq, mb, RemoveOpts{}, expunge...)
		if err != nil {
			return fmt.Errorf("removing messages: %w", err)
		}
		changes = append(changes, chremuids, chmbcounts)

		if err := tx.Update(mb); err != nil {
			return fmt.Errorf("saving mailbox: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	BroadcastChanges(a, changes)

	return nil
}

// AddMessageSize adjusts the DiskUsage.MessageSize by size.
func (a *Account) AddMessageSize(log mlog.Log, tx *bstore.Tx, size int64) error {
	du := DiskUsage{ID: 1}
	if err := tx.Get(&du); err != nil {
		return fmt.Errorf("get diskusage: %v", err)
	}
	du.MessageSize += size
	if du.MessageSize < 0 {
		log.Error("negative total message size", slog.Int64("delta", size), slog.Int64("newtotalsize", du.MessageSize))
	}
	if err := tx.Update(&du); err != nil {
		return fmt.Errorf("update total message size: %v", err)
	}
	return nil
}

// QuotaMessageSize returns the effective maximum total message size for an
// account. Returns 0 if there is no maximum.
func (a *Account) QuotaMessageSize() int64 {
	conf, _ := a.Conf()
	size := conf.QuotaMessageSize
	if size == 0 {
		size = mox.Conf.Static.QuotaMessageSize
	}
	if size < 0 {
		size = 0
	}
	return size
}

// CanAddMessageSize checks if a message of size bytes can be added, depending on
// total message size and configured quota for account.
func (a *Account) CanAddMessageSize(tx *bstore.Tx, size int64) (ok bool, maxSize int64, err error) {
	maxSize = a.QuotaMessageSize()
	if maxSize <= 0 {
		return true, 0, nil
	}

	du := DiskUsage{ID: 1}
	if err := tx.Get(&du); err != nil {
		return false, maxSize, fmt.Errorf("get diskusage: %v", err)
	}
	return du.MessageSize+size <= maxSize, maxSize, nil
}

// We keep a cache of recent successful authentications, so we don't have to bcrypt successful calls each time.
var authCache = struct {
	sync.Mutex
	success map[authKey]string
}{
	success: map[authKey]string{},
}

type authKey struct {
	email, hash string
}

// StartAuthCache starts a goroutine that regularly clears the auth cache.
func StartAuthCache() {
	go manageAuthCache()
}

func manageAuthCache() {
	for {
		authCache.Lock()
		authCache.success = map[authKey]string{}
		authCache.Unlock()
		time.Sleep(15 * time.Minute)
	}
}

// OpenEmailAuth opens an account given an email address and password.
//
// The email address may contain a catchall separator.
// For invalid credentials, a nil account is returned, but accName may be
// non-empty.
func OpenEmailAuth(log mlog.Log, email string, password string, checkLoginDisabled bool) (racc *Account, raccName string, rerr error) {
	// We check for LoginDisabled after verifying the password. Otherwise users can get
	// messages about the account being disabled without knowing the password.
	acc, accName, _, err := OpenEmail(log, email, false)
	if err != nil {
		return nil, "", err
	}

	defer func() {
		if rerr != nil {
			err := acc.Close()
			log.Check(err, "closing account after open auth failure")
			acc = nil
		}
	}()

	password, err = precis.OpaqueString.String(password)
	if err != nil {
		return nil, "", ErrUnknownCredentials
	}

	pw, err := bstore.QueryDB[Password](context.TODO(), acc.DB).Get()
	if err != nil {
		if err == bstore.ErrAbsent {
			return nil, "", ErrUnknownCredentials
		}
		return nil, "", fmt.Errorf("looking up password: %v", err)
	}
	authCache.Lock()
	ok := len(password) >= 8 && authCache.success[authKey{email, pw.Hash}] == password
	authCache.Unlock()
	if !ok {
		if err := bcrypt.CompareHashAndPassword([]byte(pw.Hash), []byte(password)); err != nil {
			return nil, "", ErrUnknownCredentials
		}
	}
	if checkLoginDisabled {
		conf, aok := acc.Conf()
		if !aok {
			return nil, "", fmt.Errorf("cannot find config for account")
		} else if conf.LoginDisabled != "" {
			return nil, "", fmt.Errorf("%w: %s", ErrLoginDisabled, conf.LoginDisabled)
		}
	}
	authCache.Lock()
	authCache.success[authKey{email, pw.Hash}] = password
	authCache.Unlock()
	return acc, accName, nil
}

// OpenEmail opens an account given an email address.
//
// The email address may contain a catchall separator.
//
// Returns account on success, may return non-empty account name even on error.
func OpenEmail(log mlog.Log, email string, checkLoginDisabled bool) (*Account, string, config.Destination, error) {
	addr, err := smtp.ParseAddress(email)
	if err != nil {
		return nil, "", config.Destination{}, fmt.Errorf("%w: %v", ErrUnknownCredentials, err)
	}
	accountName, _, _, dest, err := mox.LookupAddress(addr.Localpart, addr.Domain, false, false, false)
	if err != nil && (errors.Is(err, mox.ErrAddressNotFound) || errors.Is(err, mox.ErrDomainNotFound)) {
		return nil, accountName, config.Destination{}, ErrUnknownCredentials
	} else if err != nil {
		return nil, accountName, config.Destination{}, fmt.Errorf("looking up address: %v", err)
	}
	acc, err := OpenAccount(log, accountName, checkLoginDisabled)
	if err != nil {
		return nil, accountName, config.Destination{}, err
	}
	return acc, accountName, dest, nil
}

// We store max 1<<shift files in each subdir of an account "msg" directory.
// Defaults to 1 for easy use in tests. Set to 13, for 8k message files, in main
// for normal operation.
var msgFilesPerDirShift = 1
var msgFilesPerDir int64 = 1 << msgFilesPerDirShift

func MsgFilesPerDirShiftSet(shift int) {
	msgFilesPerDirShift = shift
	msgFilesPerDir = 1 << shift
}

// 64 characters, must be power of 2 for MessagePath
const msgDirChars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// MessagePath returns the filename of the on-disk filename, relative to the
// containing directory such as <account>/msg or queue.
// Returns names like "AB/1".
func MessagePath(messageID int64) string {
	return strings.Join(messagePathElems(messageID), string(filepath.Separator))
}

// messagePathElems returns the elems, for a single join without intermediate
// string allocations.
func messagePathElems(messageID int64) []string {
	v := messageID >> msgFilesPerDirShift
	dir := ""
	for {
		dir += string(msgDirChars[int(v)&(len(msgDirChars)-1)])
		v >>= 6
		if v == 0 {
			break
		}
	}
	return []string{dir, strconv.FormatInt(messageID, 10)}
}

// Set returns a copy of f, with each flag that is true in mask set to the
// value from flags.
func (f Flags) Set(mask, flags Flags) Flags {
	set := func(d *bool, m, v bool) {
		if m {
			*d = v
		}
	}
	r := f
	set(&r.Seen, mask.Seen, flags.Seen)
	set(&r.Answered, mask.Answered, flags.Answered)
	set(&r.Flagged, mask.Flagged, flags.Flagged)
	set(&r.Forwarded, mask.Forwarded, flags.Forwarded)
	set(&r.Junk, mask.Junk, flags.Junk)
	set(&r.Notjunk, mask.Notjunk, flags.Notjunk)
	set(&r.Deleted, mask.Deleted, flags.Deleted)
	set(&r.Draft, mask.Draft, flags.Draft)
	set(&r.Phishing, mask.Phishing, flags.Phishing)
	set(&r.MDNSent, mask.MDNSent, flags.MDNSent)
	return r
}

// Changed returns a mask of flags that have been between f and other.
func (f Flags) Changed(other Flags) (mask Flags) {
	mask.Seen = f.Seen != other.Seen
	mask.Answered = f.Answered != other.Answered
	mask.Flagged = f.Flagged != other.Flagged
	mask.Forwarded = f.Forwarded != other.Forwarded
	mask.Junk = f.Junk != other.Junk
	mask.Notjunk = f.Notjunk != other.Notjunk
	mask.Deleted = f.Deleted != other.Deleted
	mask.Draft = f.Draft != other.Draft
	mask.Phishing = f.Phishing != other.Phishing
	mask.MDNSent = f.MDNSent != other.MDNSent
	return
}

// Strings returns the flags that are set in their string form.
func (f Flags) Strings() []string {
	fields := []struct {
		word string
		have bool
	}{
		{`$forwarded`, f.Forwarded},
		{`$junk`, f.Junk},
		{`$mdnsent`, f.MDNSent},
		{`$notjunk`, f.Notjunk},
		{`$phishing`, f.Phishing},
		{`\answered`, f.Answered},
		{`\deleted`, f.Deleted},
		{`\draft`, f.Draft},
		{`\flagged`, f.Flagged},
		{`\seen`, f.Seen},
	}
	var l []string
	for _, fh := range fields {
		if fh.have {
			l = append(l, fh.word)
		}
	}
	return l
}

var systemWellKnownFlags = map[string]bool{
	`\answered`:  true,
	`\flagged`:   true,
	`\deleted`:   true,
	`\seen`:      true,
	`\draft`:     true,
	`$junk`:      true,
	`$notjunk`:   true,
	`$forwarded`: true,
	`$phishing`:  true,
	`$mdnsent`:   true,
}

// ParseFlagsKeywords parses a list of textual flags into system/known flags, and
// other keywords. Keywords are lower-cased and sorted and check for valid syntax.
func ParseFlagsKeywords(l []string) (flags Flags, keywords []string, rerr error) {
	fields := map[string]*bool{
		`\answered`:  &flags.Answered,
		`\flagged`:   &flags.Flagged,
		`\deleted`:   &flags.Deleted,
		`\seen`:      &flags.Seen,
		`\draft`:     &flags.Draft,
		`$junk`:      &flags.Junk,
		`$notjunk`:   &flags.Notjunk,
		`$forwarded`: &flags.Forwarded,
		`$phishing`:  &flags.Phishing,
		`$mdnsent`:   &flags.MDNSent,
	}
	seen := map[string]bool{}
	for _, f := range l {
		f = strings.ToLower(f)
		if field, ok := fields[f]; ok {
			*field = true
		} else if seen[f] {
			if mox.Pedantic {
				return Flags{}, nil, fmt.Errorf("duplicate keyword %s", f)
			}
		} else {
			if err := CheckKeyword(f); err != nil {
				return Flags{}, nil, fmt.Errorf("invalid keyword %s", f)
			}
			keywords = append(keywords, f)
			seen[f] = true
		}
	}
	sort.Strings(keywords)
	return flags, keywords, nil
}

// RemoveKeywords removes keywords from l, returning whether any modifications were
// made, and a slice, a new slice in case of modifications. Keywords must have been
// validated earlier, e.g. through ParseFlagKeywords or CheckKeyword. Should only
// be used with valid keywords, not with system flags like \Seen.
func RemoveKeywords(l, remove []string) ([]string, bool) {
	var copied bool
	var changed bool
	for _, k := range remove {
		if i := slices.Index(l, k); i >= 0 {
			if !copied {
				l = slices.Clone(l)
				copied = true
			}
			copy(l[i:], l[i+1:])
			l = l[:len(l)-1]
			changed = true
		}
	}
	return l, changed
}

// MergeKeywords adds keywords from add into l, returning whether it added any
// keyword, and the slice with keywords, a new slice if modifications were made.
// Keywords are only added if they aren't already present. Should only be used with
// keywords, not with system flags like \Seen.
func MergeKeywords(l, add []string) ([]string, bool) {
	var copied bool
	var changed bool
	for _, k := range add {
		if !slices.Contains(l, k) {
			if !copied {
				l = slices.Clone(l)
				copied = true
			}
			l = append(l, k)
			changed = true
		}
	}
	if changed {
		sort.Strings(l)
	}
	return l, changed
}

// CheckKeyword returns an error if kw is not a valid keyword. Kw should
// already be in lower-case.
func CheckKeyword(kw string) error {
	if kw == "" {
		return fmt.Errorf("keyword cannot be empty")
	}
	if systemWellKnownFlags[kw] {
		return fmt.Errorf("cannot use well-known flag as keyword")
	}
	for _, c := range kw {
		// ../rfc/9051:6334
		if c <= ' ' || c > 0x7e || c >= 'A' && c <= 'Z' || strings.ContainsRune(`(){%*"\]`, c) {
			return errors.New(`not a valid keyword, must be lower-case ascii without spaces and without any of these characters: (){%*"\]`)
		}
	}
	return nil
}

// SendLimitReached checks whether sending a message to recipients would reach
// the limit of outgoing messages for the account. If so, the message should
// not be sent. If the returned numbers are >= 0, the limit was reached and the
// values are the configured limits.
//
// To limit damage to the internet and our reputation in case of account
// compromise, we limit the max number of messages sent in a 24 hour window, both
// total number of messages and number of first-time recipients.
func (a *Account) SendLimitReached(tx *bstore.Tx, recipients []smtp.Path) (msglimit, rcptlimit int, rerr error) {
	conf, _ := a.Conf()
	msgmax := conf.MaxOutgoingMessagesPerDay
	if msgmax == 0 {
		// For human senders, 1000 recipients in a day is quite a lot.
		msgmax = 1000
	}
	rcptmax := conf.MaxFirstTimeRecipientsPerDay
	if rcptmax == 0 {
		// Human senders may address a new human-sized list of people once in a while. In
		// case of a compromise, a spammer will probably try to send to many new addresses.
		rcptmax = 200
	}

	rcpts := map[string]time.Time{}
	n := 0
	err := bstore.QueryTx[Outgoing](tx).FilterGreater("Submitted", time.Now().Add(-24*time.Hour)).ForEach(func(o Outgoing) error {
		n++
		if rcpts[o.Recipient].IsZero() || o.Submitted.Before(rcpts[o.Recipient]) {
			rcpts[o.Recipient] = o.Submitted
		}
		return nil
	})
	if err != nil {
		return -1, -1, fmt.Errorf("querying message recipients in past 24h: %w", err)
	}
	if n+len(recipients) > msgmax {
		return msgmax, -1, nil
	}

	// Only check if max first-time recipients is reached if there are enough messages
	// to trigger the limit.
	if n+len(recipients) < rcptmax {
		return -1, -1, nil
	}

	isFirstTime := func(rcpt string, before time.Time) (bool, error) {
		exists, err := bstore.QueryTx[Outgoing](tx).FilterNonzero(Outgoing{Recipient: rcpt}).FilterLess("Submitted", before).Exists()
		return !exists, err
	}

	firsttime := 0
	now := time.Now()
	for _, r := range recipients {
		if first, err := isFirstTime(r.XString(true), now); err != nil {
			return -1, -1, fmt.Errorf("checking whether recipient is first-time: %v", err)
		} else if first {
			firsttime++
		}
	}
	for r, t := range rcpts {
		if first, err := isFirstTime(r, t); err != nil {
			return -1, -1, fmt.Errorf("checking whether recipient is first-time: %v", err)
		} else if first {
			firsttime++
		}
	}
	if firsttime > rcptmax {
		return -1, rcptmax, nil
	}
	return -1, -1, nil
}

var ErrMailboxExpunged = errors.New("mailbox was deleted")

// MailboxID gets a mailbox by ID.
//
// Returns bstore.ErrAbsent if the mailbox does not exist.
// Returns ErrMailboxExpunged if the mailbox is expunged.
func MailboxID(tx *bstore.Tx, id int64) (Mailbox, error) {
	mb := Mailbox{ID: id}
	err := tx.Get(&mb)
	if err == nil && mb.Expunged {
		return Mailbox{}, ErrMailboxExpunged
	}
	return mb, err
}

// MailboxCreate creates a new mailbox, including any missing parent mailboxes,
// the total list of created mailboxes is returned in created. On success, if
// exists is false and rerr nil, the changes must be broadcasted by the caller.
//
// The mailbox is created with special-use flags, with those flags taken away from
// other mailboxes if they have them, reflected in the returned changes.
//
// Name must be in normalized form, see CheckMailboxName.
func (a *Account) MailboxCreate(tx *bstore.Tx, name string, specialUse SpecialUse) (nmb Mailbox, changes []Change, created []string, exists bool, rerr error) {
	elems := strings.Split(name, "/")
	var p string
	var modseq ModSeq
	for i, elem := range elems {
		if i > 0 {
			p += "/"
		}
		p += elem
		exists, err := a.MailboxExists(tx, p)
		if err != nil {
			return Mailbox{}, nil, nil, false, fmt.Errorf("checking if mailbox exists")
		}
		if exists {
			if i == len(elems)-1 {
				return Mailbox{}, nil, nil, true, fmt.Errorf("mailbox already exists")
			}
			continue
		}
		mb, nchanges, err := a.MailboxEnsure(tx, p, true, specialUse, &modseq)
		if err != nil {
			return Mailbox{}, nil, nil, false, fmt.Errorf("ensuring mailbox exists: %v", err)
		}
		nmb = mb
		changes = append(changes, nchanges...)
		created = append(created, p)
	}
	return nmb, changes, created, false, nil
}

// MailboxRename renames mailbox mbsrc to dst, including children of mbsrc, and
// adds missing parents for dst.
//
// Name must be in normalized form, see CheckMailboxName, and cannot be Inbox.
func (a *Account) MailboxRename(tx *bstore.Tx, mbsrc *Mailbox, dst string, modseq *ModSeq) (changes []Change, isInbox, alreadyExists bool, rerr error) {
	if mbsrc.Name == "Inbox" || dst == "Inbox" {
		return nil, true, false, fmt.Errorf("inbox cannot be renamed")
	}

	// Check if destination mailbox already exists.
	if exists, err := a.MailboxExists(tx, dst); err != nil {
		return nil, false, false, fmt.Errorf("checking if destination mailbox exists: %v", err)
	} else if exists {
		return nil, false, true, fmt.Errorf("destination mailbox already exists")
	}

	if *modseq == 0 {
		var err error
		*modseq, err = a.NextModSeq(tx)
		if err != nil {
			return nil, false, false, fmt.Errorf("get next modseq: %v", err)
		}
	}

	origName := mbsrc.Name

	// Move children to their new name.
	srcPrefix := mbsrc.Name + "/"
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Expunged", false)
	q.FilterFn(func(mb Mailbox) bool {
		return strings.HasPrefix(mb.Name, srcPrefix)
	})
	q.SortDesc("Name") // From leaf towards dst.
	kids, err := q.List()
	if err != nil {
		return nil, false, false, fmt.Errorf("listing child mailboxes")
	}

	// Rename children, from leaf towards dst (because sorted reverse by name).
	for _, mb := range kids {
		nname := dst + "/" + mb.Name[len(mbsrc.Name)+1:]
		var flags []string
		if err := tx.Get(&Subscription{nname}); err == nil {
			flags = []string{`\Subscribed`}
		} else if err != bstore.ErrAbsent {
			return nil, false, false, fmt.Errorf("look up subscription for new name of child %q: %v", nname, err)
		}
		// Leaf is first.
		changes = append(changes, ChangeRenameMailbox{mb.ID, mb.Name, nname, flags, *modseq})

		mb.Name = nname
		mb.ModSeq = *modseq
		if err := tx.Update(&mb); err != nil {
			return nil, false, false, fmt.Errorf("rename child mailbox %q: %v", mb.Name, err)
		}
	}

	// Move name out of the way. We may have to create it again, as our new parent.
	var flags []string
	if err := tx.Get(&Subscription{dst}); err == nil {
		flags = []string{`\Subscribed`}
	} else if err != bstore.ErrAbsent {
		return nil, false, false, fmt.Errorf("look up subscription for new name %q: %v", dst, err)
	}
	changes = append(changes, ChangeRenameMailbox{mbsrc.ID, mbsrc.Name, dst, flags, *modseq})
	mbsrc.ModSeq = *modseq
	mbsrc.Name = dst
	if err := tx.Update(mbsrc); err != nil {
		return nil, false, false, fmt.Errorf("rename mailbox: %v", err)
	}

	// Add any missing parents for the new name. A mailbox may have been renamed from
	// a/b to a/b/x/y, and we'll have to add a new "a" and a/b.
	t := strings.Split(dst, "/")
	t = t[:len(t)-1]
	var parent Mailbox
	var parentChanges []Change
	for i := range t {
		s := strings.Join(t[:i+1], "/")
		q := bstore.QueryTx[Mailbox](tx)
		q.FilterEqual("Expunged", false)
		q.FilterNonzero(Mailbox{Name: s})
		pmb, err := q.Get()
		if err == nil {
			parent = pmb
			continue
		} else if err != bstore.ErrAbsent {
			return nil, false, false, fmt.Errorf("lookup destination parent mailbox %q: %v", s, err)
		}

		uidval, err := a.NextUIDValidity(tx)
		if err != nil {
			return nil, false, false, fmt.Errorf("next uid validity: %v", err)
		}
		parent = Mailbox{
			CreateSeq:   *modseq,
			ModSeq:      *modseq,
			ParentID:    parent.ID,
			Name:        s,
			UIDValidity: uidval,
			UIDNext:     1,
			HaveCounts:  true,
		}
		if err := tx.Insert(&parent); err != nil {
			return nil, false, false, fmt.Errorf("inserting destination parent mailbox %q: %v", s, err)
		}

		var flags []string
		if err := tx.Get(&Subscription{parent.Name}); err == nil {
			flags = []string{`\Subscribed`}
		} else if err != bstore.ErrAbsent {
			return nil, false, false, fmt.Errorf("look up subscription for new parent %q: %v", parent.Name, err)
		}
		parentChanges = append(parentChanges, ChangeAddMailbox{parent, flags})
	}

	mbsrc.ParentID = parent.ID
	if err := tx.Update(mbsrc); err != nil {
		return nil, false, false, fmt.Errorf("set parent id on rename mailbox: %v", err)
	}

	// If we were moved from a/b to a/b/x, we mention the creation of a/b after we mentioned the rename.
	if strings.HasPrefix(dst, origName+"/") {
		changes = append(changes, parentChanges...)
	} else {
		changes = slices.Concat(parentChanges, changes)
	}

	return changes, false, false, nil
}

// MailboxDelete marks a mailbox as deleted, including its annotations. If it has
// children, the return value indicates that and an error is returned.
//
// Caller should broadcast the changes (deleting all messages in the mailbox and
// deleting the mailbox itself).
func (a *Account) MailboxDelete(ctx context.Context, log mlog.Log, tx *bstore.Tx, mb *Mailbox) (changes []Change, hasChildren bool, rerr error) {
	// Look for existence of child mailboxes. There is a lot of text in the IMAP RFCs about
	// NoInferior and NoSelect. We just require only leaf mailboxes are deleted.
	qmb := bstore.QueryTx[Mailbox](tx)
	qmb.FilterEqual("Expunged", false)
	mbprefix := mb.Name + "/"
	qmb.FilterFn(func(xmb Mailbox) bool {
		return strings.HasPrefix(xmb.Name, mbprefix)
	})
	if childExists, err := qmb.Exists(); err != nil {
		return nil, false, fmt.Errorf("checking if mailbox has child: %v", err)
	} else if childExists {
		return nil, true, fmt.Errorf("mailbox has a child, only leaf mailboxes can be deleted")
	}

	modseq, err := a.NextModSeq(tx)
	if err != nil {
		return nil, false, fmt.Errorf("get next modseq: %v", err)
	}

	qm := bstore.QueryTx[Message](tx)
	qm.FilterNonzero(Message{MailboxID: mb.ID})
	qm.FilterEqual("Expunged", false)
	qm.SortAsc("UID")
	l, err := qm.List()
	if err != nil {
		return nil, false, fmt.Errorf("listing messages in mailbox to remove; %v", err)
	}

	if len(l) > 0 {
		chrem, _, err := a.MessageRemove(log, tx, modseq, mb, RemoveOpts{}, l...)
		if err != nil {
			return nil, false, fmt.Errorf("marking messages removed: %v", err)
		}
		changes = append(changes, chrem)
	}

	// Marking metadata annotations deleted. ../rfc/5464:373
	qa := bstore.QueryTx[Annotation](tx)
	qa.FilterNonzero(Annotation{MailboxID: mb.ID})
	qa.FilterEqual("Expunged", false)
	if _, err := qa.UpdateFields(map[string]any{"ModSeq": modseq, "Expunged": true, "IsString": false, "Value": []byte(nil)}); err != nil {
		return nil, false, fmt.Errorf("removing annotations for mailbox: %v", err)
	}
	// Not sending changes about annotations on this mailbox, since the entire mailbox
	// is being removed.

	mb.ModSeq = modseq
	mb.Expunged = true
	mb.SpecialUse = SpecialUse{}

	if err := tx.Update(mb); err != nil {
		return nil, false, fmt.Errorf("updating mailbox: %v", err)
	}

	changes = append(changes, mb.ChangeRemoveMailbox())
	return changes, false, nil
}

// CheckMailboxName checks if name is valid, returning an INBOX-normalized name.
// I.e. it changes various casings of INBOX and INBOX/* to Inbox and Inbox/*.
// Name is invalid if it contains leading/trailing/double slashes, or when it isn't
// unicode-normalized, or when empty or has special characters.
//
// If name is the inbox, and allowInbox is false, this is indicated with the isInbox return parameter.
// For that case, and for other invalid names, an error is returned.
func CheckMailboxName(name string, allowInbox bool) (normalizedName string, isInbox bool, rerr error) {
	t := strings.Split(name, "/")
	if strings.EqualFold(t[0], "inbox") {
		if len(name) == len("inbox") && !allowInbox {
			return "", true, fmt.Errorf("special mailbox name Inbox not allowed")
		}
		name = "Inbox" + name[len("Inbox"):]
	}

	if norm.NFC.String(name) != name {
		return "", false, errors.New("non-unicode-normalized mailbox names not allowed")
	}

	for _, e := range t {
		switch e {
		case "":
			return "", false, errors.New("empty mailbox name")
		case ".":
			return "", false, errors.New(`"." not allowed`)
		case "..":
			return "", false, errors.New(`".." not allowed`)
		}
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return "", false, errors.New("bad slashes in mailbox name")
	}

	// "%" and "*" are difficult to use with the IMAP LIST command, but we allow mostly
	// allow them. ../rfc/3501:1002 ../rfc/9051:983
	if strings.HasPrefix(name, "#") {
		return "", false, errors.New("mailbox name cannot start with hash due to conflict with imap namespaces")
	}

	// "#" and "&" are special in IMAP mailbox names. "#" for namespaces, "&" for
	// IMAP-UTF-7 encoding. We do allow them. ../rfc/3501:1018 ../rfc/9051:991

	for _, c := range name {
		// ../rfc/3501:999 ../rfc/6855:192 ../rfc/9051:979
		if c <= 0x1f || c >= 0x7f && c <= 0x9f || c == 0x2028 || c == 0x2029 {
			return "", false, errors.New("control characters not allowed in mailbox name")
		}
	}
	return name, false, nil
}
