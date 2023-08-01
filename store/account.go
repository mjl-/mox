/*
Package store implements storage for accounts, their mailboxes, IMAP
subscriptions and messages, and broadcasts updates (e.g. mail delivery) to
interested sessions (e.g. IMAP connections).

Layout of storage for accounts:

	<DataDir>/accounts/<name>/index.db
	<DataDir>/accounts/<name>/msg/[a-zA-Z0-9_-]+/<id>

Index.db holds tables for user information, mailboxes, and messages. Messages
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
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"
	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/smtp"
)

var xlog = mlog.New("store")

var (
	ErrUnknownMailbox     = errors.New("no such mailbox")
	ErrUnknownCredentials = errors.New("credentials not found")
	ErrAccountUnknown     = errors.New("no such account")
)

var subjectpassRand = mox.NewRand()

var InitialMailboxes = []string{"Inbox", "Sent", "Archive", "Trash", "Drafts", "Junk"}

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

	// "Inbox" is the name for the special IMAP "INBOX". Slash separated
	// for hierarchy.
	Name string `bstore:"nonzero,unique"`

	// If UIDs are invalidated, e.g. when renaming a mailbox to a previously existing
	// name, UIDValidity must be changed. Used by IMAP for synchronization.
	UIDValidity uint32

	// UID likely to be assigned to next message. Used by IMAP to detect messages
	// delivered to a mailbox.
	UIDNext UID

	// Special-use hints. The mailbox holds these types of messages. Used
	// in IMAP LIST (mailboxes) response.
	Archive bool
	Draft   bool
	Junk    bool
	Sent    bool
	Trash   bool

	// Keywords as used in messages. Storing a non-system keyword for a message
	// automatically adds it to this list. Used in the IMAP FLAGS response. Only
	// "atoms", stored in lower case.
	Keywords []string
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
	// ID, unchanged over lifetime, determines path to on-disk msg file.
	// Set during deliver.
	ID int64

	UID       UID   `bstore:"nonzero"` // UID, for IMAP. Set during deliver.
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

	Received time.Time `bstore:"default now,index"`

	// Full IP address of remote SMTP server. Empty if not delivered over
	// SMTP.
	RemoteIP        string
	RemoteIPMasked1 string `bstore:"index RemoteIPMasked1+Received"` // For IPv4 /32, for IPv6 /64, for reputation.
	RemoteIPMasked2 string `bstore:"index RemoteIPMasked2+Received"` // For IPv4 /26, for IPv6 /48.
	RemoteIPMasked3 string `bstore:"index RemoteIPMasked3+Received"` // For IPv4 /21, for IPv6 /32.

	EHLODomain        string         `bstore:"index EHLODomain+Received"` // Only set if present and not an IP address. Unicode string.
	MailFrom          string         // With localpart and domain. Can be empty.
	MailFromLocalpart smtp.Localpart // SMTP "MAIL FROM", can be empty.
	MailFromDomain    string         `bstore:"index MailFromDomain+Received"` // Only set if it is a domain, not an IP. Unicode string.
	RcptToLocalpart   smtp.Localpart // SMTP "RCPT TO", can be empty.
	RcptToDomain      string         // Unicode string.

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

	DKIMDomains []string `bstore:"index DKIMDomains+Received"` // Domains with verified DKIM signatures. Unicode string.

	// Value of Message-Id header. Only set for messages that were
	// delivered to the rejects mailbox. For ensuring such messages are
	// delivered only once. Value includes <>.
	MessageID string `bstore:"index"`

	// Hash of message. For rejects delivery, so optional like MessageID.
	MessageHash []byte

	Flags
	Keywords    []string `bstore:"index"` // For keywords other than system flags or the basic well-known $-flags. Only in "atom" syntax, stored in lower case.
	Size        int64
	TrainedJunk *bool  // If nil, no training done yet. Otherwise, true is trained as junk, false trained as nonjunk.
	MsgPrefix   []byte // Typically holds received headers and/or header separator.

	// ParsedBuf message structure. Currently saved as JSON of message.Part because bstore
	// cannot yet store recursive types. Created when first needed, and saved in the
	// database.
	// todo: once replaced with non-json storage, remove date fixup in ../message/part.go.
	ParsedBuf []byte
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

// PrepareExpunge clears fields that are no longer needed after an expunge, so
// almost all fields. Does not change ModSeq, but does set Expunged.
func (m *Message) PrepareExpunge() {
	*m = Message{
		ID:        m.ID,
		UID:       m.UID,
		MailboxID: m.MailboxID,
		CreateSeq: m.CreateSeq,
		ModSeq:    m.ModSeq,
		Expunged:  true,
	}
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
	untrain := m.TrainedJunk != nil
	untrainJunk := untrain && *m.TrainedJunk
	train := m.Junk || m.Notjunk && !(m.Junk && m.Notjunk)
	trainJunk := m.Junk
	return untrain != train || untrain && train && untrainJunk != trainJunk
}

// JunkFlagsForMailbox sets Junk and Notjunk flags based on mailbox name if configured. Often
// used when delivering/moving/copying messages to a mailbox. Mail clients are not
// very helpful with setting junk/notjunk flags. But clients can move/copy messages
// to other mailboxes. So we set flags when clients move a message.
func (m *Message) JunkFlagsForMailbox(mailbox string, conf config.Account) {
	if !conf.AutomaticJunkFlags.Enabled {
		return
	}

	lmailbox := strings.ToLower(mailbox)

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
// first-time incoming replies from users this account has sent messages to. On
// IMAP append to Sent, the message is parsed and recipients are inserted as
// recipient. Recipients are never removed other than for removing the message. On
// IMAP move/copy, recipients aren't modified either. This assumes an IMAP client
// simply appends messages to the Sent mailbox (as opposed to copying messages from
// some place).
type Recipient struct {
	ID        int64
	MessageID int64          `bstore:"nonzero,ref Message"` // Ref gives it its own index, useful for fast removal as well.
	Localpart smtp.Localpart `bstore:"nonzero"`
	Domain    string         `bstore:"nonzero,index Domain+Localpart"` // Unicode string.
	OrgDomain string         `bstore:"nonzero,index"`                  // Unicode string.
	Sent      time.Time      `bstore:"nonzero"`
}

// Outgoing is a message submitted for delivery from the queue. Used to enforce
// maximum outgoing messages.
type Outgoing struct {
	ID        int64
	Recipient string    `bstore:"nonzero,index"` // Canonical international address with utf8 domain.
	Submitted time.Time `bstore:"nonzero,default now"`
}

// Types stored in DB.
var DBTypes = []any{NextUIDValidity{}, Message{}, Recipient{}, Mailbox{}, Subscription{}, Outgoing{}, Password{}, Subjectpass{}, SyncState{}}

// Account holds the information about a user, includings mailboxes, messages, imap subscriptions.
type Account struct {
	Name   string     // Name, according to configuration.
	Dir    string     // Directory where account files, including the database, bloom filter, and mail messages, are stored for this account.
	DBPath string     // Path to database with mailboxes, messages, etc.
	DB     *bstore.DB // Open database connection.

	// Write lock must be held for account/mailbox modifications including message delivery.
	// Read lock for reading mailboxes/messages.
	// When making changes to mailboxes/messages, changes must be broadcasted before
	// releasing the lock to ensure proper UID ordering.
	sync.RWMutex

	nused int // Reference count, while >0, this account is alive and shared.
}

// InitialUIDValidity returns a UIDValidity used for initializing an account.
// It can be replaced during tests with a predictable value.
var InitialUIDValidity = func() uint32 {
	return uint32(time.Now().Unix() >> 1) // A 2-second resolution will get us far enough beyond 2038.
}

var openAccounts = struct {
	names map[string]*Account
	sync.Mutex
}{
	names: map[string]*Account{},
}

func closeAccount(acc *Account) (rerr error) {
	openAccounts.Lock()
	acc.nused--
	defer openAccounts.Unlock()
	if acc.nused == 0 {
		rerr = acc.DB.Close()
		acc.DB = nil
		delete(openAccounts.names, acc.Name)
	}
	return
}

// OpenAccount opens an account by name.
//
// No additional data path prefix or ".db" suffix should be added to the name.
// A single shared account exists per name.
func OpenAccount(name string) (*Account, error) {
	openAccounts.Lock()
	defer openAccounts.Unlock()
	if acc, ok := openAccounts.names[name]; ok {
		acc.nused++
		return acc, nil
	}

	if _, ok := mox.Conf.Account(name); !ok {
		return nil, ErrAccountUnknown
	}

	acc, err := openAccount(name)
	if err != nil {
		return nil, err
	}
	acc.nused++
	openAccounts.names[name] = acc
	return acc, nil
}

// openAccount opens an existing account, or creates it if it is missing.
func openAccount(name string) (a *Account, rerr error) {
	dir := filepath.Join(mox.DataDirPath("accounts"), name)
	dbpath := filepath.Join(dir, "index.db")

	// Create account if it doesn't exist yet.
	isNew := false
	if _, err := os.Stat(dbpath); err != nil && os.IsNotExist(err) {
		isNew = true
		os.MkdirAll(dir, 0770)
	}

	db, err := bstore.Open(context.TODO(), dbpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			db.Close()
			if isNew {
				os.Remove(dbpath)
			}
		}
	}()

	if isNew {
		if err := initAccount(db); err != nil {
			return nil, fmt.Errorf("initializing account: %v", err)
		}
	}

	return &Account{
		Name:   name,
		Dir:    dir,
		DBPath: dbpath,
		DB:     db,
	}, nil
}

func initAccount(db *bstore.DB) error {
	return db.Write(context.TODO(), func(tx *bstore.Tx) error {
		uidvalidity := InitialUIDValidity()

		mailboxes := InitialMailboxes
		defaultMailboxes := mox.Conf.Static.DefaultMailboxes
		if len(defaultMailboxes) > 0 {
			mailboxes = []string{"Inbox"}
			for _, name := range defaultMailboxes {
				if strings.EqualFold(name, "Inbox") {
					continue
				}
				mailboxes = append(mailboxes, name)
			}
		}
		for _, name := range mailboxes {
			mb := Mailbox{Name: name, UIDValidity: uidvalidity, UIDNext: 1}
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

		uidvalidity++
		if err := tx.Insert(&NextUIDValidity{1, uidvalidity}); err != nil {
			return fmt.Errorf("inserting nextuidvalidity: %w", err)
		}
		return nil
	})
}

// Close reduces the reference count, and closes the database connection when
// it was the last user.
func (a *Account) Close() error {
	return closeAccount(a)
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

// WithWLock runs fn with account writelock held. Necessary for account/mailbox modification. For message delivery, a read lock is required.
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

// DeliverMessage delivers a mail message to the account.
//
// If consumeFile is set, the original msgFile is moved/renamed or copied and
// removed as part of delivery.
//
// The message, with msg.MsgPrefix and msgFile combined, must have a header
// section. The caller is responsible for adding a header separator to
// msg.MsgPrefix if missing from an incoming message.
//
// If isSent is true, the message is parsed for its recipients (to/cc/bcc). Their
// domains are added to Recipients for use in dmarc reputation.
//
// If sync is true, the message file and its directory are synced. Should be true
// for regular mail delivery, but can be false when importing many messages.
//
// If CreateSeq/ModSeq is not set, it is assigned automatically.
//
// Must be called with account rlock or wlock.
//
// Caller must broadcast new message.
func (a *Account) DeliverMessage(log *mlog.Log, tx *bstore.Tx, m *Message, msgFile *os.File, consumeFile, isSent, sync, notrain bool) error {
	if m.Expunged {
		return fmt.Errorf("cannot deliver expunged message")
	}

	mb := Mailbox{ID: m.MailboxID}
	if err := tx.Get(&mb); err != nil {
		return fmt.Errorf("get mailbox: %w", err)
	}
	m.UID = mb.UIDNext
	mb.UIDNext++
	if err := tx.Update(&mb); err != nil {
		return fmt.Errorf("updating mailbox nextuid: %w", err)
	}

	conf, _ := a.Conf()
	m.JunkFlagsForMailbox(mb.Name, conf)

	var part *message.Part
	if m.ParsedBuf == nil {
		mr := FileMsgReader(m.MsgPrefix, msgFile) // We don't close, it would close the msgFile.
		p, err := message.EnsurePart(mr, m.Size)
		if err != nil {
			log.Infox("parsing delivered message", err, mlog.Field("parse", ""), mlog.Field("message", m.ID))
			// We continue, p is still valid.
		}
		part = &p
		buf, err := json.Marshal(part)
		if err != nil {
			return fmt.Errorf("marshal parsed message: %w", err)
		}
		m.ParsedBuf = buf
	}

	// If we are delivering to the originally intended mailbox, no need to store the mailbox ID again.
	if m.MailboxDestinedID != 0 && m.MailboxDestinedID == m.MailboxOrigID {
		m.MailboxDestinedID = 0
	}
	if m.CreateSeq == 0 || m.ModSeq == 0 {
		modseq, err := a.NextModSeq(tx)
		if err != nil {
			return fmt.Errorf("assigning next modseq: %w", err)
		}
		m.CreateSeq = modseq
		m.ModSeq = modseq
	}

	if err := tx.Insert(m); err != nil {
		return fmt.Errorf("inserting message: %w", err)
	}

	if isSent {
		// Attempt to parse the message for its To/Cc/Bcc headers, which we insert into Recipient.
		if part == nil {
			var p message.Part
			if err := json.Unmarshal(m.ParsedBuf, &p); err != nil {
				log.Errorx("unmarshal parsed message for its to,cc,bcc headers, continuing", err, mlog.Field("parse", ""))
			} else {
				part = &p
			}
		}
		if part != nil && part.Envelope != nil {
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
					log.Info("to/cc/bcc address with empty localpart, not inserting as recipient", mlog.Field("address", addr))
					continue
				}
				d, err := dns.ParseDomain(addr.Host)
				if err != nil {
					log.Debugx("parsing domain in to/cc/bcc address", err, mlog.Field("address", addr))
					continue
				}
				mr := Recipient{
					MessageID: m.ID,
					Localpart: smtp.Localpart(addr.User),
					Domain:    d.Name(),
					OrgDomain: publicsuffix.Lookup(context.TODO(), d).Name(),
					Sent:      sent,
				}
				if err := tx.Insert(&mr); err != nil {
					return fmt.Errorf("inserting sent message recipients: %w", err)
				}
			}
		}
	}

	msgPath := a.MessagePath(m.ID)
	msgDir := filepath.Dir(msgPath)
	os.MkdirAll(msgDir, 0770)

	// Sync file data to disk.
	if sync {
		if err := msgFile.Sync(); err != nil {
			return fmt.Errorf("fsync message file: %w", err)
		}
	}

	if consumeFile {
		if err := os.Rename(msgFile.Name(), msgPath); err != nil {
			// Could be due to cross-filesystem rename. Users shouldn't configure their systems that way.
			return fmt.Errorf("moving msg file to destination directory: %w", err)
		}
	} else if err := moxio.LinkOrCopy(log, msgPath, msgFile.Name(), &moxio.AtReader{R: msgFile}, true); err != nil {
		return fmt.Errorf("linking/copying message to new file: %w", err)
	}

	if sync {
		if err := moxio.SyncDir(msgDir); err != nil {
			return fmt.Errorf("sync directory: %w", err)
		}
	}

	if !notrain && m.NeedsTraining() {
		l := []Message{*m}
		if err := a.RetrainMessages(context.TODO(), log, tx, l, false); err != nil {
			return fmt.Errorf("training junkfilter: %w", err)
		}
		*m = l[0]
	}

	return nil
}

// SetPassword saves a new password for this account. This password is used for
// IMAP, SMTP (submission) sessions and the HTTP account web page.
func (a *Account) SetPassword(password string) error {
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
		return nil
	})
	if err == nil {
		xlog.Info("new password set for account", mlog.Field("account", a.Name))
	}
	return err
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
		for i := 0; i < 16; i++ {
			key += string(chars[subjectpassRand.Intn(len(chars))])
		}
		v.Key = key
		return tx.Insert(&v)
	})
}

// Ensure mailbox is present in database, adding records for the mailbox and its
// parents if they aren't present.
//
// If subscribe is true, any mailboxes that were created will also be subscribed to.
// Caller must hold account wlock.
// Caller must propagate changes if any.
func (a *Account) MailboxEnsure(tx *bstore.Tx, name string, subscribe bool) (mb Mailbox, changes []Change, rerr error) {
	if norm.NFC.String(name) != name {
		return Mailbox{}, nil, fmt.Errorf("mailbox name not normalized")
	}

	// Quick sanity check.
	if strings.EqualFold(name, "inbox") && name != "Inbox" {
		return Mailbox{}, nil, fmt.Errorf("bad casing for inbox")
	}

	elems := strings.Split(name, "/")
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterFn(func(mb Mailbox) bool {
		return mb.Name == elems[0] || strings.HasPrefix(mb.Name, elems[0]+"/")
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
	for _, elem := range elems {
		if p != "" {
			p += "/"
		}
		p += elem
		var ok bool
		mb, ok = mailboxes[p]
		if ok {
			continue
		}
		uidval, err := a.NextUIDValidity(tx)
		if err != nil {
			return Mailbox{}, nil, fmt.Errorf("next uid validity: %v", err)
		}
		mb = Mailbox{
			Name:        p,
			UIDValidity: uidval,
			UIDNext:     1,
		}
		err = tx.Insert(&mb)
		if err != nil {
			return Mailbox{}, nil, fmt.Errorf("creating new mailbox: %v", err)
		}

		change := ChangeAddMailbox{Name: p}
		if subscribe {
			if tx.Get(&Subscription{p}) != nil {
				err := tx.Insert(&Subscription{p})
				if err != nil {
					return Mailbox{}, nil, fmt.Errorf("subscribing to mailbox: %v", err)
				}
			}
			change.Flags = []string{`\Subscribed`}
		}
		changes = append(changes, change)
	}
	return mb, changes, nil
}

// MailboxExists checks if mailbox exists.
// Caller must hold account rlock.
func (a *Account) MailboxExists(tx *bstore.Tx, name string) (bool, error) {
	q := bstore.QueryTx[Mailbox](tx)
	q.FilterEqual("Name", name)
	return q.Exists()
}

// MailboxFind finds a mailbox by name, returning a nil mailbox and nil error if mailbox does not exist.
func (a *Account) MailboxFind(tx *bstore.Tx, name string) (*Mailbox, error) {
	q := bstore.QueryTx[Mailbox](tx)
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
	q.FilterEqual("Name", name)
	exists, err := q.Exists()
	if err != nil {
		return nil, fmt.Errorf("looking up mailbox for subscription: %w", err)
	}
	if exists {
		return []Change{ChangeAddSubscription{name}}, nil
	}
	return []Change{ChangeAddMailbox{Name: name, Flags: []string{`\Subscribed`, `\NonExistent`}}}, nil
}

// MessageRuleset returns the first ruleset (if any) that message the message
// represented by msgPrefix and msgFile, with smtp and validation fields from m.
func MessageRuleset(log *mlog.Log, dest config.Destination, m *Message, msgPrefix []byte, msgFile *os.File) *config.Ruleset {
	if len(dest.Rulesets) == 0 {
		return nil
	}

	mr := FileMsgReader(msgPrefix, msgFile) // We don't close, it would close the msgFile.
	p, err := message.Parse(mr)
	if err != nil {
		log.Errorx("parsing message for evaluating rulesets, continuing with headers", err, mlog.Field("parse", ""))
		// note: part is still set.
	}
	// todo optimize: only parse header if needed for rulesets. and probably reuse an earlier parsing.
	header, err := p.Header()
	if err != nil {
		log.Errorx("parsing message headers for evaluating rulesets, delivering to default mailbox", err, mlog.Field("parse", ""))
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
	return filepath.Join(a.Dir, "msg", MessagePath(messageID))
}

// MessageReader opens a message for reading, transparently combining the
// message prefix with the original incoming message.
func (a *Account) MessageReader(m Message) *MsgReader {
	return &MsgReader{prefix: m.MsgPrefix, path: a.MessagePath(m.ID), size: m.Size}
}

// Deliver delivers an email to dest, based on the configured rulesets.
//
// Caller must hold account wlock (mailbox may be created).
// Message delivery and possible mailbox creation are broadcasted.
func (a *Account) Deliver(log *mlog.Log, dest config.Destination, m *Message, msgFile *os.File, consumeFile bool) error {
	var mailbox string
	rs := MessageRuleset(log, dest, m, m.MsgPrefix, msgFile)
	if rs != nil {
		mailbox = rs.Mailbox
	} else if dest.Mailbox == "" {
		mailbox = "Inbox"
	} else {
		mailbox = dest.Mailbox
	}
	return a.DeliverMailbox(log, mailbox, m, msgFile, consumeFile)
}

// DeliverMailbox delivers an email to the specified mailbox.
//
// Caller must hold account wlock (mailbox may be created).
// Message delivery and possible mailbox creation are broadcasted.
func (a *Account) DeliverMailbox(log *mlog.Log, mailbox string, m *Message, msgFile *os.File, consumeFile bool) error {
	var changes []Change
	err := a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		mb, chl, err := a.MailboxEnsure(tx, mailbox, true)
		if err != nil {
			return fmt.Errorf("ensuring mailbox: %w", err)
		}
		m.MailboxID = mb.ID
		m.MailboxOrigID = mb.ID
		changes = append(changes, chl...)

		return a.DeliverMessage(log, tx, m, msgFile, consumeFile, mb.Sent, true, false)
	})
	// todo: if rename succeeded but transaction failed, we should remove the file.
	if err != nil {
		return err
	}

	changes = append(changes, ChangeAddUID{m.MailboxID, m.UID, m.ModSeq, m.Flags, m.Keywords})
	BroadcastChanges(a, changes)
	return nil
}

// TidyRejectsMailbox removes old reject emails, and returns whether there is space for a new delivery.
//
// Caller most hold account wlock.
// Changes are broadcasted.
func (a *Account) TidyRejectsMailbox(log *mlog.Log, rejectsMailbox string) (hasSpace bool, rerr error) {
	var changes []Change

	var remove []Message
	defer func() {
		for _, m := range remove {
			p := a.MessagePath(m.ID)
			err := os.Remove(p)
			log.Check(err, "removing rejects message file", mlog.Field("path", p))
		}
	}()

	err := a.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		mb, err := a.MailboxFind(tx, rejectsMailbox)
		if err != nil {
			return fmt.Errorf("finding mailbox: %w", err)
		}
		if mb == nil {
			// No messages have been delivered yet.
			hasSpace = true
			return nil
		}

		// Gather old messages to remove.
		old := time.Now().Add(-14 * 24 * time.Hour)
		qdel := bstore.QueryTx[Message](tx)
		qdel.FilterNonzero(Message{MailboxID: mb.ID})
		qdel.FilterLess("Received", old)
		remove, err = qdel.List()
		if err != nil {
			return fmt.Errorf("listing old messages: %w", err)
		}

		changes, err = a.removeMessages(context.TODO(), log, tx, mb, remove)
		if err != nil {
			return fmt.Errorf("removing messages: %w", err)
		}

		// We allow up to n messages.
		qcount := bstore.QueryTx[Message](tx)
		qcount.FilterNonzero(Message{MailboxID: mb.ID})
		qcount.Limit(1000)
		n, err := qcount.Count()
		if err != nil {
			return fmt.Errorf("counting rejects: %w", err)
		}
		hasSpace = n < 1000

		return nil
	})
	if err != nil {
		remove = nil // Don't remove files on failure.
		return false, err
	}

	BroadcastChanges(a, changes)

	return hasSpace, nil
}

func (a *Account) removeMessages(ctx context.Context, log *mlog.Log, tx *bstore.Tx, mb *Mailbox, l []Message) ([]Change, error) {
	if len(l) == 0 {
		return nil, nil
	}
	ids := make([]int64, len(l))
	anyids := make([]any, len(l))
	for i, m := range l {
		ids[i] = m.ID
		anyids[i] = m.ID
	}

	// Remove any message recipients. Should not happen, but a user can move messages
	// from a Sent mailbox to the rejects mailbox...
	qdmr := bstore.QueryTx[Recipient](tx)
	qdmr.FilterEqual("MessageID", anyids...)
	if _, err := qdmr.Delete(); err != nil {
		return nil, fmt.Errorf("deleting from message recipient: %w", err)
	}

	// Assign new modseq.
	modseq, err := a.NextModSeq(tx)
	if err != nil {
		return nil, fmt.Errorf("assign next modseq: %w", err)
	}

	// Actually remove the messages.
	qx := bstore.QueryTx[Message](tx)
	qx.FilterIDs(ids)
	var expunged []Message
	qx.Gather(&expunged)
	if _, err := qx.UpdateNonzero(Message{ModSeq: modseq, Expunged: true}); err != nil {
		return nil, fmt.Errorf("expunging messages: %w", err)
	}

	// Mark as neutral and train so junk filter gets untrained with these (junk) messages.
	for i := range expunged {
		expunged[i].Junk = false
		expunged[i].Notjunk = false
	}
	if err := a.RetrainMessages(ctx, log, tx, expunged, true); err != nil {
		return nil, fmt.Errorf("retraining expunged messages: %w", err)
	}

	changes := make([]Change, len(l))
	for i, m := range l {
		changes[i] = ChangeRemoveUIDs{mb.ID, []UID{m.UID}, modseq}
	}
	return changes, nil
}

// RejectsRemove removes a message from the rejects mailbox if present.
// Caller most hold account wlock.
// Changes are broadcasted.
func (a *Account) RejectsRemove(log *mlog.Log, rejectsMailbox, messageID string) error {
	var changes []Change

	var remove []Message
	defer func() {
		for _, m := range remove {
			p := a.MessagePath(m.ID)
			err := os.Remove(p)
			log.Check(err, "removing rejects message file", mlog.Field("path", p))
		}
	}()

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
		remove, err = q.List()
		if err != nil {
			return fmt.Errorf("listing messages to remove: %w", err)
		}

		changes, err = a.removeMessages(context.TODO(), log, tx, mb, remove)
		if err != nil {
			return fmt.Errorf("removing messages: %w", err)
		}

		return nil
	})
	if err != nil {
		remove = nil // Don't remove files on failure.
		return err
	}

	BroadcastChanges(a, changes)

	return nil
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
func OpenEmailAuth(email string, password string) (acc *Account, rerr error) {
	acc, _, rerr = OpenEmail(email)
	if rerr != nil {
		return
	}

	defer func() {
		if rerr != nil && acc != nil {
			err := acc.Close()
			xlog.Check(err, "closing account after open auth failure")
			acc = nil
		}
	}()

	pw, err := bstore.QueryDB[Password](context.TODO(), acc.DB).Get()
	if err != nil {
		if err == bstore.ErrAbsent {
			return acc, ErrUnknownCredentials
		}
		return acc, fmt.Errorf("looking up password: %v", err)
	}
	authCache.Lock()
	ok := len(password) >= 8 && authCache.success[authKey{email, pw.Hash}] == password
	authCache.Unlock()
	if ok {
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pw.Hash), []byte(password)); err != nil {
		rerr = ErrUnknownCredentials
	} else {
		authCache.Lock()
		authCache.success[authKey{email, pw.Hash}] = password
		authCache.Unlock()
	}
	return
}

// OpenEmail opens an account given an email address.
//
// The email address may contain a catchall separator.
func OpenEmail(email string) (*Account, config.Destination, error) {
	addr, err := smtp.ParseAddress(email)
	if err != nil {
		return nil, config.Destination{}, fmt.Errorf("%w: %v", ErrUnknownCredentials, err)
	}
	accountName, _, dest, err := mox.FindAccount(addr.Localpart, addr.Domain, false)
	if err != nil && (errors.Is(err, mox.ErrAccountNotFound) || errors.Is(err, mox.ErrDomainNotFound)) {
		return nil, config.Destination{}, ErrUnknownCredentials
	} else if err != nil {
		return nil, config.Destination{}, fmt.Errorf("looking up address: %v", err)
	}
	acc, err := OpenAccount(accountName)
	if err != nil {
		return nil, config.Destination{}, err
	}
	return acc, dest, nil
}

// 64 characters, must be power of 2 for MessagePath
const msgDirChars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// MessagePath returns the filename of the on-disk filename, relative to the containing directory such as <account>/msg or queue.
// Returns names like "AB/1".
func MessagePath(messageID int64) string {
	v := messageID >> 13 // 8k files per directory.
	dir := ""
	for {
		dir += string(msgDirChars[int(v)&(len(msgDirChars)-1)])
		v >>= 6
		if v == 0 {
			break
		}
	}
	return fmt.Sprintf("%s/%d", dir, messageID)
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

// RemoveKeywords removes keywords from l, modifying and returning it. Should only
// be used with lower-case keywords, not with system flags like \Seen.
func RemoveKeywords(l, remove []string) []string {
	for _, k := range remove {
		if i := slices.Index(l, k); i >= 0 {
			copy(l[i:], l[i+1:])
			l = l[:len(l)-1]
		}
	}
	return l
}

// MergeKeywords adds keywords from add into l, updating and returning it along
// with whether it added any keyword. Keywords are only added if they aren't
// already present. Should only be used with lower-case keywords, not with system
// flags like \Seen.
func MergeKeywords(l, add []string) ([]string, bool) {
	var changed bool
	for _, k := range add {
		if !slices.Contains(l, k) {
			l = append(l, k)
			changed = true
		}
	}
	return l, changed
}

// ValidLowercaseKeyword returns whether s is a valid, lower-case, keyword.
func ValidLowercaseKeyword(s string) bool {
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			continue
		}
		// ../rfc/9051:6334
		const atomspecials = `(){%*"\]`
		if c <= ' ' || c > 0x7e || strings.ContainsRune(atomspecials, c) {
			return false
		}
	}
	return len(s) > 0
}
