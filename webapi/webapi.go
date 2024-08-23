package webapi

import (
	"context"
	"io"
	"time"

	"github.com/mjl-/mox/webhook"
)

// todo future: we can have text and html templates, let submitters reference them along with parameters, and compose the message bodies ourselves.
// todo future: generate api specs (e.g. openapi) for webapi
// todo future: consider deprecating some of the webapi in favor of jmap

// Methods of the webapi. More methods may be added in the future. See [Client]
// for documentation.
type Methods interface {
	Send(ctx context.Context, request SendRequest) (response SendResult, err error)
	SuppressionList(ctx context.Context, request SuppressionListRequest) (response SuppressionListResult, err error)
	SuppressionAdd(ctx context.Context, request SuppressionAddRequest) (response SuppressionAddResult, err error)
	SuppressionRemove(ctx context.Context, request SuppressionRemoveRequest) (response SuppressionRemoveResult, err error)
	SuppressionPresent(ctx context.Context, request SuppressionPresentRequest) (response SuppressionPresentResult, err error)
	MessageGet(ctx context.Context, request MessageGetRequest) (response MessageGetResult, err error)
	MessageRawGet(ctx context.Context, request MessageRawGetRequest) (response io.ReadCloser, err error)
	MessagePartGet(ctx context.Context, request MessagePartGetRequest) (response io.ReadCloser, err error)
	MessageDelete(ctx context.Context, request MessageDeleteRequest) (response MessageDeleteResult, err error)
	MessageFlagsAdd(ctx context.Context, request MessageFlagsAddRequest) (response MessageFlagsAddResult, err error)
	MessageFlagsRemove(ctx context.Context, request MessageFlagsRemoveRequest) (response MessageFlagsRemoveResult, err error)
	MessageMove(ctx context.Context, request MessageMoveRequest) (response MessageMoveResult, err error)
}

// Error indicates an API-related error.
type Error struct {
	// For programmatic handling. Common values: "user" for generic error by user,
	// "server" for a server-side processing error, "badAddress" for malformed email
	// addresses.
	Code string

	// Human readable error message.
	Message string
}

// Error returns the human-readable error message.
func (e Error) Error() string {
	return e.Message
}

type NameAddress struct {
	Name    string // Optional, human-readable "display name" of the addressee.
	Address string // Required, email address.
}

// Message is an email message, used both for outgoing submitted messages and
// incoming messages.
type Message struct {
	// For sending, if empty, automatically filled based on authenticated user and
	// account information. Outgoing messages are allowed maximum 1 From address,
	// incoming messages can in theory have zero or multiple, but typically have just
	// one.
	From []NameAddress

	// To/Cc/Bcc message headers. Outgoing messages are sent to all these addresses.
	// All are optional, but there should be at least one addressee.
	To []NameAddress
	CC []NameAddress
	// For submissions, BCC addressees receive the message but are not added to the
	// headers of the outgoing message. Only the message saved the to the Sent mailbox
	// gets the Bcc header prepended. For incoming messages, this is typically empty.
	BCC []NameAddress

	// Optional Reply-To header, where the recipient is asked to send replies to.
	ReplyTo []NameAddress

	// Message-ID from message header, should be wrapped in <>'s. For outgoing
	// messages, a unique message-id is generated if empty.
	MessageID string

	// Optional. References to message-id's (including <>) of other messages, if this
	// is a reply or forwarded message. References are from oldest (ancestor) to most
	// recent message. For outgoing messages, if non-empty then In-Reply-To is set to
	// the last element.
	References []string

	// Optional, set to time of submission for outgoing messages if nil.
	Date *time.Time

	// Subject header, optional.
	Subject string

	// For outgoing messages, at least text or HTML must be non-empty. If both are
	// present, a multipart/alternative part is created. Lines must be
	// \n-separated, automatically replaced with \r\n when composing the message.
	// For parsed, incoming messages, values are truncated to 1MB (1024*1024 bytes).
	// Use MessagePartGet to retrieve the full part data.
	Text string
	HTML string
}

// SendRequest submits a message to be delivered.
type SendRequest struct {
	// Message with headers and contents to compose. Additional headers and files can
	// be added too (see below, and the use of multipart/form-data requests). The
	// fields of Message are included directly in SendRequest. Required.
	Message

	// Metadata to associate with the delivery, through the queue, including webhooks
	// about delivery events. Metadata can also be set with regular SMTP submission
	// through message headers "X-Mox-Extra-<key>: <value>". Current behaviour is as
	// follows, but this may change: 1. Keys are canonicalized, each dash-separated
	// word changed to start with a capital. 2. Keys cannot be duplicated. 3. These
	// headers are not removed when delivering.
	Extra map[string]string

	// Additional custom headers to include in outgoing message. Optional.
	// Unless a User-Agent or X-Mailer header is present, a User-Agent is added.
	Headers [][2]string

	// Alternative files are added as (full) alternative representation of the text
	// and/or html parts. Alternative files cause a part with content-type
	// "multipart/alternative" to be added to the message. Optional.
	AlternativeFiles []File

	// Inline files are added to the message and should be displayed by mail clients as
	// part of the message contents. Inline files cause a part with content-type
	// "multipart/related" to be added to the message. Optional.
	InlineFiles []File

	// Attached files are added to the message and should be shown as files that can be
	// saved.  Attached files cause a part with content-type "multipart/mixed" to be
	// added to the message. Optional.
	AttachedFiles []File

	// If absent/null, regular TLS requirements apply (opportunistic TLS, DANE,
	// MTA-STS). If true, the SMTP REQUIRETLS extension is required, enforcing verified
	// TLS along the delivery path. If false, TLS requirements are relaxed and
	// DANE/MTA-STS policies may be ignored to increase the odds of successful but
	// insecure delivery. Optional.
	RequireTLS *bool

	// If set, it should be a time in the future at which the first delivery attempt
	// starts. Optional.
	FutureRelease *time.Time

	// Whether to store outgoing message in designated Sent mailbox (if configured).
	SaveSent bool
}

type File struct {
	Name        string // Optional.
	ContentType string // E.g. application/pdf or image/png, automatically detected if empty.
	ContentID   string // E.g. "<randomid>", for use in html email with "cid:<randomid>". Optional.
	Data        string // Base64-encoded contents of the file. Required.
}

// MessageMeta is returned as part of MessageGet.
type MessageMeta struct {
	Size                int64    // Total size of raw message file.
	DSN                 bool     // Whether this message is a DSN.
	Flags               []string // Standard message flags like \seen, \answered, $forwarded, $junk, $nonjunk, and custom keywords.
	MailFrom            string   // Address used during SMTP "MAIL FROM" command.
	MailFromValidated   bool     // Whether SMTP MAIL FROM address was SPF-validated.
	MsgFrom             string   // Address used in message "From" header.
	MsgFromValidated    bool     // Whether address in message "From"-header was DMARC(-like) validated.
	DKIMVerifiedDomains []string // Verified domains from DKIM-signature in message. Can be different domain than used in addresses.
	RemoteIP            string   // Where the message was delivered from.
	MailboxName         string
}

type SendResult struct {
	MessageID   string       // "<random>@<domain>", as added by submitter or automatically generated during submission.
	Submissions []Submission // Messages submitted to queue for delivery. In order of To, CC, BCC fields in request.
}

type Submission struct {
	Address    string // From original recipient (to/cc/bcc).
	QueueMsgID int64  // Of message added to delivery queue, later webhook calls reference this same ID.
	FromID     string // Unique ID used during delivery, later webhook calls reference this same FromID.
}

// Suppression is an address to which messages will not be delivered. Attempts to
// deliver or queue will result in an immediate permanent failure to deliver.
type Suppression struct {
	ID      int64
	Created time.Time `bstore:"default now"`

	// Suppression applies to this account only.
	Account string `bstore:"nonzero,unique Account+BaseAddress"`

	// Unicode. Address with fictional simplified localpart: lowercase, dots removed
	// (gmail), first token before any "-" or "+" (typical catchall separator).
	BaseAddress string `bstore:"nonzero"`

	// Unicode. Address that caused this suppression.
	OriginalAddress string `bstore:"nonzero"`

	Manual bool
	Reason string
}

type SuppressionListRequest struct{}
type SuppressionListResult struct {
	Suppressions []Suppression // Current suppressed addresses for account.
}

type SuppressionAddRequest struct {
	EmailAddress string
	Manual       bool   // Whether added manually or automatically.
	Reason       string // Free-form text.
}
type SuppressionAddResult struct{}

type SuppressionRemoveRequest struct {
	EmailAddress string
}
type SuppressionRemoveResult struct{}

type SuppressionPresentRequest struct {
	EmailAddress string
}
type SuppressionPresentResult struct {
	Present bool
}

type MessageGetRequest struct {
	MsgID int64
}
type MessageGetResult struct {
	Message   Message
	Structure webhook.Structure // MIME structure.
	Meta      MessageMeta       // Additional information about message and SMTP delivery.
}

type MessageRawGetRequest struct {
	MsgID int64
}

type MessagePartGetRequest struct {
	MsgID int64

	// Indexes into MIME parts, e.g. [0, 2] first dereferences the first element in a
	// multipart message, then the 3rd part within that first element.
	PartPath []int
}

type MessageDeleteRequest struct {
	MsgID int64
}
type MessageDeleteResult struct{}

type MessageFlagsAddRequest struct {
	MsgID int64
	Flags []string // Standard message flags like \seen, \answered, $forwarded, $junk, $nonjunk, and custom keywords.
}
type MessageFlagsAddResult struct{}

type MessageFlagsRemoveRequest struct {
	MsgID int64
	Flags []string
}
type MessageFlagsRemoveResult struct{}

type MessageMoveRequest struct {
	MsgID           int64
	DestMailboxName string // E.g. "Inbox", must already exist.
}
type MessageMoveResult struct{}
