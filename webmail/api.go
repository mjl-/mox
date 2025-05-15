package webmail

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/admin"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webauth"
	"github.com/mjl-/mox/webops"
)

//go:embed api.json
var webmailapiJSON []byte

type Webmail struct {
	maxMessageSize int64  // From listener.
	cookiePath     string // From listener.
	isForwarded    bool   // From listener, whether we look at X-Forwarded-* headers.
}

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		pkglog.Fatalx("parsing webmail api docs", err, slog.String("api", api))
	}
	return doc
}

var webmailDoc = mustParseAPI("webmail", webmailapiJSON)

var sherpaHandlerOpts *sherpa.HandlerOpts

func makeSherpaHandler(maxMessageSize int64, cookiePath string, isForwarded bool) (http.Handler, error) {
	return sherpa.NewHandler("/api/", moxvar.Version, Webmail{maxMessageSize, cookiePath, isForwarded}, &webmailDoc, sherpaHandlerOpts)
}

func init() {
	collector, err := sherpaprom.NewCollector("moxwebmail", nil)
	if err != nil {
		pkglog.Fatalx("creating sherpa prometheus collector", err)
	}

	sherpaHandlerOpts = &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none", NoCORS: true}
	// Just to validate.
	_, err = makeSherpaHandler(0, "", false)
	if err != nil {
		pkglog.Fatalx("sherpa handler", err)
	}
}

// LoginPrep returns a login token, and also sets it as cookie. Both must be
// present in the call to Login.
func (w Webmail) LoginPrep(ctx context.Context) string {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log

	var data [8]byte
	_, err := cryptorand.Read(data[:])
	xcheckf(ctx, err, "generate token")
	loginToken := base64.RawURLEncoding.EncodeToString(data[:])

	webauth.LoginPrep(ctx, log, "webmail", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken)

	return loginToken
}

// Login returns a session token for the credentials, or fails with error code
// "user:badLogin". Call LoginPrep to get a loginToken.
func (w Webmail) Login(ctx context.Context, loginToken, username, password string) store.CSRFToken {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log

	csrfToken, err := webauth.Login(ctx, log, webauth.Accounts, "webmail", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken, username, password)
	if _, ok := err.(*sherpa.Error); ok {
		panic(err)
	}
	xcheckf(ctx, err, "login")
	return csrfToken
}

// Logout invalidates the session token.
func (w Webmail) Logout(ctx context.Context) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log

	err := webauth.Logout(ctx, log, webauth.Accounts, "webmail", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, reqInfo.Account.Name, reqInfo.SessionToken)
	xcheckf(ctx, err, "logout")
}

// Version returns the version, goos and goarch.
func (w Webmail) Version(ctx context.Context) (version, goos, goarch string) {
	return moxvar.Version, runtime.GOOS, runtime.GOARCH
}

// Token returns a single-use token to use for an SSE connection. A token can only
// be used for a single SSE connection. Tokens are stored in memory for a maximum
// of 1 minute, with at most 10 unused tokens (the most recently created) per
// account.
func (Webmail) Token(ctx context.Context) string {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	return sseTokens.xgenerate(ctx, reqInfo.Account.Name, reqInfo.LoginAddress, reqInfo.SessionToken)
}

// Requests sends a new request for an open SSE connection. Any currently active
// request for the connection will be canceled, but this is done asynchrously, so
// the SSE connection may still send results for the previous request. Callers
// should take care to ignore such results. If req.Cancel is set, no new request is
// started.
func (Webmail) Request(ctx context.Context, req Request) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	if !req.Cancel && req.Page.Count <= 0 {
		xcheckuserf(ctx, errors.New("Page.Count must be >= 1"), "checking request")
	}

	sse, ok := sseGet(req.SSEID, reqInfo.Account.Name)
	if !ok {
		xcheckuserf(ctx, errors.New("unknown sseid"), "looking up connection")
	}
	sse.Request <- req
}

// ParsedMessage returns enough to render the textual body of a message. It is
// assumed the client already has other fields through MessageItem.
func (Webmail) ParsedMessage(ctx context.Context, msgID int64) (pm ParsedMessage) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log
	acc := reqInfo.Account

	xdbread(ctx, acc, func(tx *bstore.Tx) {
		m := xmessageID(ctx, tx, msgID)

		state := msgState{acc: acc}
		defer state.clear()
		var err error
		pm, err = parsedMessage(log, &m, &state, true, false, false)
		xcheckf(ctx, err, "parsing message")

		if len(pm.envelope.From) == 1 {
			pm.ViewMode, err = fromAddrViewMode(tx, pm.envelope.From[0])
			xcheckf(ctx, err, "looking up view mode for from address")
		}
	})
	return
}

// fromAddrViewMode returns the view mode for a from address.
func fromAddrViewMode(tx *bstore.Tx, from MessageAddress) (store.ViewMode, error) {
	settingsViewMode := func() (store.ViewMode, error) {
		settings := store.Settings{ID: 1}
		if err := tx.Get(&settings); err != nil {
			return store.ModeText, err
		}
		if settings.ShowHTML {
			return store.ModeHTML, nil
		}
		return store.ModeText, nil
	}

	lp, err := smtp.ParseLocalpart(from.User)
	if err != nil {
		return settingsViewMode()
	}
	fromAddr := smtp.NewAddress(lp, from.Domain).Pack(true)
	fas := store.FromAddressSettings{FromAddress: fromAddr}
	err = tx.Get(&fas)
	if err == bstore.ErrAbsent {
		return settingsViewMode()
	} else if err != nil {
		return store.ModeText, err
	}
	return fas.ViewMode, nil
}

// FromAddressSettingsSave saves per-"From"-address settings.
func (Webmail) FromAddressSettingsSave(ctx context.Context, fas store.FromAddressSettings) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	if fas.FromAddress == "" {
		xcheckuserf(ctx, errors.New("empty from address"), "checking address")
	}

	xdbwrite(ctx, acc, func(tx *bstore.Tx) {
		if tx.Get(&store.FromAddressSettings{FromAddress: fas.FromAddress}) == nil {
			err := tx.Update(&fas)
			xcheckf(ctx, err, "updating settings for from address")
		} else {
			err := tx.Insert(&fas)
			xcheckf(ctx, err, "inserting settings for from address")
		}
	})
}

// MessageFindMessageID looks up a message by Message-Id header, and returns the ID
// of the message in storage. Used when opening a previously saved draft message
// for editing again.
// If no message is find, zero is returned, not an error.
func (Webmail) MessageFindMessageID(ctx context.Context, messageID string) (id int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	messageID, _, _ = message.MessageIDCanonical(messageID)
	if messageID == "" {
		xcheckuserf(ctx, errors.New("empty message-id"), "parsing message-id")
	}

	xdbread(ctx, acc, func(tx *bstore.Tx) {
		q := bstore.QueryTx[store.Message](tx)
		q.FilterEqual("Expunged", false)
		q.FilterNonzero(store.Message{MessageID: messageID})
		m, err := q.Get()
		if err == bstore.ErrAbsent {
			return
		}
		xcheckf(ctx, err, "looking up message by message-id")
		id = m.ID
	})
	return
}

// ComposeMessage is a message to be composed, for saving draft messages.
type ComposeMessage struct {
	From              string
	To                []string
	Cc                []string
	Bcc               []string
	ReplyTo           string // If non-empty, Reply-To header to add to message.
	Subject           string
	TextBody          string
	ResponseMessageID int64 // If set, this was a reply or forward, based on IsForward.
	DraftMessageID    int64 // If set, previous draft message that will be removed after composing new message.
}

// MessageCompose composes a message and saves it to the mailbox. Used for
// saving draft messages.
func (w Webmail) MessageCompose(ctx context.Context, m ComposeMessage, mailboxID int64) (id int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	log.Debug("message compose")

	// Prevent any accidental control characters, or attempts at getting bare \r or \n
	// into messages.
	for _, l := range [][]string{m.To, m.Cc, m.Bcc, {m.From, m.Subject, m.ReplyTo}} {
		for _, s := range l {
			for _, c := range s {
				if c < 0x20 {
					xcheckuserf(ctx, errors.New("control characters not allowed"), "checking header values")
				}
			}
		}
	}

	fromAddr, err := parseAddress(m.From)
	xcheckuserf(ctx, err, "parsing From address")

	var replyTo *message.NameAddress
	if m.ReplyTo != "" {
		addr, err := parseAddress(m.ReplyTo)
		xcheckuserf(ctx, err, "parsing Reply-To address")
		replyTo = &addr
	}

	var recipients []smtp.Address

	var toAddrs []message.NameAddress
	for _, s := range m.To {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing To address")
		toAddrs = append(toAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	var ccAddrs []message.NameAddress
	for _, s := range m.Cc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Cc address")
		ccAddrs = append(ccAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	var bccAddrs []message.NameAddress
	for _, s := range m.Bcc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Bcc address")
		bccAddrs = append(bccAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	// We only use smtputf8 if we have to, with a utf-8 localpart. For IDNA, we use ASCII domains.
	smtputf8 := false
	for _, a := range recipients {
		if a.Localpart.IsInternational() {
			smtputf8 = true
			break
		}
	}
	if !smtputf8 && fromAddr.Address.Localpart.IsInternational() {
		// todo: may want to warn user that they should consider sending with a ascii-only localpart, in case receiver doesn't support smtputf8.
		smtputf8 = true
	}
	if !smtputf8 && replyTo != nil && replyTo.Address.Localpart.IsInternational() {
		smtputf8 = true
	}

	// Create file to compose message into.
	dataFile, err := store.CreateMessageTemp(log, "webmail-compose")
	xcheckf(ctx, err, "creating temporary file for compose message")
	defer store.CloseRemoveTempFile(log, dataFile, "compose message")

	// If writing to the message file fails, we abort immediately.
	xc := message.NewComposer(dataFile, w.maxMessageSize, smtputf8)
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrMessageSize) {
			xcheckuserf(ctx, err, "making message")
		} else if ok && errors.Is(err, message.ErrCompose) {
			xcheckf(ctx, err, "making message")
		}
		panic(x)
	}()

	// Outer message headers.
	xc.HeaderAddrs("From", []message.NameAddress{fromAddr})
	if replyTo != nil {
		xc.HeaderAddrs("Reply-To", []message.NameAddress{*replyTo})
	}
	xc.HeaderAddrs("To", toAddrs)
	xc.HeaderAddrs("Cc", ccAddrs)
	xc.HeaderAddrs("Bcc", bccAddrs)
	if m.Subject != "" {
		xc.Subject(m.Subject)
	}

	// Add In-Reply-To and References headers.
	if m.ResponseMessageID > 0 {
		xdbread(ctx, acc, func(tx *bstore.Tx) {
			rm := xmessageID(ctx, tx, m.ResponseMessageID)
			msgr := acc.MessageReader(rm)
			defer func() {
				err := msgr.Close()
				log.Check(err, "closing message reader")
			}()
			rp, err := rm.LoadPart(msgr)
			xcheckf(ctx, err, "load parsed message")
			h, err := rp.Header()
			xcheckf(ctx, err, "parsing header")

			if rp.Envelope == nil {
				return
			}

			if rp.Envelope.MessageID != "" {
				xc.Header("In-Reply-To", rp.Envelope.MessageID)
			}
			refs := h.Values("References")
			if len(refs) == 0 && rp.Envelope.InReplyTo != "" {
				refs = []string{rp.Envelope.InReplyTo}
			}
			if rp.Envelope.MessageID != "" {
				refs = append(refs, rp.Envelope.MessageID)
			}
			if len(refs) > 0 {
				xc.Header("References", strings.Join(refs, "\r\n\t"))
			}
		})
	}
	xc.Header("MIME-Version", "1.0")
	textBody, ct, cte := xc.TextPart("plain", m.TextBody)
	xc.Header("Content-Type", ct)
	xc.Header("Content-Transfer-Encoding", cte)
	xc.Line()
	xc.Write([]byte(textBody))
	xc.Flush()

	var nm store.Message

	// Remove previous draft message, append message to destination mailbox.
	acc.WithWLock(func() {
		var changes []store.Change

		var newIDs []int64
		defer func() {
			for _, id := range newIDs {
				p := acc.MessagePath(id)
				err := os.Remove(p)
				log.Check(err, "removing added message aftr error", slog.String("path", p))
			}
		}()

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq // Only set if needed.

			if m.DraftMessageID > 0 {
				nchanges := xops.MessageDeleteTx(ctx, log, tx, acc, []int64{m.DraftMessageID}, &modseq)
				changes = append(changes, nchanges...)
			}

			mb, err := store.MailboxID(tx, mailboxID)
			xcheckf(ctx, err, "looking up mailbox")

			if modseq == 0 {
				modseq, err = acc.NextModSeq(tx)
				xcheckf(ctx, err, "next modseq")
			}

			nm = store.Message{
				CreateSeq:     modseq,
				ModSeq:        modseq,
				MailboxID:     mb.ID,
				MailboxOrigID: mb.ID,
				Flags:         store.Flags{Notjunk: true},
				Size:          xc.Size,
			}

			err = acc.MessageAdd(log, tx, &mb, &nm, dataFile, store.AddOpts{})
			if err != nil && errors.Is(err, store.ErrOverQuota) {
				xcheckuserf(ctx, err, "checking quota")
			}
			xcheckf(ctx, err, "storing message in mailbox")
			newIDs = append(newIDs, nm.ID)

			err = tx.Update(&mb)
			xcheckf(ctx, err, "updating sent mailbox for counts")

			changes = append(changes, nm.ChangeAddUID(mb), mb.ChangeCounts())
		})
		newIDs = nil

		store.BroadcastChanges(acc, changes)
	})

	return nm.ID
}

// Attachment is a MIME part is an existing message that is not intended as
// viewable text or HTML part.
type Attachment struct {
	Path []int // Indices into top-level message.Part.Parts.

	// File name based on "name" attribute of "Content-Type", or the "filename"
	// attribute of "Content-Disposition".
	Filename string

	Part message.Part
}

// SubmitMessage is an email message to be sent to one or more recipients.
// Addresses are formatted as just email address, or with a name like "name
// <user@host>".
type SubmitMessage struct {
	From                      string
	To                        []string
	Cc                        []string
	Bcc                       []string
	ReplyTo                   string // If non-empty, Reply-To header to add to message.
	Subject                   string
	TextBody                  string
	Attachments               []File
	ForwardAttachments        ForwardAttachments
	IsForward                 bool
	ResponseMessageID         int64      // If set, this was a reply or forward, based on IsForward.
	UserAgent                 string     // User-Agent header added if not empty.
	RequireTLS                *bool      // For "Require TLS" extension during delivery.
	FutureRelease             *time.Time // If set, time (in the future) when message should be delivered from queue.
	ArchiveThread             bool       // If set, thread is archived after sending message.
	ArchiveReferenceMailboxID int64      // If ArchiveThread is set, thread messages from this mailbox ID are moved to the archive mailbox ID. E.g. of Inbox.
	DraftMessageID            int64      // If set, draft message that will be removed after sending.
}

// ForwardAttachments references attachments by a list of message.Part paths.
type ForwardAttachments struct {
	MessageID int64   // Only relevant if MessageID is not 0.
	Paths     [][]int // List of attachments, each path is a list of indices into the top-level message.Part.Parts.
}

// File is a new attachment (not from an existing message that is being
// forwarded) to send with a SubmitMessage.
type File struct {
	Filename string
	DataURI  string // Full data of the attachment, with base64 encoding and including content-type.
}

// parseAddress expects either a plain email address like "user@domain", or a
// single address as used in a message header, like "name <user@domain>".
func parseAddress(msghdr string) (message.NameAddress, error) {
	// todo: parse more fully according to ../rfc/5322:959
	parser := mail.AddressParser{WordDecoder: &wordDecoder}
	a, err := parser.Parse(msghdr)
	if err != nil {
		return message.NameAddress{}, err
	}

	path, err := smtp.ParseNetMailAddress(a.Address)
	if err != nil {
		return message.NameAddress{}, err
	}
	return message.NameAddress{DisplayName: a.Name, Address: path}, nil
}

func xmailboxID(ctx context.Context, tx *bstore.Tx, mailboxID int64) store.Mailbox {
	if mailboxID == 0 {
		xcheckuserf(ctx, errors.New("invalid zero mailbox ID"), "getting mailbox")
	}
	mb, err := store.MailboxID(tx, mailboxID)
	if err == bstore.ErrAbsent || err == store.ErrMailboxExpunged {
		xcheckuserf(ctx, err, "getting mailbox")
	}
	xcheckf(ctx, err, "getting mailbox")
	return mb
}

// xmessageID returns a non-expunged message or panics with a sherpa error.
func xmessageID(ctx context.Context, tx *bstore.Tx, messageID int64) store.Message {
	if messageID == 0 {
		xcheckuserf(ctx, errors.New("invalid zero message id"), "getting message")
	}
	m := store.Message{ID: messageID}
	err := tx.Get(&m)
	if err == bstore.ErrAbsent {
		xcheckuserf(ctx, errors.New("message does not exist"), "getting message")
	} else if err == nil && m.Expunged {
		xcheckuserf(ctx, errors.New("message was removed"), "getting message")
	}
	xcheckf(ctx, err, "getting message")
	return m
}

func xrandomID(ctx context.Context, n int) string {
	return base64.RawURLEncoding.EncodeToString(xrandom(ctx, n))
}

func xrandom(ctx context.Context, n int) []byte {
	buf := make([]byte, n)
	x, err := cryptorand.Read(buf)
	xcheckf(ctx, err, "read random")
	if x != n {
		xcheckf(ctx, errors.New("short random read"), "read random")
	}
	return buf
}

// MessageSubmit sends a message by submitting it the outgoing email queue. The
// message is sent to all addresses listed in the To, Cc and Bcc addresses, without
// Bcc message header.
//
// If a Sent mailbox is configured, messages are added to it after submitting
// to the delivery queue. If Bcc addresses were present, a header is prepended
// to the message stored in the Sent mailbox.
func (w Webmail) MessageSubmit(ctx context.Context, m SubmitMessage) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	log.Debug("message submit")

	// Similar between ../smtpserver/server.go:/submit\( and ../webmail/api.go:/MessageSubmit\( and ../webapisrv/server.go:/Send\(

	// todo: consider making this an HTTP POST, so we can upload as regular form, which is probably more efficient for encoding for the client and we can stream the data in. also not unlike the webapi Submit method.

	// Prevent any accidental control characters, or attempts at getting bare \r or \n
	// into messages.
	for _, l := range [][]string{m.To, m.Cc, m.Bcc, {m.From, m.Subject, m.ReplyTo, m.UserAgent}} {
		for _, s := range l {
			for _, c := range s {
				if c < 0x20 {
					xcheckuserf(ctx, errors.New("control characters not allowed"), "checking header values")
				}
			}
		}
	}

	fromAddr, err := parseAddress(m.From)
	xcheckuserf(ctx, err, "parsing From address")

	var replyTo *message.NameAddress
	if m.ReplyTo != "" {
		a, err := parseAddress(m.ReplyTo)
		xcheckuserf(ctx, err, "parsing Reply-To address")
		replyTo = &a
	}

	var recipients []smtp.Address

	var toAddrs []message.NameAddress
	for _, s := range m.To {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing To address")
		toAddrs = append(toAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	var ccAddrs []message.NameAddress
	for _, s := range m.Cc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Cc address")
		ccAddrs = append(ccAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	var bccAddrs []message.NameAddress
	for _, s := range m.Bcc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Bcc address")
		bccAddrs = append(bccAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	// Check if from address is allowed for account.
	if ok, disabled := mox.AllowMsgFrom(reqInfo.Account.Name, fromAddr.Address); disabled {
		metricSubmission.WithLabelValues("domaindisabled").Inc()
		xcheckuserf(ctx, mox.ErrDomainDisabled, `looking up "from" address for account`)
	} else if !ok {
		metricSubmission.WithLabelValues("badfrom").Inc()
		xcheckuserf(ctx, errors.New("address not found"), `looking up "from" address for account`)
	}

	if len(recipients) == 0 {
		xcheckuserf(ctx, errors.New("no recipients"), "composing message")
	}

	// Check outgoing message rate limit.
	xdbread(ctx, acc, func(tx *bstore.Tx) {
		rcpts := make([]smtp.Path, len(recipients))
		for i, r := range recipients {
			rcpts[i] = smtp.Path{Localpart: r.Localpart, IPDomain: dns.IPDomain{Domain: r.Domain}}
		}
		msglimit, rcptlimit, err := acc.SendLimitReached(tx, rcpts)
		if msglimit >= 0 {
			metricSubmission.WithLabelValues("messagelimiterror").Inc()
			xcheckuserf(ctx, errors.New("message limit reached"), "checking outgoing rate")
		} else if rcptlimit >= 0 {
			metricSubmission.WithLabelValues("recipientlimiterror").Inc()
			xcheckuserf(ctx, errors.New("recipient limit reached"), "checking outgoing rate")
		}
		xcheckf(ctx, err, "checking send limit")
	})

	// We only use smtputf8 if we have to, with a utf-8 localpart. For IDNA, we use ASCII domains.
	smtputf8 := false
	for _, a := range recipients {
		if a.Localpart.IsInternational() {
			smtputf8 = true
			break
		}
	}
	if !smtputf8 && fromAddr.Address.Localpart.IsInternational() {
		// todo: may want to warn user that they should consider sending with a ascii-only localpart, in case receiver doesn't support smtputf8.
		smtputf8 = true
	}
	if !smtputf8 && replyTo != nil && replyTo.Address.Localpart.IsInternational() {
		smtputf8 = true
	}

	// Create file to compose message into.
	dataFile, err := store.CreateMessageTemp(log, "webmail-submit")
	xcheckf(ctx, err, "creating temporary file for message")
	defer store.CloseRemoveTempFile(log, dataFile, "message to submit")

	// If writing to the message file fails, we abort immediately.
	xc := message.NewComposer(dataFile, w.maxMessageSize, smtputf8)
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrMessageSize) {
			xcheckuserf(ctx, err, "making message")
		} else if ok && errors.Is(err, message.ErrCompose) {
			xcheckf(ctx, err, "making message")
		}
		panic(x)
	}()

	// todo spec: can we add an Authentication-Results header that indicates this is an authenticated message? the "auth" method is for SMTP AUTH, which this isn't. ../rfc/8601 https://www.iana.org/assignments/email-auth/email-auth.xhtml

	// Each queued message gets a Received header.
	// We don't have access to the local IP for adding.
	// We cannot use VIA, because there is no registered method. We would like to use
	// it to add the ascii domain name in case of smtputf8 and IDNA host name.
	recvFrom := message.HeaderCommentDomain(mox.Conf.Static.HostnameDomain, smtputf8)
	recvBy := mox.Conf.Static.HostnameDomain.XName(smtputf8)
	recvID := mox.ReceivedID(mox.CidFromCtx(ctx))
	recvHdrFor := func(rcptTo string) string {
		recvHdr := &message.HeaderWriter{}
		// For additional Received-header clauses, see:
		// https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml#table-mail-parameters-8
		// Note: we don't have "via" or "with", there is no registered for webmail.
		recvHdr.Add(" ", "Received:", "from", recvFrom, "by", recvBy, "id", recvID) // ../rfc/5321:3158
		if reqInfo.Request.TLS != nil {
			recvHdr.Add(" ", mox.TLSReceivedComment(log, *reqInfo.Request.TLS)...)
		}
		recvHdr.Add(" ", "for", "<"+rcptTo+">;", time.Now().Format(message.RFC5322Z))
		return recvHdr.String()
	}

	// Outer message headers.
	xc.HeaderAddrs("From", []message.NameAddress{fromAddr})
	if replyTo != nil {
		xc.HeaderAddrs("Reply-To", []message.NameAddress{*replyTo})
	}
	xc.HeaderAddrs("To", toAddrs)
	xc.HeaderAddrs("Cc", ccAddrs)
	// We prepend Bcc headers to the message when adding to the Sent mailbox.
	if m.Subject != "" {
		xc.Subject(m.Subject)
	}

	messageID := fmt.Sprintf("<%s>", mox.MessageIDGen(smtputf8))
	xc.Header("Message-Id", messageID)
	xc.Header("Date", time.Now().Format(message.RFC5322Z))
	// Add In-Reply-To and References headers.
	if m.ResponseMessageID > 0 {
		xdbread(ctx, acc, func(tx *bstore.Tx) {
			rm := xmessageID(ctx, tx, m.ResponseMessageID)
			msgr := acc.MessageReader(rm)
			defer func() {
				err := msgr.Close()
				log.Check(err, "closing message reader")
			}()
			rp, err := rm.LoadPart(msgr)
			xcheckf(ctx, err, "load parsed message")
			h, err := rp.Header()
			xcheckf(ctx, err, "parsing header")

			if rp.Envelope == nil {
				return
			}

			if rp.Envelope.MessageID != "" {
				xc.Header("In-Reply-To", rp.Envelope.MessageID)
			}
			refs := h.Values("References")
			if len(refs) == 0 && rp.Envelope.InReplyTo != "" {
				refs = []string{rp.Envelope.InReplyTo}
			}
			if rp.Envelope.MessageID != "" {
				refs = append(refs, rp.Envelope.MessageID)
			}
			if len(refs) > 0 {
				xc.Header("References", strings.Join(refs, "\r\n\t"))
			}
		})
	}
	if m.UserAgent != "" {
		xc.Header("User-Agent", m.UserAgent)
	}
	if m.RequireTLS != nil && !*m.RequireTLS {
		xc.Header("TLS-Required", "No")
	}
	xc.Header("MIME-Version", "1.0")

	if len(m.Attachments) > 0 || len(m.ForwardAttachments.Paths) > 0 {
		mp := multipart.NewWriter(xc)
		xc.Header("Content-Type", fmt.Sprintf(`multipart/mixed; boundary="%s"`, mp.Boundary()))
		xc.Line()

		textBody, ct, cte := xc.TextPart("plain", m.TextBody)
		textHdr := textproto.MIMEHeader{}
		textHdr.Set("Content-Type", ct)
		textHdr.Set("Content-Transfer-Encoding", cte)

		textp, err := mp.CreatePart(textHdr)
		xcheckf(ctx, err, "adding text part to message")
		_, err = textp.Write(textBody)
		xcheckf(ctx, err, "writing text part")

		xaddPart := func(ct, filename string) io.Writer {
			ahdr := textproto.MIMEHeader{}
			cd := mime.FormatMediaType("attachment", map[string]string{"filename": filename})

			ahdr.Set("Content-Type", ct)
			ahdr.Set("Content-Transfer-Encoding", "base64")
			ahdr.Set("Content-Disposition", cd)
			ap, err := mp.CreatePart(ahdr)
			xcheckf(ctx, err, "adding attachment part to message")
			return ap
		}

		xaddAttachmentBase64 := func(ct, filename string, base64Data []byte) {
			ap := xaddPart(ct, filename)

			for len(base64Data) > 0 {
				line := base64Data
				n := min(len(line), 76) // ../rfc/2045:1372
				line, base64Data = base64Data[:n], base64Data[n:]
				_, err := ap.Write(line)
				xcheckf(ctx, err, "writing attachment")
				_, err = ap.Write([]byte("\r\n"))
				xcheckf(ctx, err, "writing attachment")
			}
		}

		xaddAttachment := func(ct, filename string, r io.Reader) {
			ap := xaddPart(ct, filename)
			wc := moxio.Base64Writer(ap)
			_, err := io.Copy(wc, r)
			xcheckf(ctx, err, "adding attachment")
			err = wc.Close()
			xcheckf(ctx, err, "flushing attachment")
		}

		for _, a := range m.Attachments {
			s := a.DataURI
			if !strings.HasPrefix(s, "data:") {
				xcheckuserf(ctx, errors.New("missing data: in datauri"), "parsing attachment")
			}
			s = s[len("data:"):]
			t := strings.SplitN(s, ",", 2)
			if len(t) != 2 {
				xcheckuserf(ctx, errors.New("missing comma in datauri"), "parsing attachment")
			}
			if !strings.HasSuffix(t[0], "base64") {
				xcheckuserf(ctx, errors.New("missing base64 in datauri"), "parsing attachment")
			}
			ct := strings.TrimSuffix(t[0], "base64")
			ct = strings.TrimSuffix(ct, ";")
			if ct == "" {
				ct = "application/octet-stream"
			}
			filename := a.Filename
			if filename == "" {
				filename = "unnamed.bin"
			}
			params := map[string]string{"name": filename}
			ct = mime.FormatMediaType(ct, params)

			// Ensure base64 is valid, then we'll write the original string.
			_, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(t[1])))
			xcheckuserf(ctx, err, "parsing attachment as base64")

			xaddAttachmentBase64(ct, filename, []byte(t[1]))
		}

		if len(m.ForwardAttachments.Paths) > 0 {
			acc.WithRLock(func() {
				xdbread(ctx, acc, func(tx *bstore.Tx) {
					fm := xmessageID(ctx, tx, m.ForwardAttachments.MessageID)
					msgr := acc.MessageReader(fm)
					defer func() {
						err := msgr.Close()
						log.Check(err, "closing message reader")
					}()

					fp, err := fm.LoadPart(msgr)
					xcheckf(ctx, err, "load parsed message")

					for _, path := range m.ForwardAttachments.Paths {
						ap := fp
						for _, xp := range path {
							if xp < 0 || xp >= len(ap.Parts) {
								xcheckuserf(ctx, errors.New("unknown part"), "looking up attachment")
							}
							ap = ap.Parts[xp]
						}

						_, filename, err := ap.DispositionFilename()
						if err != nil && errors.Is(err, message.ErrParamEncoding) {
							log.Debugx("parsing disposition/filename", err)
						} else {
							xcheckf(ctx, err, "reading disposition")
						}
						if filename == "" {
							filename = "unnamed.bin"
						}
						params := map[string]string{"name": filename}
						if pcharset := ap.ContentTypeParams["charset"]; pcharset != "" {
							params["charset"] = pcharset
						}
						ct := strings.ToLower(ap.MediaType + "/" + ap.MediaSubType)
						ct = mime.FormatMediaType(ct, params)
						xaddAttachment(ct, filename, ap.Reader())
					}
				})
			})
		}

		err = mp.Close()
		xcheckf(ctx, err, "writing mime multipart")
	} else {
		textBody, ct, cte := xc.TextPart("plain", m.TextBody)
		xc.Header("Content-Type", ct)
		xc.Header("Content-Transfer-Encoding", cte)
		xc.Line()
		xc.Write([]byte(textBody))
	}

	xc.Flush()

	// Add DKIM-Signature headers.
	var msgPrefix string
	fd := fromAddr.Address.Domain
	confDom, _ := mox.Conf.Domain(fd)
	if confDom.Disabled {
		xcheckuserf(ctx, mox.ErrDomainDisabled, "checking domain")
	}
	selectors := mox.DKIMSelectors(confDom.DKIM)
	if len(selectors) > 0 {
		dkimHeaders, err := dkim.Sign(ctx, log.Logger, fromAddr.Address.Localpart, fd, selectors, smtputf8, dataFile)
		if err != nil {
			metricServerErrors.WithLabelValues("dkimsign").Inc()
		}
		xcheckf(ctx, err, "sign dkim")

		msgPrefix = dkimHeaders
	}

	accConf, _ := acc.Conf()
	loginAddr, err := smtp.ParseAddress(reqInfo.LoginAddress)
	xcheckf(ctx, err, "parsing login address")
	useFromID := slices.Contains(accConf.ParsedFromIDLoginAddresses, loginAddr)
	fromPath := fromAddr.Address.Path()
	var localpartBase string
	if useFromID {
		localpartBase = strings.SplitN(string(fromPath.Localpart), confDom.LocalpartCatchallSeparatorsEffective[0], 2)[0]
	}
	qml := make([]queue.Msg, len(recipients))
	now := time.Now()
	for i, rcpt := range recipients {
		fp := fromPath
		var fromID string
		if useFromID {
			fromID = xrandomID(ctx, 16)
			fp.Localpart = smtp.Localpart(localpartBase + confDom.LocalpartCatchallSeparatorsEffective[0] + fromID)
		}

		// Don't use per-recipient unique message prefix when multiple recipients are
		// present, or the queue cannot deliver it in a single smtp transaction.
		var recvRcpt string
		if len(recipients) == 1 {
			recvRcpt = rcpt.Pack(smtputf8)
		}
		rcptMsgPrefix := recvHdrFor(recvRcpt) + msgPrefix
		msgSize := int64(len(rcptMsgPrefix)) + xc.Size
		toPath := smtp.Path{
			Localpart: rcpt.Localpart,
			IPDomain:  dns.IPDomain{Domain: rcpt.Domain},
		}
		qm := queue.MakeMsg(fp, toPath, xc.Has8bit, xc.SMTPUTF8, msgSize, messageID, []byte(rcptMsgPrefix), m.RequireTLS, now, m.Subject)
		if m.FutureRelease != nil {
			ival := time.Until(*m.FutureRelease)
			if ival < 0 {
				xcheckuserf(ctx, errors.New("date/time is in the past"), "scheduling delivery")
			} else if ival > queue.FutureReleaseIntervalMax {
				xcheckuserf(ctx, fmt.Errorf("date/time can not be further than %v in the future", queue.FutureReleaseIntervalMax), "scheduling delivery")
			}
			qm.NextAttempt = *m.FutureRelease
			qm.FutureReleaseRequest = "until;" + m.FutureRelease.Format(time.RFC3339)
			// todo: possibly add a header to the message stored in the Sent mailbox to indicate it was scheduled for later delivery.
		}
		qm.FromID = fromID
		// no qm.Extra from webmail
		qml[i] = qm
	}
	err = queue.Add(ctx, log, reqInfo.Account.Name, dataFile, qml...)
	if err != nil {
		metricSubmission.WithLabelValues("queueerror").Inc()
	}
	xcheckf(ctx, err, "adding messages to the delivery queue")
	metricSubmission.WithLabelValues("ok").Inc()

	var modseq store.ModSeq // Only set if needed.

	// We have committed to sending the message. We want to follow through
	// with appending to Sent and removing the draft message.
	ctx = context.WithoutCancel(ctx)

	// Append message to Sent mailbox, mark original messages as answered/forwarded,
	// remove any draft message.
	acc.WithWLock(func() {
		var changes []store.Change

		metricked := false
		defer func() {
			if x := recover(); x != nil {
				if !metricked {
					metricServerErrors.WithLabelValues("submit").Inc()
				}
				panic(x)
			}
		}()

		var newIDs []int64
		defer func() {
			for _, id := range newIDs {
				p := acc.MessagePath(id)
				err := os.Remove(p)
				log.Check(err, "removing delivered message on error", slog.String("path", p))
			}
		}()

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			if m.DraftMessageID > 0 {
				nchanges := xops.MessageDeleteTx(ctx, log, tx, acc, []int64{m.DraftMessageID}, &modseq)
				changes = append(changes, nchanges...)
			}

			if m.ResponseMessageID > 0 {
				rm := xmessageID(ctx, tx, m.ResponseMessageID)
				oflags := rm.Flags
				if m.IsForward {
					rm.Forwarded = true
				} else {
					rm.Answered = true
				}
				if !rm.Junk && !rm.Notjunk {
					rm.Notjunk = true
				}
				if rm.Flags != oflags {
					if modseq == 0 {
						modseq, err = acc.NextModSeq(tx)
						xcheckf(ctx, err, "next modseq")
					}
					rm.ModSeq = modseq
					err := tx.Update(&rm)
					xcheckf(ctx, err, "updating flags of replied/forwarded message")

					// Update modseq of mailbox of replied/forwarded message.
					rmb, err := store.MailboxID(tx, rm.MailboxID)
					xcheckf(ctx, err, "get mailbox of replied/forwarded message for modseq update")
					rmb.ModSeq = modseq
					err = tx.Update(&rmb)
					xcheckf(ctx, err, "update modseq of mailbox of replied/forwarded message")

					changes = append(changes, rm.ChangeFlags(oflags, rmb))

					err = acc.RetrainMessages(ctx, log, tx, []store.Message{rm})
					xcheckf(ctx, err, "retraining messages after reply/forward")
				}

				// Move messages from this thread still in this mailbox to the designated Archive
				// mailbox.
				if m.ArchiveThread {
					mbArchive, err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).FilterEqual("Archive", true).Get()
					if err == bstore.ErrAbsent || err == store.ErrMailboxExpunged {
						xcheckuserf(ctx, errors.New("not configured"), "looking up designated archive mailbox")
					}
					xcheckf(ctx, err, "looking up designated archive mailbox")

					var msgIDs []int64
					q := bstore.QueryTx[store.Message](tx)
					q.FilterNonzero(store.Message{ThreadID: rm.ThreadID, MailboxID: m.ArchiveReferenceMailboxID})
					q.FilterEqual("Expunged", false)
					err = q.IDs(&msgIDs)
					xcheckf(ctx, err, "listing messages in thread to archive")
					if len(msgIDs) > 0 {
						ids, nchanges := xops.MessageMoveTx(ctx, log, acc, tx, msgIDs, mbArchive, &modseq)
						newIDs = append(newIDs, ids...)
						changes = append(changes, nchanges...)
					}
				}
			}

			sentmb, err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).FilterEqual("Sent", true).Get()
			if err == bstore.ErrAbsent || err == store.ErrMailboxExpunged {
				// There is no mailbox designated as Sent mailbox, so we're done.
				return
			}
			xcheckf(ctx, err, "message submitted to queue, adding to Sent mailbox")

			if modseq == 0 {
				modseq, err = acc.NextModSeq(tx)
				xcheckf(ctx, err, "next modseq")
			}

			// If there were bcc headers, prepend those to the stored message only, before the
			// DKIM signature. The DKIM-signature oversigns the bcc header, so this stored
			// message won't validate with DKIM anymore, which is fine.
			if len(bccAddrs) > 0 {
				var sb strings.Builder
				xbcc := message.NewComposer(&sb, 100*1024, smtputf8)
				xbcc.HeaderAddrs("Bcc", bccAddrs)
				xbcc.Flush()
				msgPrefix = sb.String() + msgPrefix
			}

			sentm := store.Message{
				CreateSeq:     modseq,
				ModSeq:        modseq,
				MailboxID:     sentmb.ID,
				MailboxOrigID: sentmb.ID,
				Flags:         store.Flags{Notjunk: true, Seen: true},
				Size:          int64(len(msgPrefix)) + xc.Size,
				MsgPrefix:     []byte(msgPrefix),
			}

			err = acc.MessageAdd(log, tx, &sentmb, &sentm, dataFile, store.AddOpts{})
			if err != nil && errors.Is(err, store.ErrOverQuota) {
				xcheckuserf(ctx, err, "checking quota")
			} else if err != nil {
				metricSubmission.WithLabelValues("storesenterror").Inc()
				metricked = true
			}
			xcheckf(ctx, err, "message submitted to queue, appending message to Sent mailbox")
			newIDs = append(newIDs, sentm.ID)

			err = tx.Update(&sentmb)
			xcheckf(ctx, err, "updating sent mailbox for counts")

			changes = append(changes, sentm.ChangeAddUID(sentmb), sentmb.ChangeCounts())
		})
		newIDs = nil

		store.BroadcastChanges(acc, changes)
	})
}

// MessageMove moves messages to another mailbox. If the message is already in
// the mailbox an error is returned.
func (Webmail) MessageMove(ctx context.Context, messageIDs []int64, mailboxID int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	xops.MessageMove(ctx, log, acc, messageIDs, "", mailboxID)
}

var xops = webops.XOps{
	DBWrite:    xdbwrite,
	Checkf:     xcheckf,
	Checkuserf: xcheckuserf,
}

// MessageDelete permanently deletes messages, without moving them to the Trash mailbox.
func (Webmail) MessageDelete(ctx context.Context, messageIDs []int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	if len(messageIDs) == 0 {
		return
	}

	xops.MessageDelete(ctx, log, acc, messageIDs)
}

// FlagsAdd adds flags, either system flags like \Seen or custom keywords. The
// flags should be lower-case, but will be converted and verified.
func (Webmail) FlagsAdd(ctx context.Context, messageIDs []int64, flaglist []string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	xops.MessageFlagsAdd(ctx, log, acc, messageIDs, flaglist)
}

// FlagsClear clears flags, either system flags like \Seen or custom keywords.
func (Webmail) FlagsClear(ctx context.Context, messageIDs []int64, flaglist []string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	xops.MessageFlagsClear(ctx, log, acc, messageIDs, flaglist)
}

// MailboxesMarkRead marks all messages in mailboxes as read. Child mailboxes are
// not automatically included, they must explicitly be included in the list of IDs.
func (Webmail) MailboxesMarkRead(ctx context.Context, mailboxIDs []int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	xops.MailboxesMarkRead(ctx, log, acc, mailboxIDs)
}

// MailboxCreate creates a new mailbox.
func (Webmail) MailboxCreate(ctx context.Context, name string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	var err error
	name, _, err = store.CheckMailboxName(name, false)
	xcheckuserf(ctx, err, "checking mailbox name")

	acc.WithWLock(func() {
		var changes []store.Change
		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var exists bool
			var err error
			_, changes, _, exists, err = acc.MailboxCreate(tx, name, store.SpecialUse{})
			if exists {
				xcheckuserf(ctx, errors.New("mailbox already exists"), "creating mailbox")
			}
			xcheckf(ctx, err, "creating mailbox")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxDelete deletes a mailbox and all its messages and annotations.
func (Webmail) MailboxDelete(ctx context.Context, mailboxID int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			mb := xmailboxID(ctx, tx, mailboxID)
			if mb.Name == "Inbox" {
				// Inbox is special in IMAP and cannot be removed.
				xcheckuserf(ctx, errors.New("cannot remove special Inbox"), "checking mailbox")
			}

			var hasChildren bool
			var err error
			changes, hasChildren, err = acc.MailboxDelete(ctx, log, tx, &mb)
			if hasChildren {
				xcheckuserf(ctx, errors.New("mailbox has children"), "deleting mailbox")
			}
			xcheckf(ctx, err, "deleting mailbox")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxEmpty empties a mailbox, removing all messages from the mailbox, but not
// its child mailboxes.
func (Webmail) MailboxEmpty(ctx context.Context, mailboxID int64) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			mb := xmailboxID(ctx, tx, mailboxID)

			qm := bstore.QueryTx[store.Message](tx)
			qm.FilterNonzero(store.Message{MailboxID: mb.ID})
			qm.FilterEqual("Expunged", false)
			qm.SortAsc("UID")
			l, err := qm.List()
			xcheckf(ctx, err, "listing messages to remove")

			if len(l) == 0 {
				xcheckuserf(ctx, errors.New("no messages in mailbox"), "emptying mailbox")
			}

			modseq, err := acc.NextModSeq(tx)
			xcheckf(ctx, err, "next modseq")

			chrem, chmbcounts, err := acc.MessageRemove(log, tx, modseq, &mb, store.RemoveOpts{}, l...)
			xcheckf(ctx, err, "expunge messages")
			changes = append(changes, chrem, chmbcounts)

			err = tx.Update(&mb)
			xcheckf(ctx, err, "updating mailbox for counts")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxRename renames a mailbox, possibly moving it to a new parent. The mailbox
// ID and its messages are unchanged.
func (Webmail) MailboxRename(ctx context.Context, mailboxID int64, newName string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	// Renaming Inbox is special for IMAP. For IMAP we have to implement it per the
	// standard. We can just say no.
	var err error
	newName, _, err = store.CheckMailboxName(newName, false)
	xcheckuserf(ctx, err, "checking new mailbox name")

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			mbsrc := xmailboxID(ctx, tx, mailboxID)
			var err error
			var isInbox, alreadyExists bool
			var modseq store.ModSeq
			changes, isInbox, alreadyExists, err = acc.MailboxRename(tx, &mbsrc, newName, &modseq)
			if isInbox || alreadyExists {
				xcheckuserf(ctx, err, "renaming mailbox")
			}
			xcheckf(ctx, err, "renaming mailbox")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// CompleteRecipient returns autocomplete matches for a recipient, returning the
// matches, most recently used first, and whether this is the full list and further
// requests for longer prefixes aren't necessary.
func (Webmail) CompleteRecipient(ctx context.Context, search string) ([]string, bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	search = strings.ToLower(search)

	var matches []string
	all := true
	acc.WithRLock(func() {
		xdbread(ctx, acc, func(tx *bstore.Tx) {
			type key struct {
				localpart string
				domain    string
			}
			seen := map[key]bool{}

			q := bstore.QueryTx[store.Recipient](tx)
			q.SortDesc("Sent")
			err := q.ForEach(func(r store.Recipient) error {
				k := key{r.Localpart, r.Domain}
				if seen[k] {
					return nil
				}
				// todo: we should have the address including name available in the database for searching. Will result in better matching, and also for the name.
				address := fmt.Sprintf("<%s@%s>", r.Localpart, r.Domain)
				if !strings.Contains(strings.ToLower(address), search) {
					return nil
				}
				if len(matches) >= 20 {
					all = false
					return bstore.StopForEach
				}

				// Look in the message that was sent for a name along with the address.
				m := store.Message{ID: r.MessageID}
				err := tx.Get(&m)
				xcheckf(ctx, err, "get sent message")
				if !m.Expunged && m.ParsedBuf != nil {
					var part message.Part
					err := json.Unmarshal(m.ParsedBuf, &part)
					xcheckf(ctx, err, "parsing part")

					dom, err := dns.ParseDomain(r.Domain)
					xcheckf(ctx, err, "parsing domain of recipient")

					var found bool
					lp := r.Localpart
					checkAddrs := func(l []message.Address) {
						if found {
							return
						}
						for _, a := range l {
							if a.Name != "" && a.User == lp && strings.EqualFold(a.Host, dom.ASCII) {
								found = true
								address = addressString(a, false)
								return
							}
						}
					}
					if part.Envelope != nil {
						env := part.Envelope
						checkAddrs(env.To)
						checkAddrs(env.CC)
						checkAddrs(env.BCC)
					}
				}

				matches = append(matches, address)
				seen[k] = true
				return nil
			})
			xcheckf(ctx, err, "listing recipients")
		})
	})
	return matches, all
}

// addressString returns an address into a string as it could be used in a message header.
func addressString(a message.Address, smtputf8 bool) string {
	host := a.Host
	dom, err := dns.ParseDomain(a.Host)
	if err == nil {
		if smtputf8 && dom.Unicode != "" {
			host = dom.Unicode
		} else {
			host = dom.ASCII
		}
	}
	if a.Name == "" {
		return "<" + a.User + "@" + host + ">"
	}
	// We only quote the name if we have to. ../rfc/5322:679
	const atom = "!#$%&'*+-/=?^_`{|}~"
	name := a.Name
	for _, c := range a.Name {
		if c == '\t' || c == ' ' || c >= 0x80 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsAny(string(c), atom) {
			continue
		}
		// We need to quote.
		q := `"`
		for _, c := range a.Name {
			if c == '\\' || c == '"' {
				q += `\`
			}
			q += string(c)
		}
		q += `"`
		name = q
	}
	return name + " <" + a.User + "@" + host + ">"
}

// MailboxSetSpecialUse sets the special use flags of a mailbox.
func (Webmail) MailboxSetSpecialUse(ctx context.Context, mb store.Mailbox) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			xmb := xmailboxID(ctx, tx, mb.ID)

			modseq, err := acc.NextModSeq(tx)
			xcheckf(ctx, err, "get next modseq")

			// We only allow a single mailbox for each flag (JMAP requirement). So for any flag
			// we set, we clear it for the mailbox(es) that had it, if any.
			clearPrevious := func(clear bool, specialUse string) {
				if !clear {
					return
				}
				var ombl []store.Mailbox
				q := bstore.QueryTx[store.Mailbox](tx)
				q.FilterNotEqual("ID", mb.ID)
				q.FilterEqual(specialUse, true)
				q.Gather(&ombl)
				_, err := q.UpdateFields(map[string]any{specialUse: false, "ModSeq": modseq})
				xcheckf(ctx, err, "updating previous special-use mailboxes")

				for _, omb := range ombl {
					changes = append(changes, omb.ChangeSpecialUse())
				}
			}
			clearPrevious(mb.Archive, "Archive")
			clearPrevious(mb.Draft, "Draft")
			clearPrevious(mb.Junk, "Junk")
			clearPrevious(mb.Sent, "Sent")
			clearPrevious(mb.Trash, "Trash")

			xmb.SpecialUse = mb.SpecialUse
			xmb.ModSeq = modseq
			err = tx.Update(&xmb)
			xcheckf(ctx, err, "updating special-use flags for mailbox")
			changes = append(changes, xmb.ChangeSpecialUse())
		})

		store.BroadcastChanges(acc, changes)
	})
}

// ThreadCollapse saves the ThreadCollapse field for the messages and its
// children. The messageIDs are typically thread roots. But not all roots
// (without parent) of a thread need to have the same collapsed state.
func (Webmail) ThreadCollapse(ctx context.Context, messageIDs []int64, collapse bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	if len(messageIDs) == 0 {
		xcheckuserf(ctx, errors.New("no messages"), "setting collapse")
	}

	acc.WithWLock(func() {
		changes := make([]store.Change, 0, len(messageIDs))
		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			// Gather ThreadIDs to list all potential messages, for a way to get all potential
			// (child) messages. Further refined in FilterFn.
			threadIDs := map[int64]struct{}{}
			msgIDs := map[int64]struct{}{}
			for _, id := range messageIDs {
				m := store.Message{ID: id}
				err := tx.Get(&m)
				if err == bstore.ErrAbsent || err == nil && m.Expunged {
					xcheckuserf(ctx, bstore.ErrAbsent, "get message")
				}
				xcheckf(ctx, err, "get message")
				threadIDs[m.ThreadID] = struct{}{}
				msgIDs[id] = struct{}{}
			}

			var updated []store.Message
			q := bstore.QueryTx[store.Message](tx)
			q.FilterEqual("Expunged", false)
			q.FilterEqual("ThreadID", slicesAny(slices.Sorted(maps.Keys(threadIDs)))...)
			q.FilterNotEqual("ThreadCollapsed", collapse)
			q.FilterFn(func(tm store.Message) bool {
				for _, id := range tm.ThreadParentIDs {
					if _, ok := msgIDs[id]; ok {
						return true
					}
				}
				_, ok := msgIDs[tm.ID]
				return ok
			})
			q.Gather(&updated)
			q.SortAsc("ID") // Consistent order for testing.
			_, err := q.UpdateFields(map[string]any{"ThreadCollapsed": collapse})
			xcheckf(ctx, err, "updating collapse in database")

			for _, m := range updated {
				changes = append(changes, m.ChangeThread())
			}
		})
		store.BroadcastChanges(acc, changes)
	})
}

// ThreadMute saves the ThreadMute field for the messages and their children.
// If messages are muted, they are also marked collapsed.
func (Webmail) ThreadMute(ctx context.Context, messageIDs []int64, mute bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	if len(messageIDs) == 0 {
		xcheckuserf(ctx, errors.New("no messages"), "setting mute")
	}

	acc.WithWLock(func() {
		changes := make([]store.Change, 0, len(messageIDs))
		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			threadIDs := map[int64]struct{}{}
			msgIDs := map[int64]struct{}{}
			for _, id := range messageIDs {
				m := store.Message{ID: id}
				err := tx.Get(&m)
				if err == bstore.ErrAbsent || err == nil && m.Expunged {
					xcheckuserf(ctx, bstore.ErrAbsent, "get message")
				}
				xcheckf(ctx, err, "get message")
				threadIDs[m.ThreadID] = struct{}{}
				msgIDs[id] = struct{}{}
			}

			var updated []store.Message

			q := bstore.QueryTx[store.Message](tx)
			q.FilterEqual("Expunged", false)
			q.FilterEqual("ThreadID", slicesAny(slices.Sorted(maps.Keys(threadIDs)))...)
			q.FilterFn(func(tm store.Message) bool {
				if tm.ThreadMuted == mute && (!mute || tm.ThreadCollapsed) {
					return false
				}
				for _, id := range tm.ThreadParentIDs {
					if _, ok := msgIDs[id]; ok {
						return true
					}
				}
				_, ok := msgIDs[tm.ID]
				return ok
			})
			q.Gather(&updated)
			fields := map[string]any{"ThreadMuted": mute}
			if mute {
				fields["ThreadCollapsed"] = true
			}
			_, err := q.UpdateFields(fields)
			xcheckf(ctx, err, "updating mute in database")

			for _, m := range updated {
				changes = append(changes, m.ChangeThread())
			}
		})
		store.BroadcastChanges(acc, changes)
	})
}

// SecurityResult indicates whether a security feature is supported.
type SecurityResult string

const (
	SecurityResultError SecurityResult = "error"
	SecurityResultNo    SecurityResult = "no"
	SecurityResultYes   SecurityResult = "yes"
	// Unknown whether supported. Finding out may only be (reasonably) possible when
	// trying (e.g. SMTP STARTTLS). Once tried, the result may be cached for future
	// lookups.
	SecurityResultUnknown SecurityResult = "unknown"
)

// RecipientSecurity is a quick analysis of the security properties of delivery to
// the recipient (domain).
type RecipientSecurity struct {
	// Whether recipient domain supports (opportunistic) STARTTLS, as seen during most
	// recent delivery attempt. Will be "unknown" if no delivery to the domain has been
	// attempted yet.
	STARTTLS SecurityResult

	// Whether we have a stored enforced MTA-STS policy, or domain has MTA-STS DNS
	// record.
	MTASTS SecurityResult

	// Whether MX lookup response was DNSSEC-signed.
	DNSSEC SecurityResult

	// Whether first delivery destination has DANE records.
	DANE SecurityResult

	// Whether recipient domain is known to implement the REQUIRETLS SMTP extension.
	// Will be "unknown" if no delivery to the domain has been attempted yet.
	RequireTLS SecurityResult
}

// RecipientSecurity looks up security properties of the address in the
// single-address message addressee (as it appears in a To/Cc/Bcc/etc header).
func (Webmail) RecipientSecurity(ctx context.Context, messageAddressee string) (RecipientSecurity, error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log

	resolver := dns.StrictResolver{Pkg: "webmail", Log: log.Logger}
	return recipientSecurity(ctx, log, resolver, messageAddressee)
}

// logPanic can be called with a defer from a goroutine to prevent the entire program from being shutdown in case of a panic.
func logPanic(ctx context.Context) {
	x := recover()
	if x == nil {
		return
	}
	log := pkglog.WithContext(ctx)
	log.Error("recover from panic", slog.Any("panic", x))
	debug.PrintStack()
	metrics.PanicInc(metrics.Webmail)
}

// separate function for testing with mocked resolver.
func recipientSecurity(ctx context.Context, log mlog.Log, resolver dns.Resolver, messageAddressee string) (RecipientSecurity, error) {
	rs := RecipientSecurity{
		SecurityResultUnknown,
		SecurityResultUnknown,
		SecurityResultUnknown,
		SecurityResultUnknown,
		SecurityResultUnknown,
	}

	parser := mail.AddressParser{WordDecoder: &wordDecoder}
	msgAddr, err := parser.Parse(messageAddressee)
	if err != nil {
		return rs, fmt.Errorf("parsing addressee: %v", err)
	}
	addr, err := smtp.ParseNetMailAddress(msgAddr.Address)
	if err != nil {
		return rs, fmt.Errorf("parsing address: %v", err)
	}

	var wg sync.WaitGroup

	// MTA-STS.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		policy, _, _, err := mtastsdb.Get(ctx, log.Logger, resolver, addr.Domain)
		if policy != nil && policy.Mode == mtasts.ModeEnforce {
			rs.MTASTS = SecurityResultYes
		} else if err == nil {
			rs.MTASTS = SecurityResultNo
		} else {
			rs.MTASTS = SecurityResultError
		}
	}()

	// DNSSEC and DANE.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		_, origNextHopAuthentic, expandedNextHopAuthentic, _, hostPrefs, _, err := smtpclient.GatherDestinations(ctx, log.Logger, resolver, dns.IPDomain{Domain: addr.Domain})
		if err != nil {
			rs.DNSSEC = SecurityResultError
			return
		}
		if origNextHopAuthentic && expandedNextHopAuthentic {
			rs.DNSSEC = SecurityResultYes
		} else {
			rs.DNSSEC = SecurityResultNo
		}

		if !origNextHopAuthentic {
			rs.DANE = SecurityResultNo
			return
		}

		// We're only looking at the first host to deliver to (typically first mx destination).
		if len(hostPrefs) == 0 || hostPrefs[0].Host.Domain.IsZero() {
			return // Should not happen.
		}
		host := hostPrefs[0].Host

		// Resolve the IPs. Required for DANE to prevent bad DNS servers from causing an
		// error result instead of no-DANE result.
		authentic, expandedAuthentic, expandedHost, _, _, err := smtpclient.GatherIPs(ctx, log.Logger, resolver, "ip", host, map[string][]net.IP{})
		if err != nil {
			rs.DANE = SecurityResultError
			return
		}
		if !authentic {
			rs.DANE = SecurityResultNo
			return
		}

		daneRequired, _, _, err := smtpclient.GatherTLSA(ctx, log.Logger, resolver, host.Domain, expandedAuthentic, expandedHost)
		if err != nil {
			rs.DANE = SecurityResultError
			return
		} else if daneRequired {
			rs.DANE = SecurityResultYes
		} else {
			rs.DANE = SecurityResultNo
		}
	}()

	// STARTTLS and RequireTLS
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	err = acc.DB.Read(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[store.RecipientDomainTLS](tx)
		q.FilterNonzero(store.RecipientDomainTLS{Domain: addr.Domain.Name()})
		rd, err := q.Get()
		if err == bstore.ErrAbsent {
			return nil
		} else if err != nil {
			rs.STARTTLS = SecurityResultError
			rs.RequireTLS = SecurityResultError
			log.Errorx("looking up recipient domain", err, slog.Any("domain", addr.Domain))
			return nil
		}
		if rd.STARTTLS {
			rs.STARTTLS = SecurityResultYes
		} else {
			rs.STARTTLS = SecurityResultNo
		}
		if rd.RequireTLS {
			rs.RequireTLS = SecurityResultYes
		} else {
			rs.RequireTLS = SecurityResultNo
		}
		return nil
	})
	xcheckf(ctx, err, "lookup recipient domain")

	wg.Wait()

	return rs, nil
}

// DecodeMIMEWords decodes Q/B-encoded words for a mime headers into UTF-8 text.
func (Webmail) DecodeMIMEWords(ctx context.Context, text string) string {
	s, err := wordDecoder.DecodeHeader(text)
	xcheckuserf(ctx, err, "decoding mime q/b-word encoded header")
	return s
}

// SettingsSave saves settings, e.g. for composing.
func (Webmail) SettingsSave(ctx context.Context, settings store.Settings) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	settings.ID = 1
	err := acc.DB.Update(ctx, &settings)
	xcheckf(ctx, err, "save settings")
}

func (Webmail) RulesetSuggestMove(ctx context.Context, msgID, mbSrcID, mbDstID int64) (listID string, msgFrom string, isRemove bool, rcptTo string, ruleset *config.Ruleset) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account
	log := reqInfo.Log

	xdbread(ctx, acc, func(tx *bstore.Tx) {
		m := xmessageID(ctx, tx, msgID)
		mbSrc := xmailboxID(ctx, tx, mbSrcID)
		mbDst := xmailboxID(ctx, tx, mbDstID)

		if m.RcptToLocalpart == "" && m.RcptToDomain == "" {
			return
		}
		rcptTo = m.RcptToLocalpart.String() + "@" + m.RcptToDomain

		conf, _ := acc.Conf()
		dest := conf.Destinations[rcptTo] // May not be present.
		defaultMailbox := "Inbox"
		if dest.Mailbox != "" {
			defaultMailbox = dest.Mailbox
		}

		// Only suggest rules for messages moved into/out of the default mailbox (Inbox).
		if mbSrc.Name != defaultMailbox && mbDst.Name != defaultMailbox {
			return
		}

		// Check if we have a previous answer "No" answer for moving from/to mailbox.
		exists, err := bstore.QueryTx[store.RulesetNoMailbox](tx).FilterNonzero(store.RulesetNoMailbox{MailboxID: mbSrcID}).FilterEqual("ToMailbox", false).Exists()
		xcheckf(ctx, err, "looking up previous response for source mailbox")
		if exists {
			return
		}
		exists, err = bstore.QueryTx[store.RulesetNoMailbox](tx).FilterNonzero(store.RulesetNoMailbox{MailboxID: mbDstID}).FilterEqual("ToMailbox", true).Exists()
		xcheckf(ctx, err, "looking up previous response for destination mailbox")
		if exists {
			return
		}

		// Parse message for List-Id header.
		state := msgState{acc: acc}
		defer state.clear()
		pm, err := parsedMessage(log, &m, &state, true, false, false)
		xcheckf(ctx, err, "parsing message")

		// The suggested ruleset. Once all is checked, we'll return it.
		var nrs *config.Ruleset

		// If List-Id header is present, we'll treat it as a (mailing) list message.
		if l, ok := pm.Headers["List-Id"]; ok {
			if len(l) != 1 {
				log.Debug("not exactly one list-id header", slog.Any("listid", l))
				return
			}
			var listIDDom dns.Domain
			listID, listIDDom = parseListID(l[0])
			if listID == "" {
				log.Debug("invalid list-id header", slog.String("listid", l[0]))
				return
			}

			// Check if we have a previous "No" answer for this list-id.
			no := store.RulesetNoListID{
				RcptToAddress: rcptTo,
				ListID:        listID,
				ToInbox:       mbDst.Name == "Inbox",
			}
			exists, err = bstore.QueryTx[store.RulesetNoListID](tx).FilterNonzero(no).Exists()
			xcheckf(ctx, err, "looking up previous response for list-id")
			if exists {
				return
			}

			// Find the "ListAllowDomain" to use. We only match and move messages with verified
			// SPF/DKIM. Otherwise spammers could add a list-id headers for mailing lists you
			// are subscribed to, and take advantage of any reduced junk filtering.
			listIDDomStr := listIDDom.Name()

			doms := m.DKIMDomains
			if m.MailFromValidated {
				doms = append(doms, m.MailFromDomain)
			}
			// Sort, we prefer the shortest name, e.g. DKIM signature on whole domain instead
			// of SPF verification of one host.
			sort.Slice(doms, func(i, j int) bool {
				return len(doms[i]) < len(doms[j])
			})
			var listAllowDom string
			for _, dom := range doms {
				if dom == listIDDomStr || strings.HasSuffix(listIDDomStr, "."+dom) {
					listAllowDom = dom
					break
				}
			}
			if listAllowDom == "" {
				return
			}

			listIDRegExp := regexp.QuoteMeta(fmt.Sprintf("<%s>", listID)) + "$"
			nrs = &config.Ruleset{
				HeadersRegexp:   map[string]string{"^list-id$": listIDRegExp},
				ListAllowDomain: listAllowDom,
				Mailbox:         mbDst.Name,
			}
		} else {
			// Otherwise, try to make a rule based on message "From" address.
			if m.MsgFromLocalpart == "" && m.MsgFromDomain == "" {
				return
			}
			msgFrom = m.MsgFromLocalpart.String() + "@" + m.MsgFromDomain

			no := store.RulesetNoMsgFrom{
				RcptToAddress:  rcptTo,
				MsgFromAddress: msgFrom,
				ToInbox:        mbDst.Name == "Inbox",
			}
			exists, err = bstore.QueryTx[store.RulesetNoMsgFrom](tx).FilterNonzero(no).Exists()
			xcheckf(ctx, err, "looking up previous response for message from address")
			if exists {
				return
			}

			nrs = &config.Ruleset{
				MsgFromRegexp: "^" + regexp.QuoteMeta(msgFrom) + "$",
				Mailbox:       mbDst.Name,
			}
		}

		// Only suggest adding/removing rule if it isn't/is present.
		var have bool
		for _, rs := range dest.Rulesets {
			xrs := config.Ruleset{
				MsgFromRegexp:   rs.MsgFromRegexp,
				HeadersRegexp:   rs.HeadersRegexp,
				ListAllowDomain: rs.ListAllowDomain,
				Mailbox:         nrs.Mailbox,
			}
			if xrs.Equal(*nrs) {
				have = true
				break
			}
		}
		isRemove = mbDst.Name == defaultMailbox
		if isRemove {
			nrs.Mailbox = mbSrc.Name
		}
		if isRemove && !have || !isRemove && have {
			return
		}

		// We'll be returning a suggested ruleset.
		nrs.Comment = "by webmail on " + time.Now().Format("2006-01-02")
		ruleset = nrs
	})
	return
}

// Parse the list-id value (the value between <>) from a list-id header.
// Returns an empty string if it couldn't be parsed.
func parseListID(s string) (listID string, dom dns.Domain) {
	// ../rfc/2919:198
	s = strings.TrimRight(s, " \t")
	if !strings.HasSuffix(s, ">") {
		return "", dns.Domain{}
	}
	s = s[:len(s)-1]
	t := strings.Split(s, "<")
	if len(t) == 1 {
		return "", dns.Domain{}
	}
	s = t[len(t)-1]
	dom, err := dns.ParseDomain(s)
	if err != nil {
		return "", dom
	}
	return s, dom
}

func (Webmail) RulesetAdd(ctx context.Context, rcptTo string, ruleset config.Ruleset) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := admin.AccountSave(ctx, reqInfo.Account.Name, func(acc *config.Account) {
		dest, ok := acc.Destinations[rcptTo]
		if !ok {
			// todo: we could find the catchall address and add the rule, or add the address explicitly.
			xcheckuserf(ctx, errors.New("destination address not found in account (hint: if this is a catchall address, configure the address explicitly to configure rulesets)"), "looking up address")
		}

		nd := map[string]config.Destination{}
		for addr, d := range acc.Destinations {
			nd[addr] = d
		}
		dest.Rulesets = append(slices.Clone(dest.Rulesets), ruleset)
		nd[rcptTo] = dest
		acc.Destinations = nd
	})
	xcheckf(ctx, err, "saving account with new ruleset")
}

func (Webmail) RulesetRemove(ctx context.Context, rcptTo string, ruleset config.Ruleset) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := admin.AccountSave(ctx, reqInfo.Account.Name, func(acc *config.Account) {
		dest, ok := acc.Destinations[rcptTo]
		if !ok {
			xcheckuserf(ctx, errors.New("destination address not found in account"), "looking up address")
		}

		nd := map[string]config.Destination{}
		for addr, d := range acc.Destinations {
			nd[addr] = d
		}
		var l []config.Ruleset
		skipped := 0
		for _, rs := range dest.Rulesets {
			if rs.Equal(ruleset) {
				skipped++
			} else {
				l = append(l, rs)
			}
		}
		if skipped != 1 {
			xcheckuserf(ctx, fmt.Errorf("affected %d configured rulesets, expected 1", skipped), "changing rulesets")
		}
		dest.Rulesets = l
		nd[rcptTo] = dest
		acc.Destinations = nd
	})
	xcheckf(ctx, err, "saving account with new ruleset")
}

func (Webmail) RulesetMessageNever(ctx context.Context, rcptTo, listID, msgFrom string, toInbox bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	var err error
	if listID != "" {
		err = acc.DB.Insert(ctx, &store.RulesetNoListID{RcptToAddress: rcptTo, ListID: listID, ToInbox: toInbox})
	} else {
		err = acc.DB.Insert(ctx, &store.RulesetNoMsgFrom{RcptToAddress: rcptTo, MsgFromAddress: msgFrom, ToInbox: toInbox})
	}
	xcheckf(ctx, err, "storing user response")
}

func (Webmail) RulesetMailboxNever(ctx context.Context, mailboxID int64, toMailbox bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	err := acc.DB.Insert(ctx, &store.RulesetNoMailbox{MailboxID: mailboxID, ToMailbox: toMailbox})
	xcheckf(ctx, err, "storing user response")
}

func slicesAny[T any](l []T) []any {
	r := make([]any, len(l))
	for i, v := range l {
		r[i] = v
	}
	return r
}

// SSETypes exists to ensure the generated API contains the types, for use in SSE events.
func (Webmail) SSETypes() (start EventStart, viewErr EventViewErr, viewReset EventViewReset, viewMsgs EventViewMsgs, viewChanges EventViewChanges, msgAdd ChangeMsgAdd, msgRemove ChangeMsgRemove, msgFlags ChangeMsgFlags, msgThread ChangeMsgThread, mailboxRemove ChangeMailboxRemove, mailboxAdd ChangeMailboxAdd, mailboxRename ChangeMailboxRename, mailboxCounts ChangeMailboxCounts, mailboxSpecialUse ChangeMailboxSpecialUse, mailboxKeywords ChangeMailboxKeywords, flags store.Flags) {
	return
}
