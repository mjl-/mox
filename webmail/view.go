package webmail

// todo: may want to add some json omitempty tags to MessageItem, or Message to reduce json size, or just have smaller types that send only the fields that are needed.

import (
	"compress/gzip"
	"context"
	cryptrand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// Request is a request to an SSE connection to send messages, either for a new
// view, to continue with an existing view, or to a cancel an ongoing request.
type Request struct {
	ID int64

	SSEID int64 // SSE connection.

	// To indicate a request is a continuation (more results) of the previous view.
	// Echoed in events, client checks if it is getting results for the latest request.
	ViewID int64

	// If set, this request and its view are canceled. A new view must be started.
	Cancel bool

	Query Query
	Page  Page
}

type ThreadMode string

const (
	ThreadOff    ThreadMode = "off"
	ThreadOn     ThreadMode = "on"
	ThreadUnread ThreadMode = "unread"
)

// Query is a request for messages that match filters, in a given order.
type Query struct {
	OrderAsc  bool // Order by received ascending or desending.
	Threading ThreadMode
	Filter    Filter
	NotFilter NotFilter
}

// AttachmentType is for filtering by attachment type.
type AttachmentType string

const (
	AttachmentIndifferent  AttachmentType = ""
	AttachmentNone         AttachmentType = "none"
	AttachmentAny          AttachmentType = "any"
	AttachmentImage        AttachmentType = "image" // png, jpg, gif, ...
	AttachmentPDF          AttachmentType = "pdf"
	AttachmentArchive      AttachmentType = "archive"      // zip files, tgz, ...
	AttachmentSpreadsheet  AttachmentType = "spreadsheet"  // ods, xlsx, ...
	AttachmentDocument     AttachmentType = "document"     // odt, docx, ...
	AttachmentPresentation AttachmentType = "presentation" // odp, pptx, ...
)

// Filter selects the messages to return. Fields that are set must all match,
// for slices each element by match ("and").
type Filter struct {
	// If -1, then all mailboxes except Trash/Junk/Rejects. Otherwise, only active if > 0.
	MailboxID int64

	// If true, also submailboxes are included in the search.
	MailboxChildrenIncluded bool

	// In case client doesn't know mailboxes and their IDs yet. Only used during sse
	// connection setup, where it is turned into a MailboxID. Filtering only looks at
	// MailboxID.
	MailboxName string

	Words       []string // Case insensitive substring match for each string.
	From        []string
	To          []string // Including Cc and Bcc.
	Oldest      *time.Time
	Newest      *time.Time
	Subject     []string
	Attachments AttachmentType
	Labels      []string
	Headers     [][2]string // Header values can be empty, it's a check if the header is present, regardless of value.
	SizeMin     int64
	SizeMax     int64
}

// NotFilter matches messages that don't match these fields.
type NotFilter struct {
	Words       []string
	From        []string
	To          []string
	Subject     []string
	Attachments AttachmentType
	Labels      []string
}

// Page holds pagination parameters for a request.
type Page struct {
	// Start returning messages after this ID, if > 0. For pagination, fetching the
	// next set of messages.
	AnchorMessageID int64

	// Number of messages to return, must be >= 1, we never return more than 10000 for
	// one request.
	Count int

	// If > 0, return messages until DestMessageID is found. More than Count messages
	// can be returned. For long-running searches, it may take a while before this
	// message if found.
	DestMessageID int64
}

// todo: MessageAddress and MessageEnvelope into message.Address and message.Envelope.

// MessageAddress is like message.Address, but with a dns.Domain, with unicode name
// included.
type MessageAddress struct {
	Name   string // Free-form name for display in mail applications.
	User   string // Localpart, encoded.
	Domain dns.Domain
}

// MessageEnvelope is like message.Envelope, as used in message.Part, but including
// unicode host names for IDNA names.
type MessageEnvelope struct {
	// todo: should get sherpadoc to understand type embeds and embed the non-MessageAddress fields from message.Envelope.
	Date      time.Time
	Subject   string
	From      []MessageAddress
	Sender    []MessageAddress
	ReplyTo   []MessageAddress
	To        []MessageAddress
	CC        []MessageAddress
	BCC       []MessageAddress
	InReplyTo string
	MessageID string
}

// MessageItem is sent by queries, it has derived information analyzed from
// message.Part, made for the needs of the message items in the message list.
// messages.
type MessageItem struct {
	Message     store.Message // Without ParsedBuf and MsgPrefix, for size.
	Envelope    MessageEnvelope
	Attachments []Attachment
	IsSigned    bool
	IsEncrypted bool
	FirstLine   string // Of message body, for showing as preview.
	MatchQuery  bool   // If message does not match query, it can still be included because of threading.
}

// ParsedMessage has more parsed/derived information about a message, intended
// for rendering the (contents of the) message. Information from MessageItem is
// not duplicated.
type ParsedMessage struct {
	ID      int64
	Part    message.Part
	Headers map[string][]string

	// Text parts, can be empty.
	Texts []string

	// Whether there is an HTML part. The webclient renders HTML message parts through
	// an iframe and a separate request with strict CSP headers to prevent script
	// execution and loading of external resources, which isn't possible when loading
	// in iframe with inline HTML because not all browsers support the iframe csp
	// attribute.
	HasHTML bool

	ListReplyAddress *MessageAddress // From List-Post.

	// Information used by MessageItem, not exported in this type.
	envelope    MessageEnvelope
	attachments []Attachment
	isSigned    bool
	isEncrypted bool
	firstLine   string
}

// EventStart is the first message sent on an SSE connection, giving the client
// basic data to populate its UI. After this event, messages will follow quickly in
// an EventViewMsgs event.
type EventStart struct {
	SSEID                int64
	LoginAddress         MessageAddress
	Addresses            []MessageAddress
	DomainAddressConfigs map[string]DomainAddressConfig // ASCII domain to address config.
	MailboxName          string
	Mailboxes            []store.Mailbox
}

// DomainAddressConfig has the address (localpart) configuration for a domain, so
// the webmail client can decide if an address matches the addresses of the
// account.
type DomainAddressConfig struct {
	LocalpartCatchallSeparator string // Can be empty.
	LocalpartCaseSensitive     bool
}

// EventViewMsgs contains messages for a view, possibly a continuation of an
// earlier list of messages.
type EventViewMsgs struct {
	ViewID    int64
	RequestID int64

	// If empty, this was the last message for the request. If non-empty, a list of
	// thread messages. Each with the first message being the reason this thread is
	// included and can be used as AnchorID in followup requests. If the threading mode
	// is "off" in the query, there will always be only a single message. If a thread
	// is sent, all messages in the thread are sent, including those that don't match
	// the query (e.g. from another mailbox). Threads can be displayed based on the
	// ThreadParentIDs field, with possibly slightly different display based on field
	// ThreadMissingLink.
	MessageItems [][]MessageItem

	// If set, will match the target page.DestMessageID from the request.
	ParsedMessage *ParsedMessage

	// If set, there are no more messages in this view at this moment. Messages can be
	// added, typically via Change messages, e.g. for new deliveries.
	ViewEnd bool
}

// EventViewErr indicates an error during a query for messages. The request is
// aborted, no more request-related messages will be sent until the next request.
type EventViewErr struct {
	ViewID    int64
	RequestID int64
	Err       string // To be displayed in client.
	err       error  // Original message, for checking against context.Canceled.
}

// EventViewReset indicates that a request for the next set of messages in a few
// could not be fulfilled, e.g. because the anchor message does not exist anymore.
// The client should clear its list of messages. This can happen before
// EventViewMsgs events are sent.
type EventViewReset struct {
	ViewID    int64
	RequestID int64
}

// EventViewChanges contain one or more changes relevant for the client, either
// with new mailbox total/unseen message counts, or messages added/removed/modified
// (flags) for the current view.
type EventViewChanges struct {
	ViewID  int64
	Changes [][2]any // The first field of [2]any is a string, the second of the Change types below.
}

// ChangeMsgAdd adds a new message and possibly its thread to the view.
type ChangeMsgAdd struct {
	store.ChangeAddUID
	MessageItems []MessageItem
}

// ChangeMsgRemove removes one or more messages from the view.
type ChangeMsgRemove struct {
	store.ChangeRemoveUIDs
}

// ChangeMsgFlags updates flags for one message.
type ChangeMsgFlags struct {
	store.ChangeFlags
}

// ChangeMsgThread updates muted/collapsed fields for one message.
type ChangeMsgThread struct {
	store.ChangeThread
}

// ChangeMailboxRemove indicates a mailbox was removed, including all its messages.
type ChangeMailboxRemove struct {
	store.ChangeRemoveMailbox
}

// ChangeMailboxAdd indicates a new mailbox was added, initially without any messages.
type ChangeMailboxAdd struct {
	Mailbox store.Mailbox
}

// ChangeMailboxRename indicates a mailbox was renamed. Its ID stays the same.
// It could be under a new parent.
type ChangeMailboxRename struct {
	store.ChangeRenameMailbox
}

// ChangeMailboxCounts set new total and unseen message counts for a mailbox.
type ChangeMailboxCounts struct {
	store.ChangeMailboxCounts
}

// ChangeMailboxSpecialUse has updated special-use flags for a mailbox.
type ChangeMailboxSpecialUse struct {
	store.ChangeMailboxSpecialUse
}

// ChangeMailboxKeywords has an updated list of keywords for a mailbox, e.g. after
// a message was added with a keyword that wasn't in the mailbox yet.
type ChangeMailboxKeywords struct {
	store.ChangeMailboxKeywords
}

// View holds the information about the returned data for a query. It is used to
// determine whether mailbox changes should be sent to the client, we only send
// addition/removal/flag-changes of messages that are in view, or would extend it
// if the view is at the end of the results.
type view struct {
	Request Request

	// Received of last message we sent to the client. We use it to decide if a newly
	// delivered message is within the view and the client should get a notification.
	LastMessageReceived time.Time

	// If set, the last message in the query view has been sent. There is no need to do
	// another query, it will not return more data. Used to decide if an event for a
	// new message should be sent.
	End bool

	// Whether message must or must not match mailboxIDs.
	matchMailboxIDs bool
	// Mailboxes to match, can be multiple, for matching children. If empty, there is
	// no filter on mailboxes.
	mailboxIDs map[int64]bool

	// Threads sent to client. New messages for this thread are also sent, regardless
	// of regular query matching, so also for other mailboxes. If the user (re)moved
	// all messages of a thread, they may still receive events for the thread. Only
	// filled when query with threading not off.
	threadIDs map[int64]struct{}
}

// sses tracks all sse connections, and access to them.
var sses = struct {
	sync.Mutex
	gen int64
	m   map[int64]sse
}{m: map[int64]sse{}}

// sse represents an sse connection.
type sse struct {
	ID          int64        // Also returned in EventStart and used in Request to identify the request.
	AccountName string       // Used to check the authenticated user has access to the SSE connection.
	Request     chan Request // Goroutine will receive requests from here, coming from API calls.
}

// called by the goroutine when the connection is closed or breaks.
func (sse sse) unregister() {
	sses.Lock()
	defer sses.Unlock()
	delete(sses.m, sse.ID)

	// Drain any pending requests, preventing blocked goroutines from API calls.
	for {
		select {
		case <-sse.Request:
		default:
			return
		}
	}
}

func sseRegister(accountName string) sse {
	sses.Lock()
	defer sses.Unlock()
	sses.gen++
	v := sse{sses.gen, accountName, make(chan Request, 1)}
	sses.m[v.ID] = v
	return v
}

// sseGet returns a reference to an existing connection if it exists and user
// has access.
func sseGet(id int64, accountName string) (sse, bool) {
	sses.Lock()
	defer sses.Unlock()
	s := sses.m[id]
	if s.AccountName != accountName {
		return sse{}, false
	}
	return s, true
}

// ssetoken is a temporary token that has not yet been used to start an SSE
// connection. Created by Token, consumed by a new SSE connection.
type ssetoken struct {
	token      string // Uniquely generated.
	accName    string
	address    string // Address used to authenticate in call that created the token.
	validUntil time.Time
}

// ssetokens maintains unused tokens. We have just one, but it's a type so we
// can define methods.
type ssetokens struct {
	sync.Mutex
	accountTokens map[string][]ssetoken // Account to max 10 most recent tokens, from old to new.
	tokens        map[string]ssetoken   // Token to details, for finding account for a token.
}

var sseTokens = ssetokens{
	accountTokens: map[string][]ssetoken{},
	tokens:        map[string]ssetoken{},
}

// xgenerate creates and saves a new token. It ensures no more than 10 tokens
// per account exist, removing old ones if needed.
func (x *ssetokens) xgenerate(ctx context.Context, accName, address string) string {
	buf := make([]byte, 16)
	_, err := cryptrand.Read(buf)
	xcheckf(ctx, err, "generating token")
	st := ssetoken{base64.RawURLEncoding.EncodeToString(buf), accName, address, time.Now().Add(time.Minute)}

	x.Lock()
	defer x.Unlock()
	n := len(x.accountTokens[accName])
	if n >= 10 {
		for _, ost := range x.accountTokens[accName][:n-9] {
			delete(x.tokens, ost.token)
		}
		copy(x.accountTokens[accName], x.accountTokens[accName][n-9:])
		x.accountTokens[accName] = x.accountTokens[accName][:9]
	}
	x.accountTokens[accName] = append(x.accountTokens[accName], st)
	x.tokens[st.token] = st
	return st.token
}

// check verifies a token, and consumes it if valid.
func (x *ssetokens) check(token string) (string, string, bool, error) {
	x.Lock()
	defer x.Unlock()

	st, ok := x.tokens[token]
	if !ok {
		return "", "", false, nil
	}
	delete(x.tokens, token)
	if i := slices.Index(x.accountTokens[st.accName], st); i < 0 {
		return "", "", false, errors.New("internal error, could not find token in account")
	} else {
		copy(x.accountTokens[st.accName][i:], x.accountTokens[st.accName][i+1:])
		x.accountTokens[st.accName] = x.accountTokens[st.accName][:len(x.accountTokens[st.accName])-1]
		if len(x.accountTokens[st.accName]) == 0 {
			delete(x.accountTokens, st.accName)
		}
	}
	if time.Now().After(st.validUntil) {
		return "", "", false, nil
	}
	return st.accName, st.address, true, nil
}

// ioErr is panicked on i/o errors in serveEvents and handled in a defer.
type ioErr struct {
	err error
}

// serveEvents serves an SSE connection. Authentication is done through a query
// string parameter "token", a one-time-use token returned by the Token API call.
func serveEvents(ctx context.Context, log *mlog.Log, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Error("internal error: ResponseWriter not a http.Flusher")
		http.Error(w, "500 - internal error - cannot sync to http connection", 500)
		return
	}

	q := r.URL.Query()
	token := q.Get("token")
	if token == "" {
		http.Error(w, "400 - bad request - missing credentials", http.StatusBadRequest)
		return
	}
	accName, address, ok, err := sseTokens.check(token)
	if err != nil {
		http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "400 - bad request - bad token", http.StatusBadRequest)
		return
	}

	// We can simulate a slow SSE connection. It seems firefox doesn't slow down
	// incoming responses with its slow-network similation.
	var waitMin, waitMax time.Duration
	waitMinMsec := q.Get("waitMinMsec")
	waitMaxMsec := q.Get("waitMaxMsec")
	if waitMinMsec != "" && waitMaxMsec != "" {
		if v, err := strconv.ParseInt(waitMinMsec, 10, 64); err != nil {
			http.Error(w, "400 - bad request - parsing waitMinMsec: "+err.Error(), http.StatusBadRequest)
			return
		} else {
			waitMin = time.Duration(v) * time.Millisecond
		}

		if v, err := strconv.ParseInt(waitMaxMsec, 10, 64); err != nil {
			http.Error(w, "400 - bad request - parsing waitMaxMsec: "+err.Error(), http.StatusBadRequest)
			return
		} else {
			waitMax = time.Duration(v) * time.Millisecond
		}
	}

	// Parse the request with initial mailbox/search criteria.
	var req Request
	dec := json.NewDecoder(strings.NewReader(q.Get("request")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "400 - bad request - bad request query string parameter: "+err.Error(), http.StatusBadRequest)
		return
	} else if req.Page.Count <= 0 {
		http.Error(w, "400 - bad request - request cannot have Page.Count 0", http.StatusBadRequest)
		return
	}
	if req.Query.Threading == "" {
		req.Query.Threading = ThreadOff
	}

	var writer *eventWriter

	metricSSEConnections.Inc()
	defer metricSSEConnections.Dec()

	// Below here, error handling cause through xcheckf, which panics with
	// *sherpa.Error, after which we send an error event to the client. We can also get
	// an *ioErr when the connection is broken.
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(*sherpa.Error); ok {
			writer.xsendEvent(ctx, log, "fatalErr", err.Message)
		} else if _, ok := x.(ioErr); ok {
			return
		} else {
			log.WithContext(ctx).Error("serveEvents panic", mlog.Field("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Webmail)
			panic(x)
		}
	}()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")

	// We'll be sending quite a bit of message data (text) in JSON (plenty duplicate
	// keys), so should be quite compressible.
	var out writeFlusher
	gz := acceptsGzip(r)
	if gz {
		h.Set("Content-Encoding", "gzip")
		out, _ = gzip.NewWriterLevel(w, gzip.BestSpeed)
	} else {
		out = nopFlusher{w}
	}
	out = httpFlusher{out, flusher}

	// We'll be writing outgoing SSE events through writer.
	writer = newEventWriter(out, waitMin, waitMax)
	defer writer.close()

	// Fetch initial data.
	acc, err := store.OpenAccount(accName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()
	comm := store.RegisterComm(acc)
	defer comm.Unregister()

	// List addresses that the client can use to send email from.
	accConf, _ := acc.Conf()
	loginAddr, err := smtp.ParseAddress(address)
	xcheckf(ctx, err, "parsing login address")
	_, _, dest, err := mox.FindAccount(loginAddr.Localpart, loginAddr.Domain, false)
	xcheckf(ctx, err, "looking up destination for login address")
	loginName := accConf.FullName
	if dest.FullName != "" {
		loginName = dest.FullName
	}
	loginAddress := MessageAddress{Name: loginName, User: loginAddr.Localpart.String(), Domain: loginAddr.Domain}
	var addresses []MessageAddress
	for a, dest := range accConf.Destinations {
		name := dest.FullName
		if name == "" {
			name = accConf.FullName
		}
		var ma MessageAddress
		if strings.HasPrefix(a, "@") {
			dom, err := dns.ParseDomain(a[1:])
			xcheckf(ctx, err, "parsing destination address for account")
			ma = MessageAddress{Domain: dom}
		} else {
			addr, err := smtp.ParseAddress(a)
			xcheckf(ctx, err, "parsing destination address for account")
			ma = MessageAddress{Name: name, User: addr.Localpart.String(), Domain: addr.Domain}
		}
		addresses = append(addresses, ma)
	}

	// We implicitly start a query. We use the reqctx for the transaction, because the
	// transaction is passed to the query, which can be canceled.
	reqctx, reqctxcancel := context.WithCancel(ctx)
	defer func() {
		// We also cancel in cancelDrain later on, but there is a brief window where the
		// context wouldn't be canceled.
		if reqctxcancel != nil {
			reqctxcancel()
			reqctxcancel = nil
		}
	}()

	// qtx is kept around during connection initialization, until we pass it off to the
	// goroutine that starts querying for messages.
	var qtx *bstore.Tx
	defer func() {
		if qtx != nil {
			err := qtx.Rollback()
			log.Check(err, "rolling back")
		}
	}()

	var mbl []store.Mailbox

	// We only take the rlock when getting the tx.
	acc.WithRLock(func() {
		// Now a read-only transaction we'll use during the query.
		qtx, err = acc.DB.Begin(reqctx, false)
		xcheckf(ctx, err, "begin transaction")

		mbl, err = bstore.QueryTx[store.Mailbox](qtx).List()
		xcheckf(ctx, err, "list mailboxes")
	})

	// Find the designated mailbox if a mailbox name is set, or there are no filters at all.
	var zerofilter Filter
	var zeronotfilter NotFilter
	var mailbox store.Mailbox
	var mailboxPrefixes []string
	var matchMailboxes bool
	mailboxIDs := map[int64]bool{}
	mailboxName := req.Query.Filter.MailboxName
	if mailboxName != "" || reflect.DeepEqual(req.Query.Filter, zerofilter) && reflect.DeepEqual(req.Query.NotFilter, zeronotfilter) {
		if mailboxName == "" {
			mailboxName = "Inbox"
		}

		var inbox store.Mailbox
		for _, e := range mbl {
			if e.Name == mailboxName {
				mailbox = e
			}
			if e.Name == "Inbox" {
				inbox = e
			}
		}
		if mailbox.ID == 0 {
			mailbox = inbox
		}
		if mailbox.ID == 0 {
			xcheckf(ctx, errors.New("inbox not found"), "setting initial mailbox")
		}
		req.Query.Filter.MailboxID = mailbox.ID
		req.Query.Filter.MailboxName = ""
		mailboxPrefixes = []string{mailbox.Name + "/"}
		matchMailboxes = true
		mailboxIDs[mailbox.ID] = true
	} else {
		matchMailboxes, mailboxIDs, mailboxPrefixes = xprepareMailboxIDs(ctx, qtx, req.Query.Filter, accConf.RejectsMailbox)
	}
	if req.Query.Filter.MailboxChildrenIncluded {
		xgatherMailboxIDs(ctx, qtx, mailboxIDs, mailboxPrefixes)
	}

	// todo: write a last-event-id based on modseq? if last-event-id is present, we would have to send changes to mailboxes, messages, hopefully reducing the amount of data sent.

	sse := sseRegister(acc.Name)
	defer sse.unregister()

	// Per-domain localpart config so webclient can decide if an address belongs to the account.
	domainAddressConfigs := map[string]DomainAddressConfig{}
	for _, a := range addresses {
		dom, _ := mox.Conf.Domain(a.Domain)
		domainAddressConfigs[a.Domain.ASCII] = DomainAddressConfig{dom.LocalpartCatchallSeparator, dom.LocalpartCaseSensitive}
	}

	// Write first event, allowing client to fill its UI with mailboxes.
	start := EventStart{sse.ID, loginAddress, addresses, domainAddressConfigs, mailbox.Name, mbl}
	writer.xsendEvent(ctx, log, "start", start)

	// The goroutine doing the querying will send messages on these channels, which
	// result in an event being written on the SSE connection.
	viewMsgsc := make(chan EventViewMsgs)
	viewErrc := make(chan EventViewErr)
	viewResetc := make(chan EventViewReset)
	donec := make(chan int64) // When request is done.

	// Start a view, it determines if we send a change to the client. And start an
	// implicit query for messages, we'll send the messages to the client which can
	// fill its ui with messages.
	v := view{req, time.Time{}, false, matchMailboxes, mailboxIDs, map[int64]struct{}{}}
	go viewRequestTx(reqctx, log, acc, qtx, v, viewMsgsc, viewErrc, viewResetc, donec)
	qtx = nil // viewRequestTx closes qtx

	// When canceling a query, we must drain its messages until it says it is done.
	// Otherwise the sending goroutine would hang indefinitely on a channel send.
	cancelDrain := func() {
		if reqctxcancel != nil {
			// Cancel the goroutine doing the querying.
			reqctxcancel()
			reqctx = nil
			reqctxcancel = nil
		} else {
			return
		}

		// Drain events until done.
		for {
			select {
			case <-viewMsgsc:
			case <-viewErrc:
			case <-viewResetc:
			case <-donec:
				return
			}
		}
	}

	// If we stop and a query is in progress, we must drain the channel it will send on.
	defer cancelDrain()

	// Changes broadcasted by other connections on this account. If applicable for the
	// connection/view, we send events.
	xprocessChanges := func(changes []store.Change) {
		taggedChanges := [][2]any{}

		// We get a transaction first time we need it.
		var xtx *bstore.Tx
		defer func() {
			if xtx != nil {
				err := xtx.Rollback()
				log.Check(err, "rolling back transaction")
			}
		}()
		ensureTx := func() error {
			if xtx != nil {
				return nil
			}
			acc.RLock()
			defer acc.RUnlock()
			var err error
			xtx, err = acc.DB.Begin(ctx, false)
			return err
		}
		// This getmsg will now only be called mailboxID+UID, not with messageID set.
		// todo jmap: change store.Change* to include MessageID's? would mean duplication of information resulting in possible mismatch.
		getmsg := func(messageID int64, mailboxID int64, uid store.UID) (store.Message, error) {
			if err := ensureTx(); err != nil {
				return store.Message{}, fmt.Errorf("transaction: %v", err)
			}
			return bstore.QueryTx[store.Message](xtx).FilterEqual("Expunged", false).FilterNonzero(store.Message{MailboxID: mailboxID, UID: uid}).Get()
		}

		// Return uids that are within range in view. Because the end has been reached, or
		// because the UID is not after the last message.
		xchangedUIDs := func(mailboxID int64, uids []store.UID, isRemove bool) (changedUIDs []store.UID) {
			uidsAny := make([]any, len(uids))
			for i, uid := range uids {
				uidsAny[i] = uid
			}
			err := ensureTx()
			xcheckf(ctx, err, "transaction")
			q := bstore.QueryTx[store.Message](xtx)
			q.FilterNonzero(store.Message{MailboxID: mailboxID})
			q.FilterEqual("UID", uidsAny...)
			mbOK := v.matchesMailbox(mailboxID)
			err = q.ForEach(func(m store.Message) error {
				_, thread := v.threadIDs[m.ThreadID]
				if thread || mbOK && (v.inRange(m) || isRemove && m.Expunged) {
					changedUIDs = append(changedUIDs, m.UID)
				}
				return nil
			})
			xcheckf(ctx, err, "fetching messages for change")
			return changedUIDs
		}

		// Forward changes that are relevant to the current view.
		for _, change := range changes {
			switch c := change.(type) {
			case store.ChangeAddUID:
				ok, err := v.matches(log, acc, true, 0, c.MailboxID, c.UID, c.Flags, c.Keywords, getmsg)
				xcheckf(ctx, err, "matching new message against view")
				m, err := getmsg(0, c.MailboxID, c.UID)
				xcheckf(ctx, err, "get message")
				_, thread := v.threadIDs[m.ThreadID]
				if !ok && !thread {
					continue
				}
				state := msgState{acc: acc}
				mi, err := messageItem(log, m, &state)
				state.clear()
				xcheckf(ctx, err, "make messageitem")
				mi.MatchQuery = ok

				mil := []MessageItem{mi}
				if !thread && req.Query.Threading != ThreadOff {
					err := ensureTx()
					xcheckf(ctx, err, "transaction")
					more, _, err := gatherThread(log, xtx, acc, v, m, 0, false)
					xcheckf(ctx, err, "gathering thread messages for id %d, thread %d", m.ID, m.ThreadID)
					mil = append(mil, more...)
					v.threadIDs[m.ThreadID] = struct{}{}
				}

				taggedChanges = append(taggedChanges, [2]any{"ChangeMsgAdd", ChangeMsgAdd{c, mil}})

				// If message extends the view, store it as such.
				if !v.Request.Query.OrderAsc && m.Received.Before(v.LastMessageReceived) || v.Request.Query.OrderAsc && m.Received.After(v.LastMessageReceived) {
					v.LastMessageReceived = m.Received
				}

			case store.ChangeRemoveUIDs:
				// We may send changes for uids the client doesn't know, that's fine.
				changedUIDs := xchangedUIDs(c.MailboxID, c.UIDs, true)
				if len(changedUIDs) == 0 {
					continue
				}
				ch := ChangeMsgRemove{c}
				ch.UIDs = changedUIDs
				taggedChanges = append(taggedChanges, [2]any{"ChangeMsgRemove", ch})

			case store.ChangeFlags:
				// We may send changes for uids the client doesn't know, that's fine.
				changedUIDs := xchangedUIDs(c.MailboxID, []store.UID{c.UID}, false)
				if len(changedUIDs) == 0 {
					continue
				}
				ch := ChangeMsgFlags{c}
				ch.UID = changedUIDs[0]
				taggedChanges = append(taggedChanges, [2]any{"ChangeMsgFlags", ch})

			case store.ChangeThread:
				// Change in muted/collaped state, just always ship it.
				taggedChanges = append(taggedChanges, [2]any{"ChangeMsgThread", ChangeMsgThread{c}})

			case store.ChangeRemoveMailbox:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxRemove", ChangeMailboxRemove{c}})

			case store.ChangeAddMailbox:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxAdd", ChangeMailboxAdd{c.Mailbox}})

			case store.ChangeRenameMailbox:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxRename", ChangeMailboxRename{c}})

			case store.ChangeMailboxCounts:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxCounts", ChangeMailboxCounts{c}})

			case store.ChangeMailboxSpecialUse:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxSpecialUse", ChangeMailboxSpecialUse{c}})

			case store.ChangeMailboxKeywords:
				taggedChanges = append(taggedChanges, [2]any{"ChangeMailboxKeywords", ChangeMailboxKeywords{c}})

			case store.ChangeAddSubscription:
				// Webmail does not care about subscriptions.

			default:
				panic(fmt.Sprintf("missing case for change %T", c))
			}
		}

		if len(taggedChanges) > 0 {
			viewChanges := EventViewChanges{v.Request.ViewID, taggedChanges}
			writer.xsendEvent(ctx, log, "viewChanges", viewChanges)
		}
	}

	timer := time.NewTimer(5 * time.Minute) // For keepalives.
	defer timer.Stop()
	for {
		if writer.wrote {
			timer.Reset(5 * time.Minute)
			writer.wrote = false
		}

		pending := comm.Pending
		if reqctx != nil {
			pending = nil
		}

		select {
		case <-mox.Shutdown.Done():
			writer.xsendEvent(ctx, log, "fatalErr", "server is shutting down")
			// Work around go vet, it doesn't see defer cancelDrain.
			if reqctxcancel != nil {
				reqctxcancel()
			}
			return

		case <-timer.C:
			_, err := fmt.Fprintf(out, ": keepalive\n\n")
			if err != nil {
				log.Errorx("write keepalive", err)
				// Work around go vet, it doesn't see defer cancelDrain.
				if reqctxcancel != nil {
					reqctxcancel()
				}
				return
			}
			out.Flush()
			writer.wrote = true

		case vm := <-viewMsgsc:
			if vm.RequestID != v.Request.ID || vm.ViewID != v.Request.ViewID {
				panic(fmt.Sprintf("received msgs for view,request id %d,%d instead of %d,%d", vm.ViewID, vm.RequestID, v.Request.ViewID, v.Request.ID))
			}
			if vm.ViewEnd {
				v.End = true
			}
			if len(vm.MessageItems) > 0 {
				v.LastMessageReceived = vm.MessageItems[len(vm.MessageItems)-1][0].Message.Received
			}
			writer.xsendEvent(ctx, log, "viewMsgs", vm)

		case ve := <-viewErrc:
			if ve.RequestID != v.Request.ID || ve.ViewID != v.Request.ViewID {
				panic(fmt.Sprintf("received err for view,request id %d,%d instead of %d,%d", ve.ViewID, ve.RequestID, v.Request.ViewID, v.Request.ID))
			}
			if errors.Is(ve.err, context.Canceled) || moxio.IsClosed(ve.err) {
				// Work around go vet, it doesn't see defer cancelDrain.
				if reqctxcancel != nil {
					reqctxcancel()
				}
				return
			}
			writer.xsendEvent(ctx, log, "viewErr", ve)

		case vr := <-viewResetc:
			if vr.RequestID != v.Request.ID || vr.ViewID != v.Request.ViewID {
				panic(fmt.Sprintf("received reset for view,request id %d,%d instead of %d,%d", vr.ViewID, vr.RequestID, v.Request.ViewID, v.Request.ID))
			}
			writer.xsendEvent(ctx, log, "viewReset", vr)

		case id := <-donec:
			if id != v.Request.ID {
				panic(fmt.Sprintf("received done for request id %d instead of %d", id, v.Request.ID))
			}
			if reqctxcancel != nil {
				reqctxcancel()
			}
			reqctx = nil
			reqctxcancel = nil

		case req := <-sse.Request:
			if reqctx != nil {
				cancelDrain()
			}
			if req.Cancel {
				v = view{req, time.Time{}, false, false, nil, nil}
				continue
			}

			reqctx, reqctxcancel = context.WithCancel(ctx)

			stop := func() (stop bool) {
				// rtx is handed off viewRequestTx below, but we must clean it up in case of errors.
				var rtx *bstore.Tx
				var err error
				defer func() {
					if rtx != nil {
						err = rtx.Rollback()
						log.Check(err, "rolling back transaction")
					}
				}()
				acc.WithRLock(func() {
					rtx, err = acc.DB.Begin(reqctx, false)
				})
				if err != nil {
					reqctxcancel()
					reqctx = nil
					reqctxcancel = nil

					if errors.Is(err, context.Canceled) {
						return true
					}
					err := fmt.Errorf("begin transaction: %v", err)
					viewErr := EventViewErr{v.Request.ViewID, v.Request.ID, err.Error(), err}
					writer.xsendEvent(ctx, log, "viewErr", viewErr)
					return false
				}

				// Reset view state for new query.
				if req.ViewID != v.Request.ViewID {
					matchMailboxes, mailboxIDs, mailboxPrefixes := xprepareMailboxIDs(ctx, rtx, req.Query.Filter, accConf.RejectsMailbox)
					if req.Query.Filter.MailboxChildrenIncluded {
						xgatherMailboxIDs(ctx, rtx, mailboxIDs, mailboxPrefixes)
					}
					v = view{req, time.Time{}, false, matchMailboxes, mailboxIDs, map[int64]struct{}{}}
				} else {
					v.Request = req
				}
				go viewRequestTx(reqctx, log, acc, rtx, v, viewMsgsc, viewErrc, viewResetc, donec)
				rtx = nil
				return false
			}()
			if stop {
				return
			}

		case <-pending:
			xprocessChanges(comm.Get())

		case <-ctx.Done():
			// Work around go vet, it doesn't see defer cancelDrain.
			if reqctxcancel != nil {
				reqctxcancel()
			}
			return
		}
	}
}

// xprepareMailboxIDs prepare the first half of filters for mailboxes, based on
// f.MailboxID (-1 is special). matchMailboxes indicates whether the IDs in
// mailboxIDs must or must not match. mailboxPrefixes is for use with
// xgatherMailboxIDs to gather children of the mailboxIDs.
func xprepareMailboxIDs(ctx context.Context, tx *bstore.Tx, f Filter, rejectsMailbox string) (matchMailboxes bool, mailboxIDs map[int64]bool, mailboxPrefixes []string) {
	matchMailboxes = true
	mailboxIDs = map[int64]bool{}
	if f.MailboxID == -1 {
		matchMailboxes = false
		// Add the trash, junk and account rejects mailbox.
		err := bstore.QueryTx[store.Mailbox](tx).ForEach(func(mb store.Mailbox) error {
			if mb.Trash || mb.Junk || mb.Name == rejectsMailbox {
				mailboxPrefixes = append(mailboxPrefixes, mb.Name+"/")
				mailboxIDs[mb.ID] = true
			}
			return nil
		})
		xcheckf(ctx, err, "finding trash/junk/rejects mailbox")
	} else if f.MailboxID > 0 {
		mb := store.Mailbox{ID: f.MailboxID}
		err := tx.Get(&mb)
		xcheckf(ctx, err, "get mailbox")
		mailboxIDs[f.MailboxID] = true
		mailboxPrefixes = []string{mb.Name + "/"}
	}
	return
}

// xgatherMailboxIDs adds all mailboxes with a prefix matching any of
// mailboxPrefixes to mailboxIDs, to expand filtering to children of mailboxes.
func xgatherMailboxIDs(ctx context.Context, tx *bstore.Tx, mailboxIDs map[int64]bool, mailboxPrefixes []string) {
	// Gather more mailboxes to filter on, based on mailboxPrefixes.
	if len(mailboxPrefixes) == 0 {
		return
	}
	err := bstore.QueryTx[store.Mailbox](tx).ForEach(func(mb store.Mailbox) error {
		for _, p := range mailboxPrefixes {
			if strings.HasPrefix(mb.Name, p) {
				mailboxIDs[mb.ID] = true
				break
			}
		}
		return nil
	})
	xcheckf(ctx, err, "gathering mailboxes")
}

// matchesMailbox returns whether a mailbox matches the view.
func (v view) matchesMailbox(mailboxID int64) bool {
	return len(v.mailboxIDs) == 0 || v.matchMailboxIDs && v.mailboxIDs[mailboxID] || !v.matchMailboxIDs && !v.mailboxIDs[mailboxID]
}

// inRange returns whether m is within the range for the view, whether a change for
// this message should be sent to the client so it can update its state.
func (v view) inRange(m store.Message) bool {
	return v.End || !v.Request.Query.OrderAsc && !m.Received.Before(v.LastMessageReceived) || v.Request.Query.OrderAsc && !m.Received.After(v.LastMessageReceived)
}

// matches checks if the message, identified by either messageID or mailboxID+UID,
// is in the current "view" (i.e. passing the filters, and if checkRange is set
// also if within the range of sent messages based on sort order and the last seen
// message). getmsg retrieves the message, which may be necessary depending on the
// active filters. Used to determine if a store.Change with a new message should be
// sent, and for the destination and anchor messages in view requests.
func (v view) matches(log *mlog.Log, acc *store.Account, checkRange bool, messageID int64, mailboxID int64, uid store.UID, flags store.Flags, keywords []string, getmsg func(int64, int64, store.UID) (store.Message, error)) (match bool, rerr error) {
	var m store.Message
	ensureMessage := func() bool {
		if m.ID == 0 && rerr == nil {
			m, rerr = getmsg(messageID, mailboxID, uid)
		}
		return rerr == nil
	}

	q := v.Request.Query

	// Warning: Filters must be kept in sync between queryMessage and view.matches.

	// Check filters.
	if len(v.mailboxIDs) > 0 && (!ensureMessage() || v.matchMailboxIDs && !v.mailboxIDs[m.MailboxID] || !v.matchMailboxIDs && v.mailboxIDs[m.MailboxID]) {
		return false, rerr
	}
	// note: anchorMessageID is not relevant for matching.
	flagfilter := q.flagFilterFn()
	if flagfilter != nil && !flagfilter(flags, keywords) {
		return false, rerr
	}

	if q.Filter.Oldest != nil && (!ensureMessage() || m.Received.Before(*q.Filter.Oldest)) {
		return false, rerr
	}
	if q.Filter.Newest != nil && (!ensureMessage() || !m.Received.Before(*q.Filter.Newest)) {
		return false, rerr
	}

	if q.Filter.SizeMin > 0 && (!ensureMessage() || m.Size < q.Filter.SizeMin) {
		return false, rerr
	}
	if q.Filter.SizeMax > 0 && (!ensureMessage() || m.Size > q.Filter.SizeMax) {
		return false, rerr
	}

	state := msgState{acc: acc}
	defer func() {
		if rerr == nil && state.err != nil {
			rerr = state.err
		}
		state.clear()
	}()

	attachmentFilter := q.attachmentFilterFn(log, acc, &state)
	if attachmentFilter != nil && (!ensureMessage() || !attachmentFilter(m)) {
		return false, rerr
	}

	envFilter := q.envFilterFn(log, &state)
	if envFilter != nil && (!ensureMessage() || !envFilter(m)) {
		return false, rerr
	}

	headerFilter := q.headerFilterFn(log, &state)
	if headerFilter != nil && (!ensureMessage() || !headerFilter(m)) {
		return false, rerr
	}

	wordsFilter := q.wordsFilterFn(log, &state)
	if wordsFilter != nil && (!ensureMessage() || !wordsFilter(m)) {
		return false, rerr
	}

	// Now check that we are either within the sorting order, or "last" was sent.
	if !checkRange || v.End || ensureMessage() && v.inRange(m) {
		return true, rerr
	}
	return false, rerr
}

type msgResp struct {
	err     error          // If set, an error happened and fields below are not set.
	reset   bool           // If set, the anchor message does not exist (anymore?) and we are sending messages from the start, fields below not set.
	viewEnd bool           // If set, the last message for the view was seen, no more should be requested, fields below not set.
	mil     []MessageItem  // If none of the cases above apply, the messages that was found matching the query. First message was reason the thread is returned, for use as AnchorID in followup request.
	pm      *ParsedMessage // If m was the target page.DestMessageID, or this is the first match, this is the parsed message of mi.
}

// viewRequestTx executes a request (query with filters, pagination) by
// launching a new goroutine with queryMessages, receiving results as msgResp,
// and sending Event* to the SSE connection.
//
// It always closes tx.
func viewRequestTx(ctx context.Context, log *mlog.Log, acc *store.Account, tx *bstore.Tx, v view, msgc chan EventViewMsgs, errc chan EventViewErr, resetc chan EventViewReset, donec chan int64) {
	defer func() {
		err := tx.Rollback()
		log.Check(err, "rolling back query transaction")

		donec <- v.Request.ID

		x := recover() // Should not happen, but don't take program down if it does.
		if x != nil {
			log.WithContext(ctx).Error("viewRequestTx panic", mlog.Field("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Webmailrequest)
		}
	}()

	var msgitems [][]MessageItem // Gathering for 300ms, then flushing.
	var parsedMessage *ParsedMessage
	var viewEnd bool

	var immediate bool // No waiting, flush immediate.
	t := time.NewTimer(300 * time.Millisecond)
	defer t.Stop()

	sendViewMsgs := func(force bool) {
		if len(msgitems) == 0 && !force {
			return
		}

		immediate = false
		msgc <- EventViewMsgs{v.Request.ViewID, v.Request.ID, msgitems, parsedMessage, viewEnd}
		msgitems = nil
		parsedMessage = nil
		t.Reset(300 * time.Millisecond)
	}

	// todo: should probably rewrite code so we don't start yet another goroutine, but instead handle the query responses directly (through a struct that keeps state?) in the sse connection goroutine.

	mrc := make(chan msgResp, 1)
	go queryMessages(ctx, log, acc, tx, v, mrc)

	for {
		select {
		case mr, ok := <-mrc:
			if !ok {
				sendViewMsgs(false)
				// Empty message list signals this query is done.
				msgc <- EventViewMsgs{v.Request.ViewID, v.Request.ID, nil, nil, false}
				return
			}
			if mr.err != nil {
				sendViewMsgs(false)
				errc <- EventViewErr{v.Request.ViewID, v.Request.ID, mr.err.Error(), mr.err}
				return
			}
			if mr.reset {
				resetc <- EventViewReset{v.Request.ViewID, v.Request.ID}
				continue
			}
			if mr.viewEnd {
				viewEnd = true
				sendViewMsgs(true)
				return
			}

			msgitems = append(msgitems, mr.mil)
			if mr.pm != nil {
				parsedMessage = mr.pm
			}
			if immediate {
				sendViewMsgs(true)
			}

		case <-t.C:
			if len(msgitems) == 0 {
				// Nothing to send yet. We'll send immediately when the next message comes in.
				immediate = true
			} else {
				sendViewMsgs(false)
			}
		}
	}
}

// queryMessages executes a query, with filter, pagination, destination message id
// to fetch (the message that the client had in view and wants to display again).
// It sends on msgc, with several types of messages: errors, whether the view is
// reset due to missing AnchorMessageID, and when the end of the view was reached
// and/or for a message.
func queryMessages(ctx context.Context, log *mlog.Log, acc *store.Account, tx *bstore.Tx, v view, mrc chan msgResp) {
	defer func() {
		x := recover() // Should not happen, but don't take program down if it does.
		if x != nil {
			log.WithContext(ctx).Error("queryMessages panic", mlog.Field("err", x))
			debug.PrintStack()
			mrc <- msgResp{err: fmt.Errorf("query failed")}
			metrics.PanicInc(metrics.Webmailquery)
		}

		close(mrc)
	}()

	query := v.Request.Query
	page := v.Request.Page

	// Warning: Filters must be kept in sync between queryMessage and view.matches.

	checkMessage := func(id int64) (valid bool, rerr error) {
		m := store.Message{ID: id}
		err := tx.Get(&m)
		if err == bstore.ErrAbsent || err == nil && m.Expunged {
			return false, nil
		} else if err != nil {
			return false, err
		} else {
			return v.matches(log, acc, false, m.ID, m.MailboxID, m.UID, m.Flags, m.Keywords, func(int64, int64, store.UID) (store.Message, error) {
				return m, nil
			})
		}
	}

	// Check if AnchorMessageID exists and matches filter. If not, we will reset the view.
	if page.AnchorMessageID > 0 {
		// Check if message exists and (still) matches the filter.
		// todo: if AnchorMessageID exists but no longer matches the filter, we are resetting the view, but could handle it more gracefully in the future. if the message is in a different mailbox, we cannot query as efficiently, we'll have to read through more messages.
		if valid, err := checkMessage(page.AnchorMessageID); err != nil {
			mrc <- msgResp{err: fmt.Errorf("querying AnchorMessageID: %v", err)}
			return
		} else if !valid {
			mrc <- msgResp{reset: true}
			page.AnchorMessageID = 0
		}
	}

	// Check if page.DestMessageID exists and matches filter. If not, we will ignore
	// it instead of continuing to send message till the end of the view.
	if page.DestMessageID > 0 {
		if valid, err := checkMessage(page.DestMessageID); err != nil {
			mrc <- msgResp{err: fmt.Errorf("querying requested message: %v", err)}
			return
		} else if !valid {
			page.DestMessageID = 0
		}
	}

	// todo optimize: we would like to have more filters directly on the database if they can use an index. eg if there is a keyword filter and no mailbox filter.

	q := bstore.QueryTx[store.Message](tx)
	q.FilterEqual("Expunged", false)
	if len(v.mailboxIDs) > 0 {
		if len(v.mailboxIDs) == 1 && v.matchMailboxIDs {
			// Should result in fast indexed query.
			for mbID := range v.mailboxIDs {
				q.FilterNonzero(store.Message{MailboxID: mbID})
			}
		} else {
			idsAny := make([]any, 0, len(v.mailboxIDs))
			for mbID := range v.mailboxIDs {
				idsAny = append(idsAny, mbID)
			}
			if v.matchMailboxIDs {
				q.FilterEqual("MailboxID", idsAny...)
			} else {
				q.FilterNotEqual("MailboxID", idsAny...)
			}
		}
	}

	// If we are looking for an anchor, keep skipping message early (cheaply) until we've seen it.
	if page.AnchorMessageID > 0 {
		var seen = false
		q.FilterFn(func(m store.Message) bool {
			if seen {
				return true
			}
			seen = m.ID == page.AnchorMessageID
			return false
		})
	}

	// We may be added filters the the query below. The FilterFn signature does not
	// implement reporting errors, or anything else, just a bool. So when making the
	// filter functions, we give them a place to store parsed message state, and an
	// error. We check the error during and after query execution.
	state := msgState{acc: acc}
	defer state.clear()

	flagfilter := query.flagFilterFn()
	if flagfilter != nil {
		q.FilterFn(func(m store.Message) bool {
			return flagfilter(m.Flags, m.Keywords)
		})
	}

	if query.Filter.Oldest != nil {
		q.FilterGreaterEqual("Received", *query.Filter.Oldest)
	}
	if query.Filter.Newest != nil {
		q.FilterLessEqual("Received", *query.Filter.Newest)
	}

	if query.Filter.SizeMin > 0 {
		q.FilterGreaterEqual("Size", query.Filter.SizeMin)
	}
	if query.Filter.SizeMax > 0 {
		q.FilterLessEqual("Size", query.Filter.SizeMax)
	}

	attachmentFilter := query.attachmentFilterFn(log, acc, &state)
	if attachmentFilter != nil {
		q.FilterFn(attachmentFilter)
	}

	envFilter := query.envFilterFn(log, &state)
	if envFilter != nil {
		q.FilterFn(envFilter)
	}

	headerFilter := query.headerFilterFn(log, &state)
	if headerFilter != nil {
		q.FilterFn(headerFilter)
	}

	wordsFilter := query.wordsFilterFn(log, &state)
	if wordsFilter != nil {
		q.FilterFn(wordsFilter)
	}

	if query.OrderAsc {
		q.SortAsc("Received")
	} else {
		q.SortDesc("Received")
	}
	found := page.DestMessageID <= 0
	end := true
	have := 0
	err := q.ForEach(func(m store.Message) error {
		// Check for an error in one of the filters, propagate it.
		if state.err != nil {
			return state.err
		}

		if have >= page.Count && found || have > 10000 {
			end = false
			return bstore.StopForEach
		}

		if _, ok := v.threadIDs[m.ThreadID]; ok {
			// Message was already returned as part of a thread.
			return nil
		}

		var pm *ParsedMessage
		if m.ID == page.DestMessageID || page.DestMessageID == 0 && have == 0 && page.AnchorMessageID == 0 {
			// For threads, if there was not DestMessageID, we may be getting the newest
			// message. For an initial view, this isn't necessarily the first the user is
			// expected to read first, that would be the first unread, which we'll get below
			// when gathering the thread.
			found = true
			xpm, err := parsedMessage(log, m, &state, true, false)
			if err != nil {
				return fmt.Errorf("parsing message %d: %v", m.ID, err)
			}
			pm = &xpm
		}

		mi, err := messageItem(log, m, &state)
		if err != nil {
			return fmt.Errorf("making messageitem for message %d: %v", m.ID, err)
		}
		mil := []MessageItem{mi}
		if query.Threading != ThreadOff {
			more, xpm, err := gatherThread(log, tx, acc, v, m, page.DestMessageID, page.AnchorMessageID == 0 && have == 0)
			if err != nil {
				return fmt.Errorf("gathering thread messages for id %d, thread %d: %v", m.ID, m.ThreadID, err)
			}
			if xpm != nil {
				pm = xpm
				found = true
			}
			mil = append(mil, more...)
			v.threadIDs[m.ThreadID] = struct{}{}

			// Calculate how many messages the frontend is going to show, and only count those as returned.
			collapsed := map[int64]bool{}
			for _, mi := range mil {
				collapsed[mi.Message.ID] = mi.Message.ThreadCollapsed
			}
			unread := map[int64]bool{} // Propagated to thread root.
			if query.Threading == ThreadUnread {
				for _, mi := range mil {
					m := mi.Message
					if m.Seen {
						continue
					}
					unread[m.ID] = true
					for _, id := range m.ThreadParentIDs {
						unread[id] = true
					}
				}
			}
			for _, mi := range mil {
				m := mi.Message
				threadRoot := true
				rootID := m.ID
				for _, id := range m.ThreadParentIDs {
					if _, ok := collapsed[id]; ok {
						threadRoot = false
						rootID = id
					}
				}
				if threadRoot || (query.Threading == ThreadOn && !collapsed[rootID] || query.Threading == ThreadUnread && unread[rootID]) {
					have++
				}
			}
		} else {
			have++
		}
		mrc <- msgResp{mil: mil, pm: pm}
		return nil
	})
	// Check for an error in one of the filters again. Check in ForEach would not
	// trigger if the last message has the error.
	if err == nil && state.err != nil {
		err = state.err
	}
	if err != nil {
		mrc <- msgResp{err: fmt.Errorf("querying messages: %v", err)}
		return
	}
	if end {
		mrc <- msgResp{viewEnd: true}
	}
}

func gatherThread(log *mlog.Log, tx *bstore.Tx, acc *store.Account, v view, m store.Message, destMessageID int64, first bool) ([]MessageItem, *ParsedMessage, error) {
	if m.ThreadID == 0 {
		// If we would continue, FilterNonzero would fail because there are no non-zero fields.
		return nil, nil, fmt.Errorf("message has threadid 0, account is probably still being upgraded, try turning threading off until the upgrade is done")
	}

	// Fetch other messages for this thread.
	qt := bstore.QueryTx[store.Message](tx)
	qt.FilterNonzero(store.Message{ThreadID: m.ThreadID})
	qt.FilterEqual("Expunged", false)
	qt.FilterNotEqual("ID", m.ID)
	qt.SortAsc("ID")
	tml, err := qt.List()
	if err != nil {
		return nil, nil, fmt.Errorf("listing other messages in thread for message %d, thread %d: %v", m.ID, m.ThreadID, err)
	}

	var mil []MessageItem
	var pm *ParsedMessage
	var firstUnread bool
	for _, tm := range tml {
		err := func() error {
			xstate := msgState{acc: acc}
			defer xstate.clear()

			mi, err := messageItem(log, tm, &xstate)
			if err != nil {
				return fmt.Errorf("making messageitem for message %d, for thread %d: %v", tm.ID, m.ThreadID, err)
			}
			mi.MatchQuery, err = v.matches(log, acc, false, tm.ID, tm.MailboxID, tm.UID, tm.Flags, tm.Keywords, func(int64, int64, store.UID) (store.Message, error) {
				return tm, nil
			})
			if err != nil {
				return fmt.Errorf("matching thread message %d against view query: %v", tm.ID, err)
			}
			mil = append(mil, mi)

			if tm.ID == destMessageID || destMessageID == 0 && first && (pm == nil || !firstUnread && !tm.Seen) {
				firstUnread = !tm.Seen
				xpm, err := parsedMessage(log, tm, &xstate, true, false)
				if err != nil {
					return fmt.Errorf("parsing thread message %d: %v", tm.ID, err)
				}
				pm = &xpm
			}
			return nil
		}()
		if err != nil {
			return nil, nil, err
		}
	}

	// Finally, the message that caused us to gather this thread (which is likely the
	// most recent message in the thread) could be the only unread message.
	if destMessageID == 0 && first && !m.Seen && !firstUnread {
		xstate := msgState{acc: acc}
		defer xstate.clear()
		xpm, err := parsedMessage(log, m, &xstate, true, false)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing thread message %d: %v", m.ID, err)
		}
		pm = &xpm
	}

	return mil, pm, nil
}

// While checking the filters on a message, we may need to get more message
// details as each filter passes. We check the filters that need the basic
// information first, and load and cache more details for the next filters.
// msgState holds parsed details for a message, it is updated while filtering,
// with more information or reset for a next message.
type msgState struct {
	acc  *store.Account // Never changes during lifetime.
	err  error          // Once set, doesn't get cleared.
	m    store.Message
	part *message.Part // Will be without Reader when msgr is nil.
	msgr *store.MsgReader
}

func (ms *msgState) clear() {
	if ms.msgr != nil {
		ms.msgr.Close()
		ms.msgr = nil
	}
	*ms = msgState{acc: ms.acc, err: ms.err}
}

func (ms *msgState) ensureMsg(m store.Message) {
	if m.ID != ms.m.ID {
		ms.clear()
	}
	ms.m = m
}

func (ms *msgState) ensurePart(m store.Message, withMsgReader bool) bool {
	ms.ensureMsg(m)

	if ms.err == nil {
		if ms.part == nil {
			if m.ParsedBuf == nil {
				ms.err = fmt.Errorf("message %d not parsed", m.ID)
				return false
			}
			var p message.Part
			if err := json.Unmarshal(m.ParsedBuf, &p); err != nil {
				ms.err = fmt.Errorf("load part for message %d: %w", m.ID, err)
				return false
			}
			ms.part = &p
		}
		if withMsgReader && ms.msgr == nil {
			ms.msgr = ms.acc.MessageReader(m)
			ms.part.SetReaderAt(ms.msgr)
		}
	}
	return ms.part != nil
}

// flagFilterFn returns a function that applies the flag/keyword/"label"-related
// filters for a query. A nil function is returned if there are no flags to filter
// on.
func (q Query) flagFilterFn() func(store.Flags, []string) bool {
	labels := map[string]bool{}
	for _, k := range q.Filter.Labels {
		labels[k] = true
	}
	for _, k := range q.NotFilter.Labels {
		labels[k] = false
	}

	if len(labels) == 0 {
		return nil
	}

	var mask, flags store.Flags
	systemflags := map[string][]*bool{
		`\answered`:  {&mask.Answered, &flags.Answered},
		`\flagged`:   {&mask.Flagged, &flags.Flagged},
		`\deleted`:   {&mask.Deleted, &flags.Deleted},
		`\seen`:      {&mask.Seen, &flags.Seen},
		`\draft`:     {&mask.Draft, &flags.Draft},
		`$junk`:      {&mask.Junk, &flags.Junk},
		`$notjunk`:   {&mask.Notjunk, &flags.Notjunk},
		`$forwarded`: {&mask.Forwarded, &flags.Forwarded},
		`$phishing`:  {&mask.Phishing, &flags.Phishing},
		`$mdnsent`:   {&mask.MDNSent, &flags.MDNSent},
	}
	keywords := map[string]bool{}
	for k, v := range labels {
		k = strings.ToLower(k)
		if mf, ok := systemflags[k]; ok {
			*mf[0] = true
			*mf[1] = v
		} else {
			keywords[k] = v
		}
	}
	return func(msgFlags store.Flags, msgKeywords []string) bool {
		var f store.Flags
		if f.Set(mask, msgFlags) != flags {
			return false
		}
		for k, v := range keywords {
			if slices.Contains(msgKeywords, k) != v {
				return false
			}
		}
		return true
	}
}

// attachmentFilterFn returns a function that filters for the attachment-related
// filter from the query. A nil function is returned if there are attachment
// filters.
func (q Query) attachmentFilterFn(log *mlog.Log, acc *store.Account, state *msgState) func(m store.Message) bool {
	if q.Filter.Attachments == AttachmentIndifferent && q.NotFilter.Attachments == AttachmentIndifferent {
		return nil
	}

	return func(m store.Message) bool {
		if !state.ensurePart(m, false) {
			return false
		}
		types, err := attachmentTypes(log, m, state)
		if err != nil {
			state.err = err
			return false
		}
		return (q.Filter.Attachments == AttachmentIndifferent || types[q.Filter.Attachments]) && (q.NotFilter.Attachments == AttachmentIndifferent || !types[q.NotFilter.Attachments])
	}
}

var attachmentMimetypes = map[string]AttachmentType{
	"application/pdf":                                AttachmentPDF,
	"application/zip":                                AttachmentArchive,
	"application/x-rar-compressed":                   AttachmentArchive,
	"application/vnd.oasis.opendocument.spreadsheet": AttachmentSpreadsheet,
	"application/vnd.ms-excel":                       AttachmentSpreadsheet,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         AttachmentSpreadsheet,
	"application/vnd.oasis.opendocument.text":                                   AttachmentDocument,
	"application/vnd.oasis.opendocument.presentation":                           AttachmentPresentation,
	"application/vnd.ms-powerpoint":                                             AttachmentPresentation,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": AttachmentPresentation,
}
var attachmentExtensions = map[string]AttachmentType{
	".pdf":     AttachmentPDF,
	".zip":     AttachmentArchive,
	".tar":     AttachmentArchive,
	".tgz":     AttachmentArchive,
	".tar.gz":  AttachmentArchive,
	".tbz2":    AttachmentArchive,
	".tar.bz2": AttachmentArchive,
	".tar.lz":  AttachmentArchive,
	".tlz":     AttachmentArchive,
	".tar.xz":  AttachmentArchive,
	".txz":     AttachmentArchive,
	".tar.zst": AttachmentArchive,
	".tar.lz4": AttachmentArchive,
	".7z":      AttachmentArchive,
	".rar":     AttachmentArchive,
	".ods":     AttachmentSpreadsheet,
	".xls":     AttachmentSpreadsheet,
	".xlsx":    AttachmentSpreadsheet,
	".odt":     AttachmentDocument,
	".doc":     AttachmentDocument,
	".docx":    AttachmentDocument,
	".odp":     AttachmentPresentation,
	".ppt":     AttachmentPresentation,
	".pptx":    AttachmentPresentation,
}

func attachmentTypes(log *mlog.Log, m store.Message, state *msgState) (map[AttachmentType]bool, error) {
	types := map[AttachmentType]bool{}

	pm, err := parsedMessage(log, m, state, false, false)
	if err != nil {
		return nil, fmt.Errorf("parsing message for attachments: %w", err)
	}
	for _, a := range pm.attachments {
		if a.Part.MediaType == "IMAGE" {
			types[AttachmentImage] = true
			continue
		}
		mt := strings.ToLower(a.Part.MediaType + "/" + a.Part.MediaSubType)
		if t, ok := attachmentMimetypes[mt]; ok {
			types[t] = true
		} else if ext := filepath.Ext(a.Part.ContentTypeParams["name"]); ext != "" {
			if t, ok := attachmentExtensions[strings.ToLower(ext)]; ok {
				types[t] = true
			} else {
				continue
			}
		}
	}

	if len(types) == 0 {
		types[AttachmentNone] = true
	} else {
		types[AttachmentAny] = true
	}
	return types, nil
}

// envFilterFn returns a filter function for the "envelope" headers ("envelope" as
// used by IMAP, i.e. basic message headers from/to/subject, an unfortunate name
// clash with SMTP envelope) for the query. A nil function is returned if no
// filtering is needed.
func (q Query) envFilterFn(log *mlog.Log, state *msgState) func(m store.Message) bool {
	if len(q.Filter.From) == 0 && len(q.Filter.To) == 0 && len(q.Filter.Subject) == 0 && len(q.NotFilter.From) == 0 && len(q.NotFilter.To) == 0 && len(q.NotFilter.Subject) == 0 {
		return nil
	}

	lower := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		r := make([]string, len(l))
		for i, s := range l {
			r[i] = strings.ToLower(s)
		}
		return r
	}

	filterSubject := lower(q.Filter.Subject)
	notFilterSubject := lower(q.NotFilter.Subject)
	filterFrom := lower(q.Filter.From)
	notFilterFrom := lower(q.NotFilter.From)
	filterTo := lower(q.Filter.To)
	notFilterTo := lower(q.NotFilter.To)

	return func(m store.Message) bool {
		if !state.ensurePart(m, false) {
			return false
		}

		var env message.Envelope
		if state.part.Envelope != nil {
			env = *state.part.Envelope
		}

		if len(filterSubject) > 0 || len(notFilterSubject) > 0 {
			subject := strings.ToLower(env.Subject)
			for _, s := range filterSubject {
				if !strings.Contains(subject, s) {
					return false
				}
			}
			for _, s := range notFilterSubject {
				if strings.Contains(subject, s) {
					return false
				}
			}
		}

		contains := func(textLower []string, l []message.Address, all bool) bool {
		next:
			for _, s := range textLower {
				for _, a := range l {
					name := strings.ToLower(a.Name)
					addr := strings.ToLower(fmt.Sprintf("<%s@%s>", a.User, a.Host))
					if strings.Contains(name, s) || strings.Contains(addr, s) {
						if !all {
							return true
						}
						continue next
					}
				}
				if all {
					return false
				}
			}
			return all
		}

		if len(filterFrom) > 0 && !contains(filterFrom, env.From, true) {
			return false
		}
		if len(notFilterFrom) > 0 && contains(notFilterFrom, env.From, false) {
			return false
		}
		if len(filterTo) > 0 || len(notFilterTo) > 0 {
			to := append(append(append([]message.Address{}, env.To...), env.CC...), env.BCC...)
			if len(filterTo) > 0 && !contains(filterTo, to, true) {
				return false
			}
			if len(notFilterTo) > 0 && contains(notFilterTo, to, false) {
				return false
			}
		}
		return true
	}
}

// headerFilterFn returns a function that filters for the header filters in the
// query. A nil function is returned if there are no header filters.
func (q Query) headerFilterFn(log *mlog.Log, state *msgState) func(m store.Message) bool {
	if len(q.Filter.Headers) == 0 {
		return nil
	}

	lowerValues := make([]string, len(q.Filter.Headers))
	for i, t := range q.Filter.Headers {
		lowerValues[i] = strings.ToLower(t[1])
	}

	return func(m store.Message) bool {
		if !state.ensurePart(m, true) {
			return false
		}
		hdr, err := state.part.Header()
		if err != nil {
			state.err = fmt.Errorf("reading header for message %d: %w", m.ID, err)
			return false
		}

	next:
		for i, t := range q.Filter.Headers {
			k := t[0]
			v := lowerValues[i]
			l := hdr.Values(k)
			if v == "" && len(l) > 0 {
				continue
			}
			for _, e := range l {
				if strings.Contains(strings.ToLower(e), v) {
					continue next
				}
			}
			return false
		}
		return true
	}
}

// wordFiltersFn returns a function that applies the word filters of the query. A
// nil function is returned when query does not contain a word filter.
func (q Query) wordsFilterFn(log *mlog.Log, state *msgState) func(m store.Message) bool {
	if len(q.Filter.Words) == 0 && len(q.NotFilter.Words) == 0 {
		return nil
	}

	ws := store.PrepareWordSearch(q.Filter.Words, q.NotFilter.Words)

	return func(m store.Message) bool {
		if !state.ensurePart(m, true) {
			return false
		}

		if ok, err := ws.MatchPart(log, state.part, true); err != nil {
			state.err = fmt.Errorf("searching for words in message %d: %w", m.ID, err)
			return false
		} else {
			return ok
		}
	}
}
