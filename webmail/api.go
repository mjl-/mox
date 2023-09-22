package webmail

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"sort"
	"strings"
	"time"

	_ "embed"

	"golang.org/x/exp/maps"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

//go:embed api.json
var webmailapiJSON []byte

type Webmail struct {
	maxMessageSize int64 // From listener.
}

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		xlog.Fatalx("parsing api docs", err, mlog.Field("api", api))
	}
	return doc
}

var webmailDoc = mustParseAPI("webmail", webmailapiJSON)

var sherpaHandlerOpts *sherpa.HandlerOpts

func makeSherpaHandler(maxMessageSize int64) (http.Handler, error) {
	return sherpa.NewHandler("/api/", moxvar.Version, Webmail{maxMessageSize}, &webmailDoc, sherpaHandlerOpts)
}

func init() {
	collector, err := sherpaprom.NewCollector("moxwebmail", nil)
	if err != nil {
		xlog.Fatalx("creating sherpa prometheus collector", err)
	}

	sherpaHandlerOpts = &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none"}
	// Just to validate.
	_, err = makeSherpaHandler(0)
	if err != nil {
		xlog.Fatalx("sherpa handler", err)
	}
}

// Token returns a token to use for an SSE connection. A token can only be used for
// a single SSE connection. Tokens are stored in memory for a maximum of 1 minute,
// with at most 10 unused tokens (the most recently created) per account.
func (Webmail) Token(ctx context.Context) string {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	return sseTokens.xgenerate(ctx, reqInfo.AccountName, reqInfo.LoginAddress)
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

	sse, ok := sseGet(req.SSEID, reqInfo.AccountName)
	if !ok {
		xcheckuserf(ctx, errors.New("unknown sseid"), "looking up connection")
	}
	sse.Request <- req
}

// ParsedMessage returns enough to render the textual body of a message. It is
// assumed the client already has other fields through MessageItem.
func (Webmail) ParsedMessage(ctx context.Context, msgID int64) (pm ParsedMessage) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	var m store.Message
	xdbread(ctx, acc, func(tx *bstore.Tx) {
		m = xmessageID(ctx, tx, msgID)
	})

	state := msgState{acc: acc}
	defer state.clear()
	pm, err = parsedMessage(log, m, &state, true, false)
	xcheckf(ctx, err, "parsing message")
	return
}

// Attachment is a MIME part is an existing message that is not intended as
// viewable text or HTML part.
type Attachment struct {
	Path []int // Indices into top-level message.Part.Parts.

	// File name based on "name" attribute of "Content-Type", or the "filename"
	// attribute of "Content-Disposition".
	// todo: decode non-ascii character sets
	Filename string

	Part message.Part
}

// SubmitMessage is an email message to be sent to one or more recipients.
// Addresses are formatted as just email address, or with a name like "name
// <user@host>".
type SubmitMessage struct {
	From               string
	To                 []string
	Cc                 []string
	Bcc                []string
	Subject            string
	TextBody           string
	Attachments        []File
	ForwardAttachments ForwardAttachments
	IsForward          bool
	ResponseMessageID  int64  // If set, this was a reply or forward, based on IsForward.
	ReplyTo            string // If non-empty, Reply-To header to add to message.
	UserAgent          string // User-Agent header added if not empty.
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

// xerrWriter is an io.Writer that panics with a *sherpa.Error when Write
// returns an error.
type xerrWriter struct {
	ctx  context.Context
	w    *bufio.Writer
	size int64
	max  int64
}

// Write implements io.Writer, but calls panic (that is handled higher up) on
// i/o errors.
func (w *xerrWriter) Write(buf []byte) (int, error) {
	n, err := w.w.Write(buf)
	xcheckf(w.ctx, err, "writing message file")
	if n > 0 {
		w.size += int64(n)
		if w.size > w.max {
			xcheckuserf(w.ctx, errors.New("max message size reached"), "writing message file")
		}
	}
	return n, err
}

type nameAddress struct {
	Name    string
	Address smtp.Address
}

// parseAddress expects either a plain email address like "user@domain", or a
// single address as used in a message header, like "name <user@domain>".
func parseAddress(msghdr string) (nameAddress, error) {
	a, err := mail.ParseAddress(msghdr)
	if err != nil {
		return nameAddress{}, nil
	}

	// todo: parse more fully according to ../rfc/5322:959
	path, err := smtp.ParseAddress(a.Address)
	if err != nil {
		return nameAddress{}, err
	}
	return nameAddress{a.Name, path}, nil
}

func xmailboxID(ctx context.Context, tx *bstore.Tx, mailboxID int64) store.Mailbox {
	if mailboxID == 0 {
		xcheckuserf(ctx, errors.New("invalid zero mailbox ID"), "getting mailbox")
	}
	mb := store.Mailbox{ID: mailboxID}
	err := tx.Get(&mb)
	if err == bstore.ErrAbsent {
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

// MessageSubmit sends a message by submitting it the outgoing email queue. The
// message is sent to all addresses listed in the To, Cc and Bcc addresses, without
// Bcc message header.
//
// If a Sent mailbox is configured, messages are added to it after submitting
// to the delivery queue.
func (w Webmail) MessageSubmit(ctx context.Context, m SubmitMessage) {
	// Similar between ../smtpserver/server.go:/submit\( and ../webmail/webmail.go:/MessageSubmit\(

	// todo: consider making this an HTTP POST, so we can upload as regular form, which is probably more efficient for encoding for the client and we can stream the data in.

	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := xlog.WithContext(ctx).Fields(mlog.Field("account", reqInfo.AccountName))
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	log.Debug("message submit")

	fromAddr, err := parseAddress(m.From)
	xcheckuserf(ctx, err, "parsing From address")

	var replyTo *nameAddress
	if m.ReplyTo != "" {
		a, err := parseAddress(m.ReplyTo)
		xcheckuserf(ctx, err, "parsing Reply-To address")
		replyTo = &a
	}

	var recipients []smtp.Address

	var toAddrs []nameAddress
	for _, s := range m.To {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing To address")
		toAddrs = append(toAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	var ccAddrs []nameAddress
	for _, s := range m.Cc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Cc address")
		ccAddrs = append(ccAddrs, addr)
		recipients = append(recipients, addr.Address)
	}

	for _, s := range m.Bcc {
		addr, err := parseAddress(s)
		xcheckuserf(ctx, err, "parsing Bcc address")
		recipients = append(recipients, addr.Address)
	}

	// Check if from address is allowed for account.
	fromAccName, _, _, err := mox.FindAccount(fromAddr.Address.Localpart, fromAddr.Address.Domain, false)
	if err == nil && fromAccName != reqInfo.AccountName {
		err = mox.ErrAccountNotFound
	}
	if err != nil && (errors.Is(err, mox.ErrAccountNotFound) || errors.Is(err, mox.ErrDomainNotFound)) {
		metricSubmission.WithLabelValues("badfrom").Inc()
		xcheckuserf(ctx, errors.New("address not found"), "looking from address for account")
	}
	xcheckf(ctx, err, "checking if from address is allowed")

	if len(recipients) == 0 {
		xcheckuserf(ctx, fmt.Errorf("no recipients"), "composing message")
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
			xcheckuserf(ctx, errors.New("send message limit reached"), "checking outgoing rate limit")
		} else if rcptlimit >= 0 {
			metricSubmission.WithLabelValues("recipientlimiterror").Inc()
			xcheckuserf(ctx, errors.New("send message limit reached"), "checking outgoing rate limit")
		}
		xcheckf(ctx, err, "checking send limit")
	})

	has8bit := false // We update this later on.

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

	// Create file to compose message into.
	dataFile, err := store.CreateMessageTemp("webmail-submit")
	xcheckf(ctx, err, "creating temporary file for message")
	defer func() {
		if dataFile != nil {
			err := dataFile.Close()
			log.Check(err, "closing submit message file")
			err = os.Remove(dataFile.Name())
			log.Check(err, "removing temporary submit message file")
		}
	}()

	// If writing to the message file fails, we abort immediately.
	xmsgw := &xerrWriter{ctx, bufio.NewWriter(dataFile), 0, w.maxMessageSize}

	isASCII := func(s string) bool {
		for _, c := range s {
			if c >= 0x80 {
				return false
			}
		}
		return true
	}

	header := func(k, v string) {
		fmt.Fprintf(xmsgw, "%s: %s\r\n", k, v)
	}

	headerAddrs := func(k string, l []nameAddress) {
		if len(l) == 0 {
			return
		}
		v := ""
		linelen := len(k) + len(": ")
		for _, a := range l {
			if v != "" {
				v += ","
				linelen++
			}
			addr := mail.Address{Name: a.Name, Address: a.Address.Pack(smtputf8)}
			s := addr.String()
			if v != "" && linelen+1+len(s) > 77 {
				v += "\r\n\t"
				linelen = 1
			} else if v != "" {
				v += " "
				linelen++
			}
			v += s
			linelen += len(s)
		}
		fmt.Fprintf(xmsgw, "%s: %s\r\n", k, v)
	}

	line := func(w io.Writer) {
		_, _ = w.Write([]byte("\r\n"))
	}

	text := m.TextBody
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text = strings.ReplaceAll(text, "\n", "\r\n")

	charset := "us-ascii"
	if !isASCII(text) {
		charset = "utf-8"
	}

	var cte string
	if message.NeedsQuotedPrintable(text) {
		var sb strings.Builder
		_, err := io.Copy(quotedprintable.NewWriter(&sb), strings.NewReader(text))
		xcheckf(ctx, err, "converting text to quoted printable")
		text = sb.String()
		cte = "quoted-printable"
	} else if has8bit || charset == "utf-8" {
		cte = "8bit"
	} else {
		cte = "7bit"
	}

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
			recvHdr.Add(" ", message.TLSReceivedComment(log, *reqInfo.Request.TLS)...)
		}
		recvHdr.Add(" ", "for", "<"+rcptTo+">;", time.Now().Format(message.RFC5322Z))
		return recvHdr.String()
	}

	// Outer message headers.
	headerAddrs("From", []nameAddress{fromAddr})
	if replyTo != nil {
		headerAddrs("Reply-To", []nameAddress{*replyTo})
	}
	headerAddrs("To", toAddrs)
	headerAddrs("Cc", ccAddrs)

	var subjectValue string
	subjectLineLen := len("Subject: ")
	subjectWord := false
	for i, word := range strings.Split(m.Subject, " ") {
		if !smtputf8 && !isASCII(word) {
			word = mime.QEncoding.Encode("utf-8", word)
		}
		if i > 0 {
			subjectValue += " "
			subjectLineLen++
		}
		if subjectWord && subjectLineLen+len(word) > 77 {
			subjectValue += "\r\n\t"
			subjectLineLen = 1
		}
		subjectValue += word
		subjectLineLen += len(word)
		subjectWord = true
	}
	if subjectValue != "" {
		header("Subject", subjectValue)
	}

	messageID := fmt.Sprintf("<%s>", mox.MessageIDGen(smtputf8))
	header("Message-Id", messageID)
	header("Date", time.Now().Format(message.RFC5322Z))
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
			header("In-Reply-To", rp.Envelope.MessageID)
			ref := h.Get("References")
			if ref == "" {
				ref = h.Get("In-Reply-To")
			}
			if ref != "" {
				header("References", ref+"\r\n\t"+rp.Envelope.MessageID)
			} else {
				header("References", rp.Envelope.MessageID)
			}
		})
	}
	if m.UserAgent != "" {
		header("User-Agent", m.UserAgent)
	}
	header("MIME-Version", "1.0")

	if len(m.Attachments) > 0 || len(m.ForwardAttachments.Paths) > 0 {
		mp := multipart.NewWriter(xmsgw)
		header("Content-Type", fmt.Sprintf(`multipart/mixed; boundary="%s"`, mp.Boundary()))
		line(xmsgw)

		textHdr := textproto.MIMEHeader{}
		textHdr.Set("Content-Type", "text/plain; charset="+escapeParam(charset))
		textHdr.Set("Content-Transfer-Encoding", cte)
		textp, err := mp.CreatePart(textHdr)
		xcheckf(ctx, err, "adding text part to message")
		_, err = textp.Write([]byte(text))
		xcheckf(ctx, err, "writing text part")

		xaddPart := func(ct, filename string) io.Writer {
			ahdr := textproto.MIMEHeader{}
			if ct == "" {
				ct = "application/octet-stream"
			}
			ct += fmt.Sprintf(`; name="%s"`, filename)
			ahdr.Set("Content-Type", ct)
			ahdr.Set("Content-Transfer-Encoding", "base64")
			ahdr.Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%s`, escapeParam(filename)))
			ap, err := mp.CreatePart(ahdr)
			xcheckf(ctx, err, "adding attachment part to message")
			return ap
		}

		xaddAttachmentBase64 := func(ct, filename string, base64Data []byte) {
			ap := xaddPart(ct, filename)

			for len(base64Data) > 0 {
				line := base64Data
				n := len(line)
				if n > 78 {
					n = 78
				}
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

			// Ensure base64 is valid, then we'll write the original string.
			_, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(t[1])))
			xcheckuserf(ctx, err, "parsing attachment as base64")

			xaddAttachmentBase64(ct, a.Filename, []byte(t[1]))
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

						filename := ap.ContentTypeParams["name"]
						if filename == "" {
							filename = "unnamed.bin"
						}
						ct := strings.ToLower(ap.MediaType + "/" + ap.MediaSubType)
						if pcharset := ap.ContentTypeParams["charset"]; pcharset != "" {
							ct += "; charset=" + escapeParam(pcharset)
						}
						xaddAttachment(ct, filename, ap.Reader())
					}
				})
			})
		}

		err = mp.Close()
		xcheckf(ctx, err, "writing mime multipart")
	} else {
		header("Content-Type", "text/plain; charset="+escapeParam(charset))
		header("Content-Transfer-Encoding", cte)
		line(xmsgw)
		xmsgw.Write([]byte(text))
	}

	err = xmsgw.w.Flush()
	xcheckf(ctx, err, "writing message")

	// Add DKIM-Signature headers.
	var msgPrefix string
	fd := fromAddr.Address.Domain
	confDom, _ := mox.Conf.Domain(fd)
	if len(confDom.DKIM.Sign) > 0 {
		dkimHeaders, err := dkim.Sign(ctx, fromAddr.Address.Localpart, fd, confDom.DKIM, smtputf8, dataFile)
		if err != nil {
			metricServerErrors.WithLabelValues("dkimsign").Inc()
		}
		xcheckf(ctx, err, "sign dkim")

		msgPrefix = dkimHeaders
	}

	fromPath := smtp.Path{
		Localpart: fromAddr.Address.Localpart,
		IPDomain:  dns.IPDomain{Domain: fromAddr.Address.Domain},
	}
	for _, rcpt := range recipients {
		rcptMsgPrefix := recvHdrFor(rcpt.Pack(smtputf8)) + msgPrefix
		msgSize := int64(len(rcptMsgPrefix)) + xmsgw.size
		toPath := smtp.Path{
			Localpart: rcpt.Localpart,
			IPDomain:  dns.IPDomain{Domain: rcpt.Domain},
		}
		_, err := queue.Add(ctx, log, reqInfo.AccountName, fromPath, toPath, has8bit, smtputf8, msgSize, messageID, []byte(rcptMsgPrefix), dataFile, nil, false)
		if err != nil {
			metricSubmission.WithLabelValues("queueerror").Inc()
		}
		xcheckf(ctx, err, "adding message to the delivery queue")
		metricSubmission.WithLabelValues("ok").Inc()
	}

	var modseq store.ModSeq // Only set if needed.

	// Append message to Sent mailbox and mark original messages as answered/forwarded.
	acc.WithRLock(func() {
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
		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
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
					modseq, err = acc.NextModSeq(tx)
					xcheckf(ctx, err, "next modseq")
					rm.ModSeq = modseq
					err := tx.Update(&rm)
					xcheckf(ctx, err, "updating flags of replied/forwarded message")
					changes = append(changes, rm.ChangeFlags(oflags))

					err = acc.RetrainMessages(ctx, log, tx, []store.Message{rm}, false)
					xcheckf(ctx, err, "retraining messages after reply/forward")
				}
			}

			sentmb, err := bstore.QueryDB[store.Mailbox](ctx, acc.DB).FilterEqual("Sent", true).Get()
			if err == bstore.ErrAbsent {
				// There is no mailbox designated as Sent mailbox, so we're done.
				err := os.Remove(dataFile.Name())
				log.Check(err, "removing submitmessage file")
				err = dataFile.Close()
				log.Check(err, "closing submitmessage file")
				dataFile = nil
				return
			}
			xcheckf(ctx, err, "message submitted to queue, adding to Sent mailbox")

			if modseq == 0 {
				modseq, err = acc.NextModSeq(tx)
				xcheckf(ctx, err, "next modseq")
			}

			sentm := store.Message{
				CreateSeq:     modseq,
				ModSeq:        modseq,
				MailboxID:     sentmb.ID,
				MailboxOrigID: sentmb.ID,
				Flags:         store.Flags{Notjunk: true, Seen: true},
				Size:          int64(len(msgPrefix)) + xmsgw.size,
				MsgPrefix:     []byte(msgPrefix),
			}

			// Update mailbox before delivery, which changes uidnext.
			sentmb.Add(sentm.MailboxCounts())
			err = tx.Update(&sentmb)
			xcheckf(ctx, err, "updating sent mailbox for counts")

			err = acc.DeliverMessage(log, tx, &sentm, dataFile, true, true, false, false)
			if err != nil {
				metricSubmission.WithLabelValues("storesenterror").Inc()
				metricked = true
			}
			xcheckf(ctx, err, "message submitted to queue, appending message to Sent mailbox")

			changes = append(changes, sentm.ChangeAddUID(), sentmb.ChangeCounts())

			err = dataFile.Close()
			log.Check(err, "closing submit message file")
			dataFile = nil
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MessageMove moves messages to another mailbox. If the message is already in
// the mailbox an error is returned.
func (Webmail) MessageMove(ctx context.Context, messageIDs []int64, mailboxID int64) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	acc.WithRLock(func() {
		retrain := make([]store.Message, 0, len(messageIDs))
		removeChanges := map[int64]store.ChangeRemoveUIDs{}
		// n adds, 1 remove, 2 mailboxcounts, optimistic and at least for a single message.
		changes := make([]store.Change, 0, len(messageIDs)+3)

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var mbSrc store.Mailbox
			var modseq store.ModSeq

			mbDst := xmailboxID(ctx, tx, mailboxID)

			if len(messageIDs) == 0 {
				return
			}

			keywords := map[string]struct{}{}

			for _, mid := range messageIDs {
				m := xmessageID(ctx, tx, mid)

				// We may have loaded this mailbox in the previous iteration of this loop.
				if m.MailboxID != mbSrc.ID {
					if mbSrc.ID != 0 {
						err = tx.Update(&mbSrc)
						xcheckf(ctx, err, "updating source mailbox counts")
						changes = append(changes, mbSrc.ChangeCounts())
					}
					mbSrc = xmailboxID(ctx, tx, m.MailboxID)
				}

				if mbSrc.ID == mailboxID {
					// Client should filter out messages that are already in mailbox.
					xcheckuserf(ctx, errors.New("already in destination mailbox"), "moving message")
				}

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					xcheckf(ctx, err, "assigning next modseq")
				}

				ch := removeChanges[m.MailboxID]
				ch.UIDs = append(ch.UIDs, m.UID)
				ch.ModSeq = modseq
				ch.MailboxID = m.MailboxID
				removeChanges[m.MailboxID] = ch

				// Copy of message record that we'll insert when UID is freed up.
				om := m
				om.PrepareExpunge()
				om.ID = 0 // Assign new ID.
				om.ModSeq = modseq

				mbSrc.Sub(m.MailboxCounts())

				if mbDst.Trash {
					m.Seen = true
				}
				conf, _ := acc.Conf()
				m.MailboxID = mbDst.ID
				if m.IsReject && m.MailboxDestinedID != 0 {
					// Incorrectly delivered to Rejects mailbox. Adjust MailboxOrigID so this message
					// is used for reputation calculation during future deliveries.
					m.MailboxOrigID = m.MailboxDestinedID
					m.IsReject = false
					m.Seen = false
				}
				m.UID = mbDst.UIDNext
				m.ModSeq = modseq
				mbDst.UIDNext++
				m.JunkFlagsForMailbox(mbDst, conf)
				err = tx.Update(&m)
				xcheckf(ctx, err, "updating moved message in database")

				// Now that UID is unused, we can insert the old record again.
				err = tx.Insert(&om)
				xcheckf(ctx, err, "inserting record for expunge after moving message")

				mbDst.Add(m.MailboxCounts())

				changes = append(changes, m.ChangeAddUID())
				retrain = append(retrain, m)

				for _, kw := range m.Keywords {
					keywords[kw] = struct{}{}
				}
			}

			err = tx.Update(&mbSrc)
			xcheckf(ctx, err, "updating source mailbox counts")

			changes = append(changes, mbSrc.ChangeCounts(), mbDst.ChangeCounts())

			// Ensure destination mailbox has keywords of the moved messages.
			var mbKwChanged bool
			mbDst.Keywords, mbKwChanged = store.MergeKeywords(mbDst.Keywords, maps.Keys(keywords))
			if mbKwChanged {
				changes = append(changes, mbDst.ChangeKeywords())
			}

			err = tx.Update(&mbDst)
			xcheckf(ctx, err, "updating mailbox with uidnext")

			err = acc.RetrainMessages(ctx, log, tx, retrain, false)
			xcheckf(ctx, err, "retraining messages after move")
		})

		// Ensure UIDs of the removed message are in increasing order. It is quite common
		// for all messages to be from a single source mailbox, meaning this is just one
		// change, for which we preallocated space.
		for _, ch := range removeChanges {
			sort.Slice(ch.UIDs, func(i, j int) bool {
				return ch.UIDs[i] < ch.UIDs[j]
			})
			changes = append(changes, ch)
		}
		store.BroadcastChanges(acc, changes)
	})
}

// MessageDelete permanently deletes messages, without moving them to the Trash mailbox.
func (Webmail) MessageDelete(ctx context.Context, messageIDs []int64) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	if len(messageIDs) == 0 {
		return
	}

	acc.WithWLock(func() {
		removeChanges := map[int64]store.ChangeRemoveUIDs{}
		changes := make([]store.Change, 0, len(messageIDs)+1) // n remove, 1 mailbox counts

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			var mb store.Mailbox
			remove := make([]store.Message, 0, len(messageIDs))

			for _, mid := range messageIDs {
				m := xmessageID(ctx, tx, mid)

				if m.MailboxID != mb.ID {
					if mb.ID != 0 {
						err := tx.Update(&mb)
						xcheckf(ctx, err, "updating mailbox counts")
						changes = append(changes, mb.ChangeCounts())
					}
					mb = xmailboxID(ctx, tx, m.MailboxID)
				}

				qmr := bstore.QueryTx[store.Recipient](tx)
				qmr.FilterEqual("MessageID", m.ID)
				_, err = qmr.Delete()
				xcheckf(ctx, err, "removing message recipients")

				mb.Sub(m.MailboxCounts())

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					xcheckf(ctx, err, "assigning next modseq")
				}
				m.Expunged = true
				m.ModSeq = modseq
				err = tx.Update(&m)
				xcheckf(ctx, err, "marking message as expunged")

				ch := removeChanges[m.MailboxID]
				ch.UIDs = append(ch.UIDs, m.UID)
				ch.MailboxID = m.MailboxID
				ch.ModSeq = modseq
				removeChanges[m.MailboxID] = ch
				remove = append(remove, m)
			}

			if mb.ID != 0 {
				err := tx.Update(&mb)
				xcheckf(ctx, err, "updating count in mailbox")
				changes = append(changes, mb.ChangeCounts())
			}

			// Mark removed messages as not needing training, then retrain them, so if they
			// were trained, they get untrained.
			for i := range remove {
				remove[i].Junk = false
				remove[i].Notjunk = false
			}
			err = acc.RetrainMessages(ctx, log, tx, remove, true)
			xcheckf(ctx, err, "untraining deleted messages")
		})

		for _, ch := range removeChanges {
			sort.Slice(ch.UIDs, func(i, j int) bool {
				return ch.UIDs[i] < ch.UIDs[j]
			})
			changes = append(changes, ch)
		}
		store.BroadcastChanges(acc, changes)
	})

	for _, mID := range messageIDs {
		p := acc.MessagePath(mID)
		err := os.Remove(p)
		log.Check(err, "removing message file for expunge")
	}
}

// FlagsAdd adds flags, either system flags like \Seen or custom keywords. The
// flags should be lower-case, but will be converted and verified.
func (Webmail) FlagsAdd(ctx context.Context, messageIDs []int64, flaglist []string) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	flags, keywords, err := store.ParseFlagsKeywords(flaglist)
	xcheckuserf(ctx, err, "parsing flags")

	acc.WithRLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			var retrain []store.Message
			var mb, origmb store.Mailbox

			for _, mid := range messageIDs {
				m := xmessageID(ctx, tx, mid)

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
						err := tx.Update(&mb)
						xcheckf(ctx, err, "updating mailbox")
						if mb.MailboxCounts != origmb.MailboxCounts {
							changes = append(changes, mb.ChangeCounts())
						}
						if mb.KeywordsChanged(origmb) {
							changes = append(changes, mb.ChangeKeywords())
						}
					}
					mb = xmailboxID(ctx, tx, m.MailboxID)
					origmb = mb
				}
				mb.Keywords, _ = store.MergeKeywords(mb.Keywords, keywords)

				mb.Sub(m.MailboxCounts())
				oflags := m.Flags
				m.Flags = m.Flags.Set(flags, flags)
				var kwChanged bool
				m.Keywords, kwChanged = store.MergeKeywords(m.Keywords, keywords)
				mb.Add(m.MailboxCounts())

				if m.Flags == oflags && !kwChanged {
					continue
				}

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					xcheckf(ctx, err, "assigning next modseq")
				}
				m.ModSeq = modseq
				err = tx.Update(&m)
				xcheckf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				err := tx.Update(&mb)
				xcheckf(ctx, err, "updating mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				if mb.KeywordsChanged(origmb) {
					changes = append(changes, mb.ChangeKeywords())
				}
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain, false)
			xcheckf(ctx, err, "retraining messages")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// FlagsClear clears flags, either system flags like \Seen or custom keywords.
func (Webmail) FlagsClear(ctx context.Context, messageIDs []int64, flaglist []string) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	flags, keywords, err := store.ParseFlagsKeywords(flaglist)
	xcheckuserf(ctx, err, "parsing flags")

	acc.WithRLock(func() {
		var retrain []store.Message
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var modseq store.ModSeq
			var mb, origmb store.Mailbox

			for _, mid := range messageIDs {
				m := xmessageID(ctx, tx, mid)

				if mb.ID != m.MailboxID {
					if mb.ID != 0 {
						err := tx.Update(&mb)
						xcheckf(ctx, err, "updating counts for mailbox")
						if mb.MailboxCounts != origmb.MailboxCounts {
							changes = append(changes, mb.ChangeCounts())
						}
						// note: cannot remove keywords from mailbox by removing keywords from message.
					}
					mb = xmailboxID(ctx, tx, m.MailboxID)
					origmb = mb
				}

				oflags := m.Flags
				mb.Sub(m.MailboxCounts())
				m.Flags = m.Flags.Set(flags, store.Flags{})
				var changed bool
				m.Keywords, changed = store.RemoveKeywords(m.Keywords, keywords)
				mb.Add(m.MailboxCounts())

				if m.Flags == oflags && !changed {
					continue
				}

				if modseq == 0 {
					modseq, err = acc.NextModSeq(tx)
					xcheckf(ctx, err, "assigning next modseq")
				}
				m.ModSeq = modseq
				err = tx.Update(&m)
				xcheckf(ctx, err, "updating message")

				changes = append(changes, m.ChangeFlags(oflags))
				retrain = append(retrain, m)
			}

			if mb.ID != 0 {
				err := tx.Update(&mb)
				xcheckf(ctx, err, "updating keywords in mailbox")
				if mb.MailboxCounts != origmb.MailboxCounts {
					changes = append(changes, mb.ChangeCounts())
				}
				// note: cannot remove keywords from mailbox by removing keywords from message.
			}

			err = acc.RetrainMessages(ctx, log, tx, retrain, false)
			xcheckf(ctx, err, "retraining messages")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxCreate creates a new mailbox.
func (Webmail) MailboxCreate(ctx context.Context, name string) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	name, _, err = store.CheckMailboxName(name, false)
	xcheckuserf(ctx, err, "checking mailbox name")

	acc.WithWLock(func() {
		var changes []store.Change
		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			var exists bool
			var err error
			changes, _, exists, err = acc.MailboxCreate(tx, name)
			if exists {
				xcheckuserf(ctx, errors.New("mailbox already exists"), "creating mailbox")
			}
			xcheckf(ctx, err, "creating mailbox")
		})

		store.BroadcastChanges(acc, changes)
	})
}

// MailboxDelete deletes a mailbox and all its messages.
func (Webmail) MailboxDelete(ctx context.Context, mailboxID int64) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	// Messages to remove after having broadcasted the removal of messages.
	var removeMessageIDs []int64

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
			changes, removeMessageIDs, hasChildren, err = acc.MailboxDelete(ctx, log, tx, mb)
			if hasChildren {
				xcheckuserf(ctx, errors.New("mailbox has children"), "deleting mailbox")
			}
			xcheckf(ctx, err, "deleting mailbox")
		})

		store.BroadcastChanges(acc, changes)
	})

	for _, mID := range removeMessageIDs {
		p := acc.MessagePath(mID)
		err := os.Remove(p)
		log.Check(err, "removing message file for mailbox delete", mlog.Field("path", p))
	}
}

// MailboxEmpty empties a mailbox, removing all messages from the mailbox, but not
// its child mailboxes.
func (Webmail) MailboxEmpty(ctx context.Context, mailboxID int64) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	var expunged []store.Message

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			mb := xmailboxID(ctx, tx, mailboxID)

			modseq, err := acc.NextModSeq(tx)
			xcheckf(ctx, err, "next modseq")

			// Mark messages as expunged.
			qm := bstore.QueryTx[store.Message](tx)
			qm.FilterNonzero(store.Message{MailboxID: mb.ID})
			qm.FilterEqual("Expunged", false)
			qm.SortAsc("UID")
			qm.Gather(&expunged)
			_, err = qm.UpdateNonzero(store.Message{ModSeq: modseq, Expunged: true})
			xcheckf(ctx, err, "deleting messages")

			// Remove Recipients.
			anyIDs := make([]any, len(expunged))
			for i, m := range expunged {
				anyIDs[i] = m.ID
			}
			qmr := bstore.QueryTx[store.Recipient](tx)
			qmr.FilterEqual("MessageID", anyIDs...)
			_, err = qmr.Delete()
			xcheckf(ctx, err, "removing message recipients")

			// Adjust mailbox counts, gather UIDs for broadcasted change, prepare for untraining.
			uids := make([]store.UID, len(expunged))
			for i, m := range expunged {
				m.Expunged = false // Gather returns updated values.
				mb.Sub(m.MailboxCounts())
				uids[i] = m.UID

				expunged[i].Junk = false
				expunged[i].Notjunk = false
			}

			err = tx.Update(&mb)
			xcheckf(ctx, err, "updating mailbox for counts")

			err = acc.RetrainMessages(ctx, log, tx, expunged, true)
			xcheckf(ctx, err, "retraining expunged messages")

			chremove := store.ChangeRemoveUIDs{MailboxID: mb.ID, UIDs: uids, ModSeq: modseq}
			changes = []store.Change{chremove, mb.ChangeCounts()}
		})

		store.BroadcastChanges(acc, changes)
	})

	for _, m := range expunged {
		p := acc.MessagePath(m.ID)
		err := os.Remove(p)
		log.Check(err, "removing message file after emptying mailbox", mlog.Field("path", p))
	}
}

// MailboxRename renames a mailbox, possibly moving it to a new parent. The mailbox
// ID and its messages are unchanged.
func (Webmail) MailboxRename(ctx context.Context, mailboxID int64, newName string) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	// Renaming Inbox is special for IMAP. For IMAP we have to implement it per the
	// standard. We can just say no.
	newName, _, err = store.CheckMailboxName(newName, false)
	xcheckuserf(ctx, err, "checking new mailbox name")

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			mbsrc := xmailboxID(ctx, tx, mailboxID)
			var err error
			var isInbox, notExists, alreadyExists bool
			changes, isInbox, notExists, alreadyExists, err = acc.MailboxRename(tx, mbsrc, newName)
			if isInbox || notExists || alreadyExists {
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
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	search = strings.ToLower(search)

	var matches []string
	all := true
	acc.WithRLock(func() {
		xdbread(ctx, acc, func(tx *bstore.Tx) {
			type key struct {
				localpart smtp.Localpart
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
				address := fmt.Sprintf("<%s@%s>", r.Localpart.String(), r.Domain)
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
					lp := r.Localpart.String()
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
	s := "<" + a.User + "@" + host + ">"
	if a.Name != "" {
		// todo: properly encoded/escaped name
		s = a.Name + " " + s
	}
	return s
}

// MailboxSetSpecialUse sets the special use flags of a mailbox.
func (Webmail) MailboxSetSpecialUse(ctx context.Context, mb store.Mailbox) {
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	acc.WithWLock(func() {
		var changes []store.Change

		xdbwrite(ctx, acc, func(tx *bstore.Tx) {
			xmb := xmailboxID(ctx, tx, mb.ID)

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
				_, err := q.UpdateField(specialUse, false)
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
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

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
				if err == bstore.ErrAbsent {
					xcheckuserf(ctx, err, "get message")
				}
				xcheckf(ctx, err, "get message")
				threadIDs[m.ThreadID] = struct{}{}
				msgIDs[id] = struct{}{}
			}

			var updated []store.Message
			q := bstore.QueryTx[store.Message](tx)
			q.FilterEqual("ThreadID", slicesAny(maps.Keys(threadIDs))...)
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
			_, err = q.UpdateFields(map[string]any{"ThreadCollapsed": collapse})
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
	log := xlog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

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
				if err == bstore.ErrAbsent {
					xcheckuserf(ctx, err, "get message")
				}
				xcheckf(ctx, err, "get message")
				threadIDs[m.ThreadID] = struct{}{}
				msgIDs[id] = struct{}{}
			}

			var updated []store.Message

			q := bstore.QueryTx[store.Message](tx)
			q.FilterEqual("ThreadID", slicesAny(maps.Keys(threadIDs))...)
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
			_, err = q.UpdateFields(fields)
			xcheckf(ctx, err, "updating mute in database")

			for _, m := range updated {
				changes = append(changes, m.ChangeThread())
			}
		})
		store.BroadcastChanges(acc, changes)
	})
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
