package imapserver

// todo: if fetch fails part-way through the command, we wouldn't be storing the messages that were parsed. should we try harder to get parsed form of messages stored in db?

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strings"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
)

// functions to handle fetch attribute requests are defined on fetchCmd.
type fetchCmd struct {
	conn          *conn
	mailboxID     int64
	uid           store.UID
	tx            *bstore.Tx     // Writable tx, for storing message when first parsed as mime parts.
	changes       []store.Change // For updated Seen flag.
	markSeen      bool
	needFlags     bool
	expungeIssued bool // Set if a message cannot be read. Can happen for expunged messages.

	// Loaded when first needed, closed when message was processed.
	m    *store.Message // Message currently being processed.
	msgr *store.MsgReader
	part *message.Part
}

// error when processing an attribute. we typically just don't respond with requested attributes that encounter a failure.
type attrError struct{ err error }

func (e attrError) Error() string {
	return e.err.Error()
}

// raise error processing an attribute.
func (cmd *fetchCmd) xerrorf(format string, args ...any) {
	panic(attrError{fmt.Errorf(format, args...)})
}

func (cmd *fetchCmd) xcheckf(err error, format string, args ...any) {
	if err != nil {
		msg := fmt.Sprintf(format, args...)
		cmd.xerrorf("%s: %w", msg, err)
	}
}

// Fetch returns information about messages, be it email envelopes, headers,
// bodies, full messages, flags.
//
// State: Selected
func (c *conn) cmdxFetch(isUID bool, tag, cmdstr string, p *parser) {
	// Command: ../rfc/9051:4330 ../rfc/3501:2992
	// Examples: ../rfc/9051:4463 ../rfc/9051:4520
	// Response syntax: ../rfc/9051:6742 ../rfc/3501:4864

	// Request syntax: ../rfc/9051:6553 ../rfc/3501:4748
	p.xspace()
	nums := p.xnumSet()
	p.xspace()
	atts := p.xfetchAtts()
	p.xempty()

	// We don't use c.account.WithRLock because we write to the client while reading messages.
	// We get the rlock, then we check the mailbox, release the lock and read the messages.
	// The db transaction still locks out any changes to the database...
	c.account.RLock()
	runlock := c.account.RUnlock
	// Note: we call runlock in a closure because we replace it below.
	defer func() {
		runlock()
	}()

	cmd := &fetchCmd{conn: c, mailboxID: c.mailboxID}
	c.xdbwrite(func(tx *bstore.Tx) {
		cmd.tx = tx

		// Ensure the mailbox still exists.
		c.xmailboxID(tx, c.mailboxID)

		uids := c.xnumSetUIDs(isUID, nums)

		// Release the account lock.
		runlock()
		runlock = func() {} // Prevent defer from unlocking again.

		for _, uid := range uids {
			cmd.uid = uid
			cmd.process(atts)
		}
	})

	if len(cmd.changes) > 0 {
		// Broadcast seen updates to other connections.
		c.broadcast(cmd.changes)
	}

	if cmd.expungeIssued {
		// ../rfc/2180:343
		c.writeresultf("%s NO [EXPUNGEISSUED] at least one message was expunged", tag)
	} else {
		c.ok(tag, cmdstr)
	}
}

func (cmd *fetchCmd) xensureMessage() *store.Message {
	if cmd.m != nil {
		return cmd.m
	}

	q := bstore.QueryTx[store.Message](cmd.tx)
	q.FilterNonzero(store.Message{MailboxID: cmd.mailboxID, UID: cmd.uid})
	m, err := q.Get()
	cmd.xcheckf(err, "get message for uid %d", cmd.uid)
	cmd.m = &m
	return cmd.m
}

func (cmd *fetchCmd) xensureParsed() (*store.MsgReader, *message.Part) {
	if cmd.msgr != nil {
		return cmd.msgr, cmd.part
	}

	m := cmd.xensureMessage()

	cmd.msgr = cmd.conn.account.MessageReader(*m)
	defer func() {
		if cmd.part == nil {
			err := cmd.msgr.Close()
			cmd.conn.xsanity(err, "closing messagereader")
			cmd.msgr = nil
		}
	}()

	p, err := m.LoadPart(cmd.msgr)
	xcheckf(err, "load parsed message")
	cmd.part = &p
	return cmd.msgr, cmd.part
}

func (cmd *fetchCmd) process(atts []fetchAtt) {
	defer func() {
		cmd.m = nil
		cmd.part = nil
		if cmd.msgr != nil {
			err := cmd.msgr.Close()
			cmd.conn.xsanity(err, "closing messagereader")
			cmd.msgr = nil
		}

		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(attrError)
		if !ok {
			panic(x)
		}
		if errors.Is(err, bstore.ErrAbsent) {
			cmd.expungeIssued = true
			return
		}
		cmd.conn.log.Infox("processing fetch attribute", err, mlog.Field("uid", cmd.uid))
		xuserErrorf("processing fetch attribute: %v", err)
	}()

	data := listspace{bare("UID"), number(cmd.uid)}

	cmd.markSeen = false
	cmd.needFlags = false

	for _, a := range atts {
		data = append(data, cmd.xprocessAtt(a)...)
	}

	if cmd.markSeen {
		m := cmd.xensureMessage()
		m.Seen = true
		err := cmd.tx.Update(m)
		xcheckf(err, "marking message as seen")

		cmd.changes = append(cmd.changes, store.ChangeFlags{MailboxID: cmd.mailboxID, UID: cmd.uid, Mask: store.Flags{Seen: true}, Flags: m.Flags, Keywords: m.Keywords})
	}

	if cmd.needFlags {
		m := cmd.xensureMessage()
		data = append(data, bare("FLAGS"), flaglist(m.Flags, m.Keywords))
	}

	// Write errors are turned into panics because we write through c.
	fmt.Fprintf(cmd.conn.bw, "* %d FETCH ", cmd.conn.xsequence(cmd.uid))
	data.writeTo(cmd.conn, cmd.conn.bw)
	cmd.conn.bw.Write([]byte("\r\n"))
}

// result for one attribute. if processing fails, e.g. because data was requested
// that doesn't exist and cannot be represented in imap, the attribute is simply
// not returned to the user. in this case, the returned value is a nil list.
func (cmd *fetchCmd) xprocessAtt(a fetchAtt) []token {
	switch a.field {
	case "UID":
		// Always present.
		return nil
	case "ENVELOPE":
		_, part := cmd.xensureParsed()
		envelope := xenvelope(part)
		return []token{bare("ENVELOPE"), envelope}

	case "INTERNALDATE":
		// ../rfc/9051:6753 ../rfc/9051:6502
		m := cmd.xensureMessage()
		return []token{bare("INTERNALDATE"), dquote(m.Received.Format("_2-Jan-2006 15:04:05 -0700"))}

	case "BODYSTRUCTURE":
		_, part := cmd.xensureParsed()
		bs := xbodystructure(part)
		return []token{bare("BODYSTRUCTURE"), bs}

	case "BODY":
		respField, t := cmd.xbody(a)
		if respField == "" {
			return nil
		}
		return []token{bare(respField), t}

	case "BINARY.SIZE":
		_, p := cmd.xensureParsed()
		if len(a.sectionBinary) == 0 {
			// Must return the size of the entire message but with decoded body.
			// todo: make this less expensive and/or cache the result?
			n, err := io.Copy(io.Discard, cmd.xbinaryMessageReader(p))
			cmd.xcheckf(err, "reading message as binary for its size")
			return []token{bare(cmd.sectionRespField(a)), number(uint32(n))}
		}
		p = cmd.xpartnumsDeref(a.sectionBinary, p)
		if len(p.Parts) > 0 || p.Message != nil {
			// ../rfc/9051:4385
			cmd.xerrorf("binary only allowed on leaf parts, not multipart/* or message/rfc822 or message/global")
		}
		return []token{bare(cmd.sectionRespField(a)), number(p.DecodedSize)}

	case "BINARY":
		respField, t := cmd.xbinary(a)
		if respField == "" {
			return nil
		}
		return []token{bare(respField), t}

	case "RFC822.SIZE":
		m := cmd.xensureMessage()
		return []token{bare("RFC822.SIZE"), number(m.Size)}

	case "RFC822.HEADER":
		ba := fetchAtt{
			field: "BODY",
			peek:  true,
			section: &sectionSpec{
				msgtext: &sectionMsgtext{s: "HEADER"},
			},
		}
		respField, t := cmd.xbody(ba)
		if respField == "" {
			return nil
		}
		return []token{bare(a.field), t}

	case "RFC822":
		ba := fetchAtt{
			field:   "BODY",
			section: &sectionSpec{},
		}
		respField, t := cmd.xbody(ba)
		if respField == "" {
			return nil
		}
		return []token{bare(a.field), t}

	case "RFC822.TEXT":
		ba := fetchAtt{
			field: "BODY",
			section: &sectionSpec{
				msgtext: &sectionMsgtext{s: "TEXT"},
			},
		}
		respField, t := cmd.xbody(ba)
		if respField == "" {
			return nil
		}
		return []token{bare(a.field), t}

	case "FLAGS":
		cmd.needFlags = true

	default:
		xserverErrorf("field %q not yet implemented", a.field)
	}
	return nil
}

// ../rfc/9051:6522
func xenvelope(p *message.Part) token {
	var env message.Envelope
	if p.Envelope != nil {
		env = *p.Envelope
	}
	var date token = nilt
	if !env.Date.IsZero() {
		// ../rfc/5322:791
		date = string0(env.Date.Format("Mon, 2 Jan 2006 15:04:05 -0700"))
	}
	var subject token = nilt
	if env.Subject != "" {
		subject = string0(env.Subject)
	}
	var inReplyTo token = nilt
	if env.InReplyTo != "" {
		inReplyTo = string0(env.InReplyTo)
	}
	var messageID token = nilt
	if env.MessageID != "" {
		messageID = string0(env.MessageID)
	}

	addresses := func(l []message.Address) token {
		if len(l) == 0 {
			return nilt
		}
		r := listspace{}
		for _, a := range l {
			var name token = nilt
			if a.Name != "" {
				name = string0(a.Name)
			}
			user := string0(a.User)
			var host token = nilt
			if a.Host != "" {
				host = string0(a.Host)
			}
			r = append(r, listspace{name, nilt, user, host})
		}
		return r
	}

	// Empty sender or reply-to result in fall-back to from. ../rfc/9051:6140
	sender := env.Sender
	if len(sender) == 0 {
		sender = env.From
	}
	replyTo := env.ReplyTo
	if len(replyTo) == 0 {
		replyTo = env.From
	}

	return listspace{
		date,
		subject,
		addresses(env.From),
		addresses(sender),
		addresses(replyTo),
		addresses(env.To),
		addresses(env.CC),
		addresses(env.BCC),
		inReplyTo,
		messageID,
	}
}

func (cmd *fetchCmd) peekOrSeen(peek bool) {
	if cmd.conn.readonly || peek {
		return
	}
	m := cmd.xensureMessage()
	if !m.Seen {
		cmd.markSeen = true
		cmd.needFlags = true
	}
}

// reader that returns the message, but with header Content-Transfer-Encoding left out.
func (cmd *fetchCmd) xbinaryMessageReader(p *message.Part) io.Reader {
	hr := cmd.xmodifiedHeader(p, []string{"Content-Transfer-Encoding"}, true)
	return io.MultiReader(hr, p.Reader())
}

// return header with only fields, or with everything except fields if "not" is set.
func (cmd *fetchCmd) xmodifiedHeader(p *message.Part, fields []string, not bool) io.Reader {
	h, err := io.ReadAll(p.HeaderReader())
	cmd.xcheckf(err, "reading header")

	matchesFields := func(line []byte) bool {
		k := bytes.TrimRight(bytes.SplitN(line, []byte(":"), 2)[0], " \t")
		for _, f := range fields {
			if bytes.EqualFold(k, []byte(f)) {
				return true
			}
		}
		return false
	}

	var match bool
	hb := &bytes.Buffer{}
	for len(h) > 0 {
		line := h
		i := bytes.Index(line, []byte("\r\n"))
		if i >= 0 {
			line = line[:i+2]
		}
		h = h[len(line):]

		match = matchesFields(line) || match && (bytes.HasPrefix(line, []byte(" ")) || bytes.HasPrefix(line, []byte("\t")))
		if match != not || len(line) == 2 {
			hb.Write(line)
		}
	}
	return hb
}

func (cmd *fetchCmd) xbinary(a fetchAtt) (string, token) {
	_, part := cmd.xensureParsed()

	cmd.peekOrSeen(a.peek)
	if len(a.sectionBinary) == 0 {
		r := cmd.xbinaryMessageReader(part)
		if a.partial != nil {
			r = cmd.xpartialReader(a.partial, r)
		}
		return cmd.sectionRespField(a), readerSyncliteral{r}
	}

	p := part
	if len(a.sectionBinary) > 0 {
		p = cmd.xpartnumsDeref(a.sectionBinary, p)
	}
	if len(p.Parts) != 0 || p.Message != nil {
		// ../rfc/9051:4385
		cmd.xerrorf("binary only allowed on leaf parts, not multipart/* or message/rfc822 or message/global")
	}

	switch p.ContentTransferEncoding {
	case "", "7BIT", "8BIT", "BINARY", "BASE64", "QUOTED-PRINTABLE":
	default:
		// ../rfc/9051:5913
		xusercodeErrorf("UNKNOWN-CTE", "unknown Content-Transfer-Encoding %q", p.ContentTransferEncoding)
	}

	r := p.Reader()
	if a.partial != nil {
		r = cmd.xpartialReader(a.partial, r)
	}
	return cmd.sectionRespField(a), readerSyncliteral{r}
}

func (cmd *fetchCmd) xpartialReader(partial *partial, r io.Reader) io.Reader {
	n, err := io.Copy(io.Discard, io.LimitReader(r, int64(partial.offset)))
	cmd.xcheckf(err, "skipping to offset for partial")
	if n != int64(partial.offset) {
		return strings.NewReader("") // ../rfc/3501:3143 ../rfc/9051:4418
	}
	return io.LimitReader(r, int64(partial.count))
}

func (cmd *fetchCmd) xbody(a fetchAtt) (string, token) {
	msgr, part := cmd.xensureParsed()

	if a.section == nil {
		// Non-extensible form of BODYSTRUCTURE.
		return a.field, xbodystructure(part)
	}

	cmd.peekOrSeen(a.peek)

	respField := cmd.sectionRespField(a)

	if a.section.msgtext == nil && a.section.part == nil {
		m := cmd.xensureMessage()
		var offset int64
		count := m.Size
		if a.partial != nil {
			offset = int64(a.partial.offset)
			if offset > m.Size {
				offset = m.Size
			}
			count = int64(a.partial.count)
			if offset+count > m.Size {
				count = m.Size - offset
			}
		}
		return respField, readerSizeSyncliteral{&moxio.AtReader{R: msgr, Offset: offset}, count}
	}

	sr := cmd.xsection(a.section, part)

	if a.partial != nil {
		n, err := io.Copy(io.Discard, io.LimitReader(sr, int64(a.partial.offset)))
		cmd.xcheckf(err, "skipping to offset for partial")
		if n != int64(a.partial.offset) {
			return respField, syncliteral("") // ../rfc/3501:3143 ../rfc/9051:4418
		}
		return respField, readerSyncliteral{io.LimitReader(sr, int64(a.partial.count))}
	}
	return respField, readerSyncliteral{sr}
}

func (cmd *fetchCmd) xpartnumsDeref(nums []uint32, p *message.Part) *message.Part {
	// ../rfc/9051:4481
	if (len(p.Parts) == 0 && p.Message == nil) && len(nums) == 1 && nums[0] == 1 {
		return p
	}

	// ../rfc/9051:4485
	for i, num := range nums {
		index := int(num - 1)
		if p.Message != nil {
			err := p.SetMessageReaderAt()
			cmd.xcheckf(err, "preparing submessage")
			return cmd.xpartnumsDeref(nums[i:], p.Message)
		}
		if index < 0 || index >= len(p.Parts) {
			cmd.xerrorf("requested part does not exist")
		}
		p = &p.Parts[index]
	}
	return p
}

func (cmd *fetchCmd) xsection(section *sectionSpec, p *message.Part) io.Reader {
	if section.part == nil {
		return cmd.xsectionMsgtext(section.msgtext, p)
	}

	p = cmd.xpartnumsDeref(section.part.part, p)

	if section.part.text == nil {
		return p.RawReader()
	}

	// ../rfc/9051:4535
	if p.Message != nil {
		err := p.SetMessageReaderAt()
		cmd.xcheckf(err, "preparing submessage")
		p = p.Message
	}

	if !section.part.text.mime {
		return cmd.xsectionMsgtext(section.part.text.msgtext, p)
	}

	// MIME header, see ../rfc/9051:4534 ../rfc/2045:1645
	h, err := io.ReadAll(p.HeaderReader())
	cmd.xcheckf(err, "reading header")

	matchesFields := func(line []byte) bool {
		k := textproto.CanonicalMIMEHeaderKey(string(bytes.TrimRight(bytes.SplitN(line, []byte(":"), 2)[0], " \t")))
		// Only add MIME-Version and additional CRLF for messages, not other parts. ../rfc/2045:1645 ../rfc/2045:1652
		return (p.Envelope != nil && k == "Mime-Version") || strings.HasPrefix(k, "Content-")
	}

	var match bool
	hb := &bytes.Buffer{}
	for len(h) > 0 {
		line := h
		i := bytes.Index(line, []byte("\r\n"))
		if i >= 0 {
			line = line[:i+2]
		}
		h = h[len(line):]

		match = matchesFields(line) || match && (bytes.HasPrefix(line, []byte(" ")) || bytes.HasPrefix(line, []byte("\t")))
		if match || len(line) == 2 {
			hb.Write(line)
		}
	}
	return hb
}

func (cmd *fetchCmd) xsectionMsgtext(smt *sectionMsgtext, p *message.Part) io.Reader {
	if smt.s == "HEADER" {
		return p.HeaderReader()
	}

	switch smt.s {
	case "HEADER.FIELDS":
		return cmd.xmodifiedHeader(p, smt.headers, false)

	case "HEADER.FIELDS.NOT":
		return cmd.xmodifiedHeader(p, smt.headers, true)

	case "TEXT":
		// It appears imap clients expect to get the body of the message, not a "text body"
		// which sounds like it means a text/* part of a message. ../rfc/9051:4517
		return p.RawReader()
	}
	panic(serverError{fmt.Errorf("missing case")})
}

func (cmd *fetchCmd) sectionRespField(a fetchAtt) string {
	s := a.field + "["
	if len(a.sectionBinary) > 0 {
		s += fmt.Sprintf("%d", a.sectionBinary[0])
		for _, v := range a.sectionBinary[1:] {
			s += "." + fmt.Sprintf("%d", v)
		}
	} else if a.section != nil {
		if a.section.part != nil {
			p := a.section.part
			s += fmt.Sprintf("%d", p.part[0])
			for _, v := range p.part[1:] {
				s += "." + fmt.Sprintf("%d", v)
			}
			if p.text != nil {
				if p.text.mime {
					s += ".MIME"
				} else {
					s += "." + cmd.sectionMsgtextName(p.text.msgtext)
				}
			}
		} else if a.section.msgtext != nil {
			s += cmd.sectionMsgtextName(a.section.msgtext)
		}
	}
	s += "]"
	// binary does not have partial in field, unlike BODY ../rfc/9051:6757
	if a.field != "BINARY" && a.partial != nil {
		s += fmt.Sprintf("<%d>", a.partial.offset)
	}
	return s
}

func (cmd *fetchCmd) sectionMsgtextName(smt *sectionMsgtext) string {
	s := smt.s
	if strings.HasPrefix(smt.s, "HEADER.FIELDS") {
		l := listspace{}
		for _, h := range smt.headers {
			l = append(l, astring(h))
		}
		s += " " + l.pack(cmd.conn)
	}
	return s
}

func bodyFldParams(params map[string]string) token {
	if len(params) == 0 {
		return nilt
	}
	// Ensure same ordering, easier for testing.
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	l := make(listspace, 2*len(keys))
	i := 0
	for _, k := range keys {
		l[i] = string0(strings.ToUpper(k))
		l[i+1] = string0(params[k])
		i += 2
	}
	return l
}

func bodyFldEnc(s string) token {
	up := strings.ToUpper(s)
	switch up {
	case "7BIT", "8BIT", "BINARY", "BASE64", "QUOTED-PRINTABLE":
		return dquote(up)
	}
	return string0(s)
}

// xbodystructure returns a "body".
// calls itself for multipart messages and message/{rfc822,global}.
func xbodystructure(p *message.Part) token {
	if p.MediaType == "MULTIPART" {
		// Multipart, ../rfc/9051:6355 ../rfc/9051:6411
		var bodies concat
		for i := range p.Parts {
			bodies = append(bodies, xbodystructure(&p.Parts[i]))
		}
		return listspace{bodies, string0(p.MediaSubType)}
	}

	// ../rfc/9051:6355
	if p.MediaType == "TEXT" {
		// ../rfc/9051:6404 ../rfc/9051:6418
		return listspace{
			dquote("TEXT"), string0(p.MediaSubType), // ../rfc/9051:6739
			// ../rfc/9051:6376
			bodyFldParams(p.ContentTypeParams), // ../rfc/9051:6401
			nilOrString(p.ContentID),
			nilOrString(p.ContentDescription),
			bodyFldEnc(p.ContentTransferEncoding),
			number(p.EndOffset - p.BodyOffset),
			number(p.RawLineCount),
		}
	} else if p.MediaType == "MESSAGE" && (p.MediaSubType == "RFC822" || p.MediaSubType == "GLOBAL") {
		// ../rfc/9051:6415
		// note: we don't have to prepare p.Message for reading, because we aren't going to read from it.
		return listspace{
			dquote("MESSAGE"), dquote(p.MediaSubType), // ../rfc/9051:6732
			// ../rfc/9051:6376
			bodyFldParams(p.ContentTypeParams), // ../rfc/9051:6401
			nilOrString(p.ContentID),
			nilOrString(p.ContentDescription),
			bodyFldEnc(p.ContentTransferEncoding),
			number(p.EndOffset - p.BodyOffset),
			xenvelope(p.Message),
			xbodystructure(p.Message),
			number(p.RawLineCount), // todo: or mp.RawLineCount?
		}
	}
	var media token
	switch p.MediaType {
	case "APPLICATION", "AUDIO", "IMAGE", "FONT", "MESSAGE", "MODEL", "VIDEO":
		media = dquote(p.MediaType)
	default:
		media = string0(p.MediaType)
	}
	// ../rfc/9051:6404 ../rfc/9051:6407
	return listspace{
		media, string0(p.MediaSubType), // ../rfc/9051:6723
		// ../rfc/9051:6376
		bodyFldParams(p.ContentTypeParams), // ../rfc/9051:6401
		nilOrString(p.ContentID),
		nilOrString(p.ContentDescription),
		bodyFldEnc(p.ContentTransferEncoding),
		number(p.EndOffset - p.BodyOffset),
	}
}
