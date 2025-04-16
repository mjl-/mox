package imapserver

// todo: if fetch fails part-way through the command, we wouldn't be storing the messages that were parsed. should we try harder to get parsed form of messages stored in db?

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/textproto"
	"slices"
	"strings"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
)

// functions to handle fetch attribute requests are defined on fetchCmd.
type fetchCmd struct {
	conn            *conn
	isUID           bool        // If this is a UID FETCH command.
	rtx             *bstore.Tx  // Read-only transaction, kept open while processing all messages.
	updateSeen      []store.UID // To mark as seen after processing all messages. UID instead of message ID since moved messages keep their ID and insert a new ID in the original mailbox.
	hasChangedSince bool        // Whether CHANGEDSINCE was set. Enables MODSEQ in response.
	expungeIssued   bool        // Set if any message has been expunged. Can happen for expunged messages.

	// For message currently processing.
	mailboxID int64
	uid       store.UID

	markSeen    bool
	needFlags   bool
	needModseq  bool                 // Whether untagged responses needs modseq.
	newPreviews map[store.UID]string // Save with messages when done.

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
	// Command: ../rfc/9051:4330 ../rfc/3501:2992 ../rfc/7162:864
	// Examples: ../rfc/9051:4463 ../rfc/9051:4520 ../rfc/7162:880
	// Response syntax: ../rfc/9051:6742 ../rfc/3501:4864 ../rfc/7162:2490

	// Request syntax: ../rfc/9051:6553 ../rfc/3501:4748 ../rfc/4466:535 ../rfc/7162:2475
	p.xspace()
	nums := p.xnumSet()
	p.xspace()
	atts := p.xfetchAtts()
	var changedSince int64
	var haveChangedSince bool
	var vanished bool
	if p.space() {
		// ../rfc/4466:542
		// ../rfc/7162:2479
		p.xtake("(")
		seen := map[string]bool{}
		for {
			var w string
			if isUID && p.conn.enabled[capQresync] {
				// Vanished only valid for uid fetch, and only for qresync. ../rfc/7162:1693
				w = p.xtakelist("CHANGEDSINCE", "VANISHED")
			} else {
				w = p.xtakelist("CHANGEDSINCE")
			}
			if seen[w] {
				xsyntaxErrorf("duplicate fetch modifier %s", w)
			}
			seen[w] = true
			switch w {
			case "CHANGEDSINCE":
				p.xspace()
				changedSince = p.xnumber64()
				// workaround: ios mail (16.5.1) was seen sending changedSince 0 on an existing account that got condstore enabled.
				if changedSince == 0 && mox.Pedantic {
					// ../rfc/7162:2551
					xsyntaxErrorf("changedsince modseq must be > 0")
				}
				// CHANGEDSINCE is a CONDSTORE-enabling parameter. ../rfc/7162:380
				p.conn.xensureCondstore(nil)
				haveChangedSince = true
			case "VANISHED":
				vanished = true
			}
			if p.take(")") {
				break
			}
			p.xspace()
		}

		// ../rfc/7162:1701
		if vanished && !haveChangedSince {
			xsyntaxErrorf("VANISHED can only be used with CHANGEDSINCE")
		}
	}
	p.xempty()

	// We only keep a wlock, only for initial checks and listing the uids. Then we
	// unlock and work without a lock. So changes to the store can happen, and we need
	// to deal with that. If we need to mark messages as seen, we do so after
	// processing the fetch for all messages, in a single write transaction. We don't
	// send untagged changes for those \seen flag changes before finishing this
	// command, because we have to sequence all changes properly, and since we don't
	// (want to) hold a wlock while processing messages (can be many!), other changes
	// may have happened to the store. So instead, we'll silently mark messages as seen
	// (the client should know this is happening anyway!), then broadcast the changes
	// to everyone, including ourselves. A noop/idle command that may come next will
	// return the \seen flag changes, in the correct order, with the correct modseq. We
	// also cannot just apply pending changes while processing. It is not allowed at
	// all for non-uid-fetch. It would also make life more complicated, e.g. we would
	// perhaps have to check if newly added messages also match uid fetch set that was
	// requested.

	var uids []store.UID
	var vanishedUIDs []store.UID

	cmd := &fetchCmd{conn: c, isUID: isUID, hasChangedSince: haveChangedSince, mailboxID: c.mailboxID, newPreviews: map[store.UID]string{}}

	defer func() {
		if cmd.rtx == nil {
			return
		}
		err := cmd.rtx.Rollback()
		c.log.Check(err, "rollback rtx")
		cmd.rtx = nil
	}()

	c.account.WithRLock(func() {
		var err error
		cmd.rtx, err = c.account.DB.Begin(context.TODO(), false)
		cmd.xcheckf(err, "begin transaction")

		// Ensure the mailbox still exists.
		c.xmailboxID(cmd.rtx, c.mailboxID)

		// With changedSince, the client is likely asking for a small set of changes. Use a
		// database query to trim down the uids we need to look at. We need to go through
		// the database for "VANISHED (EARLIER)" anyway, to see UIDs that aren't in the
		// session anymore. Vanished must be used with changedSince. ../rfc/7162:871
		if changedSince > 0 {
			q := bstore.QueryTx[store.Message](cmd.rtx)
			q.FilterNonzero(store.Message{MailboxID: c.mailboxID})
			q.FilterGreater("ModSeq", store.ModSeqFromClient(changedSince))
			if !vanished {
				q.FilterEqual("Expunged", false)
			}
			err := q.ForEach(func(m store.Message) error {
				if m.UID >= c.uidnext {
					return nil
				}
				if isUID {
					if nums.xcontainsKnownUID(m.UID, c.searchResult, func() store.UID { return c.uidnext - 1 }) {
						if m.Expunged {
							vanishedUIDs = append(vanishedUIDs, m.UID)
						} else {
							uids = append(uids, m.UID)
						}
					}
				} else {
					seq := c.sequence(m.UID)
					if seq > 0 && nums.containsSeq(seq, c.uids, c.searchResult) {
						uids = append(uids, m.UID)
					}
				}
				return nil
			})
			xcheckf(err, "looking up messages with changedsince")

			// In case of vanished where we don't have the full history, we must send VANISHED
			// for all uids matching nums. ../rfc/7162:1718
			delModSeq, err := c.account.HighestDeletedModSeq(cmd.rtx)
			xcheckf(err, "looking up highest deleted modseq")
			if !vanished || changedSince >= delModSeq.Client() {
				return
			}

			// We'll iterate through all UIDs in the numset, and add anything that isn't
			// already in uids and vanishedUIDs. First sort the uids we already found, for fast
			// lookup. We'll gather new UIDs in more, so we don't break the binary search.
			slices.Sort(vanishedUIDs)
			slices.Sort(uids)

			more := map[store.UID]struct{}{} // We'll add them at the end.
			checkVanished := func(uid store.UID) {
				if uid < c.uidnext && uidSearch(uids, uid) <= 0 && uidSearch(vanishedUIDs, uid) <= 0 {
					more[uid] = struct{}{}
				}
			}

			// Now look through the requested uids. We may have a searchResult, handle it
			// separately from a numset with potential stars, over which we can more easily
			// iterate.
			if nums.searchResult {
				for _, uid := range c.searchResult {
					checkVanished(uid)
				}
			} else {
				xlastUID := c.newCachedLastUID(cmd.rtx, c.mailboxID, func(xerr error) { xuserErrorf("%s", xerr) })
				iter := nums.xinterpretStar(xlastUID).newIter()
				for {
					num, ok := iter.Next()
					if !ok {
						break
					}
					checkVanished(store.UID(num))
				}
			}
			vanishedUIDs = slices.AppendSeq(vanishedUIDs, maps.Keys(more))
			slices.Sort(vanishedUIDs)
		} else {
			uids = c.xnumSetEval(cmd.rtx, isUID, nums)
		}

	})
	// We are continuing without a lock, working off our snapshot of uids to process.

	// First report all vanished UIDs. ../rfc/7162:1714
	if len(vanishedUIDs) > 0 {
		// Mention all vanished UIDs in compact numset form.
		// ../rfc/7162:1985
		// No hard limit on response sizes, but clients are recommended to not send more
		// than 8k. We send a more conservative max 4k.
		for _, s := range compactUIDSet(vanishedUIDs).Strings(4*1024 - 32) {
			c.xbwritelinef("* VANISHED (EARLIER) %s", s)
		}
	}

	defer cmd.msgclose() // In case of panic.

	for _, cmd.uid = range uids {
		cmd.conn.log.Debug("processing uid", slog.Any("uid", cmd.uid))
		data, err := cmd.process(atts)
		if err != nil {
			cmd.conn.log.Infox("processing fetch attribute", err, slog.Any("uid", cmd.uid))
			xuserErrorf("processing fetch attribute: %v", err)
		}

		// UIDFETCH in case of uidonly. ../rfc/9586:181
		if c.uidonly {
			fmt.Fprintf(cmd.conn.xbw, "* %d UIDFETCH ", cmd.uid)
		} else {
			fmt.Fprintf(cmd.conn.xbw, "* %d FETCH ", cmd.conn.xsequence(cmd.uid))
		}
		data.xwriteTo(cmd.conn, cmd.conn.xbw)
		cmd.conn.xbw.Write([]byte("\r\n"))

		cmd.msgclose()
	}

	// We've returned all data. Now we mark messages as seen in one go, in a new write
	// transaction. We don't send untagged messages for the changes, since there may be
	// unprocessed pending changes. Instead, we broadcast them to ourselve too, so a
	// next noop/idle will return the flags to the client.

	err := cmd.rtx.Rollback()
	c.log.Check(err, "fetch read tx rollback")
	cmd.rtx = nil

	// ../rfc/9051:4432 We mark all messages that need it as seen at the end of the
	// command, in a single transaction.
	if len(cmd.updateSeen) > 0 || len(cmd.newPreviews) > 0 {
		c.account.WithWLock(func() {
			changes := make([]store.Change, 0, len(cmd.updateSeen)+1)

			c.xdbwrite(func(wtx *bstore.Tx) {
				mb, err := store.MailboxID(wtx, c.mailboxID)
				if err == store.ErrMailboxExpunged {
					xusercodeErrorf("NONEXISTENT", "mailbox has been expunged")
				}
				xcheckf(err, "get mailbox for updating counts after marking as seen")

				var modseq store.ModSeq

				for _, uid := range cmd.updateSeen {
					m, err := bstore.QueryTx[store.Message](wtx).FilterNonzero(store.Message{MailboxID: c.mailboxID, UID: uid}).Get()
					xcheckf(err, "get message")
					if m.Expunged {
						// Message has been deleted in the mean time.
						cmd.expungeIssued = true
						continue
					}
					if m.Seen {
						// Message already marked as seen by another process.
						continue
					}

					if modseq == 0 {
						modseq, err = c.account.NextModSeq(wtx)
						xcheckf(err, "get next mod seq")
					}

					oldFlags := m.Flags
					mb.Sub(m.MailboxCounts())
					m.Seen = true
					mb.Add(m.MailboxCounts())
					changes = append(changes, m.ChangeFlags(oldFlags, mb))

					m.ModSeq = modseq
					err = wtx.Update(&m)
					xcheckf(err, "mark message as seen")
				}

				changes = append(changes, mb.ChangeCounts())

				for uid, s := range cmd.newPreviews {
					m, err := bstore.QueryTx[store.Message](wtx).FilterNonzero(store.Message{MailboxID: c.mailboxID, UID: uid}).Get()
					xcheckf(err, "get message")
					if m.Expunged {
						// Message has been deleted in the mean time.
						cmd.expungeIssued = true
						continue
					}

					// note: we are not updating modseq.

					m.Preview = &s
					err = wtx.Update(&m)
					xcheckf(err, "saving preview with message")
				}

				if modseq > 0 {
					mb.ModSeq = modseq
					err = wtx.Update(&mb)
					xcheckf(err, "update mailbox with counts and modseq")
				}
			})

			// Broadcast these changes also to ourselves, so we'll send the updated flags, but
			// in the correct order, after other changes.
			store.BroadcastChanges(c.account, changes)
		})
	}

	if cmd.expungeIssued {
		// ../rfc/2180:343
		// ../rfc/9051:5102
		c.xwriteresultf("%s OK [EXPUNGEISSUED] at least one message was expunged", tag)
	} else {
		c.ok(tag, cmdstr)
	}
}

func (cmd *fetchCmd) xensureMessage() *store.Message {
	if cmd.m != nil {
		return cmd.m
	}

	// We do not filter by Expunged, the message may have been deleted in other
	// sessions, but not in ours.
	q := bstore.QueryTx[store.Message](cmd.rtx)
	q.FilterNonzero(store.Message{MailboxID: cmd.mailboxID, UID: cmd.uid})
	m, err := q.Get()
	cmd.xcheckf(err, "get message for uid %d", cmd.uid)
	cmd.m = &m
	if m.Expunged {
		cmd.expungeIssued = true
	}
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

// msgclose must be called after processing a message (after having written/used
// its data), even in the case of a panic.
func (cmd *fetchCmd) msgclose() {
	cmd.m = nil
	cmd.part = nil
	if cmd.msgr != nil {
		err := cmd.msgr.Close()
		cmd.conn.xsanity(err, "closing messagereader")
		cmd.msgr = nil
	}
}

func (cmd *fetchCmd) process(atts []fetchAtt) (rdata listspace, rerr error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(attrError)
		if !ok {
			panic(x)
		} else if rerr == nil {
			rerr = err
		}
	}()

	var data listspace
	if !cmd.conn.uidonly {
		data = append(data, bare("UID"), number(cmd.uid))
	}

	cmd.markSeen = false
	cmd.needFlags = false
	cmd.needModseq = false

	for _, a := range atts {
		data = append(data, cmd.xprocessAtt(a)...)
	}

	if cmd.markSeen {
		cmd.updateSeen = append(cmd.updateSeen, cmd.uid)
	}

	if cmd.needFlags {
		m := cmd.xensureMessage()
		data = append(data, bare("FLAGS"), flaglist(m.Flags, m.Keywords))
	}

	// The wording around when to include the MODSEQ attribute is hard to follow and is
	// specified and refined in several places.
	//
	// An additional rule applies to "QRESYNC servers" (we'll assume it only applies
	// when QRESYNC is enabled on a connection): setting the \Seen flag also triggers
	// sending MODSEQ, and so does a UID FETCH command. ../rfc/7162:1421
	//
	// For example, ../rfc/7162:389 says the server must include modseq in "all
	// subsequent untagged fetch responses", then lists cases, but leaves out FETCH/UID
	// FETCH. That appears intentional, it is not a list of examples, it is the full
	// list, and the "all subsequent untagged fetch responses" doesn't mean "all", just
	// those covering the listed cases. That makes sense, because otherwise all the
	// other mentioning of cases elsewhere in the RFC would be too superfluous.
	//
	// ../rfc/7162:877 ../rfc/7162:388 ../rfc/7162:909 ../rfc/7162:1426
	if cmd.needModseq || cmd.hasChangedSince || cmd.conn.enabled[capQresync] && cmd.isUID {
		m := cmd.xensureMessage()
		data = append(data, bare("MODSEQ"), listspace{bare(fmt.Sprintf("%d", m.ModSeq.Client()))})
	}

	return data, nil
}

// result for one attribute. if processing fails, e.g. because data was requested
// that doesn't exist and cannot be represented in imap, the attribute is simply
// not returned to the user. in this case, the returned value is a nil list.
func (cmd *fetchCmd) xprocessAtt(a fetchAtt) []token {
	switch a.field {
	case "UID":
		// Present by default without uidonly. For uidonly, we only add it when explicitly
		// requested. ../rfc/9586:184
		if cmd.conn.uidonly {
			return []token{bare("UID"), number(cmd.uid)}
		}

	case "ENVELOPE":
		_, part := cmd.xensureParsed()
		envelope := xenvelope(part)
		return []token{bare("ENVELOPE"), envelope}

	case "INTERNALDATE":
		// ../rfc/9051:6753 ../rfc/9051:6502
		m := cmd.xensureMessage()
		return []token{bare("INTERNALDATE"), dquote(m.Received.Format("_2-Jan-2006 15:04:05 -0700"))}

	case "SAVEDATE":
		m := cmd.xensureMessage()
		// For messages in storage from before we implemented this extension, we don't have
		// a savedate, and we return nil. This is normally meant to be per mailbox, but
		// returning it per message should be fine. ../rfc/8514:191
		var savedate token = nilt
		if m.SaveDate != nil {
			savedate = dquote(m.SaveDate.Format("_2-Jan-2006 15:04:05 -0700"))
		}
		return []token{bare("SAVEDATE"), savedate}

	case "BODYSTRUCTURE":
		_, part := cmd.xensureParsed()
		bs := xbodystructure(cmd.conn.log, part, true)
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

	case "MODSEQ":
		cmd.needModseq = true

	case "PREVIEW":
		m := cmd.xensureMessage()
		preview := m.Preview
		// We ignore "lazy", generating the preview is fast enough.
		if preview == nil {
			// Get the preview. We'll save all generated previews in a single transaction at
			// the end.
			_, p := cmd.xensureParsed()
			s, err := p.Preview(cmd.conn.log)
			cmd.xcheckf(err, "generating preview")
			preview = &s
			cmd.newPreviews[m.UID] = s
		}
		var t token = nilt
		if preview != nil {
			s := *preview

			// Limit to 200 characters (not bytes). ../rfc/8970:206
			var n, o int
			for o = range s {
				n++
				if n > 200 {
					s = s[:o]
					break
				}
			}
			s = strings.TrimSpace(s)
			t = string0(s)
		}
		return []token{bare(a.field), t}

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

	var cte string
	if p.ContentTransferEncoding != nil {
		cte = *p.ContentTransferEncoding
	}
	switch cte {
	case "", "7BIT", "8BIT", "BINARY", "BASE64", "QUOTED-PRINTABLE":
	default:
		// ../rfc/9051:5913
		xusercodeErrorf("UNKNOWN-CTE", "unknown Content-Transfer-Encoding %q", cte)
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
		return a.field, xbodystructure(cmd.conn.log, part, false)
	}

	cmd.peekOrSeen(a.peek)

	respField := cmd.sectionRespField(a)

	if a.section.msgtext == nil && a.section.part == nil {
		m := cmd.xensureMessage()
		var offset int64
		count := m.Size
		if a.partial != nil {
			offset = min(int64(a.partial.offset), m.Size)
			count = int64(a.partial.count)
			if offset+count > m.Size {
				count = m.Size - offset
			}
		}
		return respField, readerSizeSyncliteral{&moxio.AtReader{R: msgr, Offset: offset}, count, false}
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
	// msgtext is not nil, i.e. HEADER* or TEXT (not MIME), for the top-level part (a message).
	if section.part == nil {
		return cmd.xsectionMsgtext(section.msgtext, p)
	}

	p = cmd.xpartnumsDeref(section.part.part, p)

	// If there is no sectionMsgText, then this isn't for HEADER*, TEXT or MIME, i.e. a
	// part body, e.g. "BODY[1]".
	if section.part.text == nil {
		return p.RawReader()
	}

	// MIME is defined for all parts. Otherwise it's HEADER* or TEXT, which is only
	// defined for parts that are messages. ../rfc/9051:4500 ../rfc/9051:4517
	if !section.part.text.mime {
		if p.Message == nil {
			cmd.xerrorf("part is not a message, cannot request header* or text")
		}

		err := p.SetMessageReaderAt()
		cmd.xcheckf(err, "preparing submessage")
		p = p.Message

		return cmd.xsectionMsgtext(section.part.text.msgtext, p)
	}

	// MIME header, see ../rfc/9051:4514 ../rfc/2045:1652
	h, err := io.ReadAll(p.HeaderReader())
	cmd.xcheckf(err, "reading header")

	matchesFields := func(line []byte) bool {
		k := textproto.CanonicalMIMEHeaderKey(string(bytes.TrimRight(bytes.SplitN(line, []byte(":"), 2)[0], " \t")))
		return strings.HasPrefix(k, "Content-")
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
		if match {
			hb.Write(line)
		}
	}
	return hb
}

func (cmd *fetchCmd) xsectionMsgtext(smt *sectionMsgtext, p *message.Part) io.Reader {
	switch smt.s {
	case "HEADER":
		return p.HeaderReader()

	case "HEADER.FIELDS":
		return cmd.xmodifiedHeader(p, smt.headers, false)

	case "HEADER.FIELDS.NOT":
		return cmd.xmodifiedHeader(p, smt.headers, true)

	case "TEXT":
		// TEXT the body (excluding headers) of a message, either the top-level message, or
		// a nested as message/rfc822 or message/global. ../rfc/9051:4517
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

func bodyFldParams(p *message.Part) token {
	if len(p.ContentTypeParams) == 0 {
		return nilt
	}
	params := make(listspace, 0, 2*len(p.ContentTypeParams))
	// Ensure same ordering, easier for testing.
	for _, k := range slices.Sorted(maps.Keys(p.ContentTypeParams)) {
		v := p.ContentTypeParams[k]
		params = append(params, string0(strings.ToUpper(k)), string0(v))
	}
	return params
}

func bodyFldEnc(cte *string) token {
	var s string
	if cte != nil {
		s = *cte
	}
	up := strings.ToUpper(s)
	switch up {
	case "7BIT", "8BIT", "BINARY", "BASE64", "QUOTED-PRINTABLE":
		return dquote(up)
	}
	return string0(s)
}

func bodyFldMd5(p *message.Part) token {
	if p.ContentMD5 == nil {
		return nilt
	}
	return string0(*p.ContentMD5)
}

func bodyFldDisp(log mlog.Log, p *message.Part) token {
	if p.ContentDisposition == nil {
		return nilt
	}

	// ../rfc/9051:5989
	// mime.ParseMediaType recombines parameter value continuations like "title*0" and
	// "title*1" into "title". ../rfc/2231:147
	// And decodes character sets and removes language tags, like
	// "title*0*=us-ascii'en'hello%20world. ../rfc/2231:210

	disp, params, err := mime.ParseMediaType(*p.ContentDisposition)
	if err != nil {
		log.Debugx("parsing content-disposition, ignoring", err, slog.String("header", *p.ContentDisposition))
		return nilt
	} else if len(params) == 0 {
		log.Debug("content-disposition has no parameters, ignoring", slog.String("header", *p.ContentDisposition))
		return nilt
	}
	var fields listspace
	for _, k := range slices.Sorted(maps.Keys(params)) {
		fields = append(fields, string0(k), string0(params[k]))
	}
	return listspace{string0(disp), fields}
}

func bodyFldLang(p *message.Part) token {
	// todo: ../rfc/3282:86 ../rfc/5646:218 we currently just split on comma and trim space, should properly parse header.
	if p.ContentLanguage == nil {
		return nilt
	}
	var l listspace
	for _, s := range strings.Split(*p.ContentLanguage, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			return string0(*p.ContentLanguage)
		}
		l = append(l, string0(s))
	}
	return l
}

func bodyFldLoc(p *message.Part) token {
	if p.ContentLocation == nil {
		return nilt
	}
	return string0(*p.ContentLocation)
}

// xbodystructure returns a "body".
// calls itself for multipart messages and message/{rfc822,global}.
func xbodystructure(log mlog.Log, p *message.Part, extensible bool) token {
	if p.MediaType == "MULTIPART" {
		// Multipart, ../rfc/9051:6355 ../rfc/9051:6411
		var bodies concat
		for i := range p.Parts {
			bodies = append(bodies, xbodystructure(log, &p.Parts[i], extensible))
		}
		r := listspace{bodies, string0(p.MediaSubType)}
		// ../rfc/9051:6371
		if extensible {
			r = append(r,
				bodyFldParams(p),
				bodyFldDisp(log, p),
				bodyFldLang(p),
				bodyFldLoc(p),
			)
		}
		return r
	}

	// ../rfc/9051:6355
	var r listspace
	if p.MediaType == "TEXT" {
		// ../rfc/9051:6404 ../rfc/9051:6418
		r = listspace{
			dquote("TEXT"), string0(p.MediaSubType), // ../rfc/9051:6739
			// ../rfc/9051:6376
			bodyFldParams(p), // ../rfc/9051:6401
			nilOrString(p.ContentID),
			nilOrString(p.ContentDescription),
			bodyFldEnc(p.ContentTransferEncoding),
			number(p.EndOffset - p.BodyOffset),
			number(p.RawLineCount),
		}
	} else if p.MediaType == "MESSAGE" && (p.MediaSubType == "RFC822" || p.MediaSubType == "GLOBAL") {
		// ../rfc/9051:6415
		// note: we don't have to prepare p.Message for reading, because we aren't going to read from it.
		r = listspace{
			dquote("MESSAGE"), dquote(p.MediaSubType), // ../rfc/9051:6732
			// ../rfc/9051:6376
			bodyFldParams(p), // ../rfc/9051:6401
			nilOrString(p.ContentID),
			nilOrString(p.ContentDescription),
			bodyFldEnc(p.ContentTransferEncoding),
			number(p.EndOffset - p.BodyOffset),
			xenvelope(p.Message),
			xbodystructure(log, p.Message, extensible),
			number(p.RawLineCount), // todo: or mp.RawLineCount?
		}
	} else {
		var media token
		switch p.MediaType {
		case "APPLICATION", "AUDIO", "IMAGE", "FONT", "MESSAGE", "MODEL", "VIDEO":
			media = dquote(p.MediaType)
		default:
			media = string0(p.MediaType)
		}
		// ../rfc/9051:6404 ../rfc/9051:6407
		r = listspace{
			media, string0(p.MediaSubType), // ../rfc/9051:6723
			// ../rfc/9051:6376
			bodyFldParams(p), // ../rfc/9051:6401
			nilOrString(p.ContentID),
			nilOrString(p.ContentDescription),
			bodyFldEnc(p.ContentTransferEncoding),
			number(p.EndOffset - p.BodyOffset),
		}
	}
	if extensible {
		// ../rfc/9051:6366
		r = append(r,
			bodyFldMd5(p),
			bodyFldDisp(log, p),
			bodyFldLang(p),
			bodyFldLoc(p),
		)
	}
	return r
}
