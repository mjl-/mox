package imapserver

import (
	"fmt"
	"io"
	"net/textproto"
	"strings"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/store"
)

// Search returns messages matching criteria specified in parameters.
//
// State: Selected
func (c *conn) cmdxSearch(isUID bool, tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3716 ../rfc/4731:31 ../rfc/4466:354 ../rfc/3501:2723
	// Examples: ../rfc/9051:3986 ../rfc/4731:153 ../rfc/3501:2975
	// Syntax: ../rfc/9051:6918 ../rfc/4466:611 ../rfc/3501:4954

	// We will respond with ESEARCH instead of SEARCH if "RETURN" is present or for IMAP4rev2.
	var eargs map[string]bool // Options except SAVE. Nil means old-style SEARCH response.
	var save bool             // For SAVE option. Kept separately for easier handling of MIN/MAX later.

	// IMAP4rev2 always returns ESEARCH, even with absent RETURN.
	if c.enabled[capIMAP4rev2] {
		eargs = map[string]bool{}
	}
	// ../rfc/9051:6967
	if p.take(" RETURN (") {
		eargs = map[string]bool{}

		for !p.take(")") {
			if len(eargs) > 0 || save {
				p.xspace()
			}
			if w, ok := p.takelist("MIN", "MAX", "ALL", "COUNT", "SAVE"); ok {
				if w == "SAVE" {
					save = true
				} else {
					eargs[w] = true
				}
			} else {
				// ../rfc/4466:378 ../rfc/9051:3745
				xsyntaxErrorf("ESEARCH result option %q not supported", w)
			}
		}
	}
	// ../rfc/4731:149 ../rfc/9051:3737
	if eargs != nil && len(eargs) == 0 && !save {
		eargs["ALL"] = true
	}

	// If UTF8=ACCEPT is enabled, we should not accept any charset. We are a bit more
	// relaxed (reasonable?) and still allow US-ASCII and UTF-8. ../rfc/6855:198
	if p.take(" CHARSET ") {
		charset := strings.ToUpper(p.xastring())
		if charset != "US-ASCII" && charset != "UTF-8" {
			// ../rfc/3501:2771 ../rfc/9051:3836
			xusercodeErrorf("BADCHARSET", "only US-ASCII and UTF-8 supported")
		}
	}
	p.xspace()
	sk := &searchKey{
		searchKeys: []searchKey{*p.xsearchKey()},
	}
	for !p.empty() {
		p.xspace()
		sk.searchKeys = append(sk.searchKeys, *p.xsearchKey())
	}

	// Even in case of error, we ensure search result is changed.
	if save {
		c.searchResult = []store.UID{}
	}

	// Note: we only hold the account rlock for verifying the mailbox at the start.
	c.account.RLock()
	runlock := c.account.RUnlock
	// Note: in a defer because we replace it below.
	defer func() {
		runlock()
	}()

	// If we only have a MIN and/or MAX, we can stop processing as soon as we
	// have those matches.
	var min, max int
	if eargs["MIN"] {
		min = 1
	}
	if eargs["MAX"] {
		max = 1
	}

	var expungeIssued bool
	var maxModSeq store.ModSeq

	var uids []store.UID
	c.xdbread(func(tx *bstore.Tx) {
		c.xmailboxID(tx, c.mailboxID) // Validate.
		runlock()
		runlock = func() {}

		// Normal forward search when we don't have MAX only.
		var lastIndex = -1
		if eargs == nil || max == 0 || len(eargs) != 1 {
			for i, uid := range c.uids {
				lastIndex = i
				if match, modseq := c.searchMatch(tx, msgseq(i+1), uid, *sk, &expungeIssued); match {
					uids = append(uids, uid)
					if modseq > maxModSeq {
						maxModSeq = modseq
					}
					if min == 1 && min+max == len(eargs) {
						break
					}
				}
			}
		}
		// And reverse search for MAX if we have only MAX or MAX combined with MIN.
		if max == 1 && (len(eargs) == 1 || min+max == len(eargs)) {
			for i := len(c.uids) - 1; i > lastIndex; i-- {
				if match, modseq := c.searchMatch(tx, msgseq(i+1), c.uids[i], *sk, &expungeIssued); match {
					uids = append(uids, c.uids[i])
					if modseq > maxModSeq {
						maxModSeq = modseq
					}
					break
				}
			}
		}
	})

	if eargs == nil {
		// In IMAP4rev1, an untagged SEARCH response is required. ../rfc/3501:2728
		if len(uids) == 0 {
			c.bwritelinef("* SEARCH")
		}

		// Old-style SEARCH response. We must spell out each number. So we may be splitting
		// into multiple responses. ../rfc/9051:6809 ../rfc/3501:4833
		for len(uids) > 0 {
			n := len(uids)
			if n > 100 {
				n = 100
			}
			s := ""
			for _, v := range uids[:n] {
				if !isUID {
					v = store.UID(c.xsequence(v))
				}
				s += " " + fmt.Sprintf("%d", v)
			}

			// Since we don't have the max modseq for the possibly partial uid range we're
			// writing here within hand reach, we conveniently interpret the ambiguous "for all
			// messages being returned" in ../rfc/7162:1107 as meaning over all lines that we
			// write. And that clients only commit this value after they have seen the tagged
			// end of the command. Appears to be recommended behaviour, ../rfc/7162:2323.
			// ../rfc/7162:1077 ../rfc/7162:1101
			var modseq string
			if sk.hasModseq() {
				// ../rfc/7162:2557
				modseq = fmt.Sprintf(" (MODSEQ %d)", maxModSeq.Client())
			}

			c.bwritelinef("* SEARCH%s%s", s, modseq)
			uids = uids[n:]
		}
	} else {
		// New-style ESEARCH response syntax: ../rfc/9051:6546 ../rfc/4466:522

		if save {
			// ../rfc/9051:3784 ../rfc/5182:13
			c.searchResult = uids
			if sanityChecks {
				checkUIDs(c.searchResult)
			}
		}

		// No untagged ESEARCH response if nothing was requested. ../rfc/9051:4160
		if len(eargs) > 0 {
			resp := fmt.Sprintf("* ESEARCH (TAG %s)", tag)
			if isUID {
				resp += " UID"
			}

			// NOTE: we are converting UIDs to msgseq in the uids slice (if needed) while
			// keeping the "uids" name!
			if !isUID {
				// If searchResult is hanging on to the slice, we need to work on a copy.
				if save {
					nuids := make([]store.UID, len(uids))
					copy(nuids, uids)
					uids = nuids
				}
				for i, uid := range uids {
					uids[i] = store.UID(c.xsequence(uid))
				}
			}

			// If no matches, then no MIN/MAX response. ../rfc/4731:98 ../rfc/9051:3758
			if eargs["MIN"] && len(uids) > 0 {
				resp += fmt.Sprintf(" MIN %d", uids[0])
			}
			if eargs["MAX"] && len(uids) > 0 {
				resp += fmt.Sprintf(" MAX %d", uids[len(uids)-1])
			}
			if eargs["COUNT"] {
				resp += fmt.Sprintf(" COUNT %d", len(uids))
			}
			if eargs["ALL"] && len(uids) > 0 {
				resp += fmt.Sprintf(" ALL %s", compactUIDSet(uids).String())
			}

			// Interaction between ESEARCH and CONDSTORE: ../rfc/7162:1211 ../rfc/4731:273
			// Summary: send the highest modseq of the returned messages.
			if sk.hasModseq() && len(uids) > 0 {
				resp += fmt.Sprintf(" MODSEQ %d", maxModSeq.Client())
			}

			c.bwritelinef("%s", resp)
		}
	}
	if expungeIssued {
		// ../rfc/9051:5102
		c.writeresultf("%s OK [EXPUNGEISSUED] done", tag)
	} else {
		c.ok(tag, cmd)
	}
}

type search struct {
	c             *conn
	tx            *bstore.Tx
	seq           msgseq
	uid           store.UID
	mr            *store.MsgReader
	m             store.Message
	p             *message.Part
	expungeIssued *bool
	hasModseq     bool
}

func (c *conn) searchMatch(tx *bstore.Tx, seq msgseq, uid store.UID, sk searchKey, expungeIssued *bool) (bool, store.ModSeq) {
	s := search{c: c, tx: tx, seq: seq, uid: uid, expungeIssued: expungeIssued, hasModseq: sk.hasModseq()}
	defer func() {
		if s.mr != nil {
			err := s.mr.Close()
			c.xsanity(err, "closing messagereader")
			s.mr = nil
		}
	}()
	return s.match(sk)
}

func (s *search) match(sk searchKey) (match bool, modseq store.ModSeq) {
	// Instead of littering all the cases in match0 with calls to get modseq, we do it once
	// here in case of a match.
	defer func() {
		if match && s.hasModseq {
			if s.m.ID == 0 {
				match = s.xloadMessage()
			}
			modseq = s.m.ModSeq
		}
	}()

	match = s.match0(sk)
	return
}

func (s *search) xloadMessage() bool {
	q := bstore.QueryTx[store.Message](s.tx)
	q.FilterNonzero(store.Message{MailboxID: s.c.mailboxID, UID: s.uid})
	m, err := q.Get()
	if err == bstore.ErrAbsent || err == nil && m.Expunged {
		// ../rfc/2180:607
		*s.expungeIssued = true
		return false
	}
	xcheckf(err, "get message")
	s.m = m
	return true
}

func (s *search) match0(sk searchKey) bool {
	c := s.c

	if sk.searchKeys != nil {
		for _, ssk := range sk.searchKeys {
			if !s.match0(ssk) {
				return false
			}
		}
		return true
	} else if sk.seqSet != nil {
		return sk.seqSet.containsSeq(s.seq, c.uids, c.searchResult)
	}

	filterHeader := func(field, value string) bool {
		lower := strings.ToLower(value)
		h, err := s.p.Header()
		if err != nil {
			c.log.Debugx("parsing message header", err, mlog.Field("uid", s.uid))
			return false
		}
		for _, v := range h.Values(field) {
			if strings.Contains(strings.ToLower(v), lower) {
				return true
			}
		}
		return false
	}

	// We handle ops by groups that need increasing details about the message.

	switch sk.op {
	case "ALL":
		return true
	case "NEW":
		// We do not implement the RECENT flag, so messages cannot be NEW.
		return false
	case "OLD":
		// We treat all messages as non-recent, so this means all messages.
		return true
	case "RECENT":
		// We do not implement the RECENT flag. All messages are not recent.
		return false
	case "NOT":
		return !s.match0(*sk.searchKey)
	case "OR":
		return s.match0(*sk.searchKey) || s.match0(*sk.searchKey2)
	case "UID":
		return sk.uidSet.containsUID(s.uid, c.uids, c.searchResult)
	}

	// Parsed message.
	if s.mr == nil {
		if !s.xloadMessage() {
			return false
		}

		// Closed by searchMatch after all (recursive) search.match calls are finished.
		s.mr = c.account.MessageReader(s.m)

		if s.m.ParsedBuf == nil {
			c.log.Error("missing parsed message")
		} else {
			p, err := s.m.LoadPart(s.mr)
			xcheckf(err, "load parsed message")
			s.p = &p
		}
	}

	// Parsed message, basic info.
	switch sk.op {
	case "ANSWERED":
		return s.m.Answered
	case "DELETED":
		return s.m.Deleted
	case "FLAGGED":
		return s.m.Flagged
	case "KEYWORD":
		kw := strings.ToLower(sk.atom)
		switch kw {
		case "$forwarded":
			return s.m.Forwarded
		case "$junk":
			return s.m.Junk
		case "$notjunk":
			return s.m.Notjunk
		case "$phishing":
			return s.m.Phishing
		case "$mdnsent":
			return s.m.MDNSent
		default:
			for _, k := range s.m.Keywords {
				if k == kw {
					return true
				}
			}
			return false
		}
	case "SEEN":
		return s.m.Seen
	case "UNANSWERED":
		return !s.m.Answered
	case "UNDELETED":
		return !s.m.Deleted
	case "UNFLAGGED":
		return !s.m.Flagged
	case "UNKEYWORD":
		kw := strings.ToLower(sk.atom)
		switch kw {
		case "$forwarded":
			return !s.m.Forwarded
		case "$junk":
			return !s.m.Junk
		case "$notjunk":
			return !s.m.Notjunk
		case "$phishing":
			return !s.m.Phishing
		case "$mdnsent":
			return !s.m.MDNSent
		default:
			for _, k := range s.m.Keywords {
				if k == kw {
					return false
				}
			}
			return true
		}
	case "UNSEEN":
		return !s.m.Seen
	case "DRAFT":
		return s.m.Draft
	case "UNDRAFT":
		return !s.m.Draft
	case "BEFORE", "ON", "SINCE":
		skdt := sk.date.Format("2006-01-02")
		rdt := s.m.Received.Format("2006-01-02")
		switch sk.op {
		case "BEFORE":
			return rdt < skdt
		case "ON":
			return rdt == skdt
		case "SINCE":
			return rdt >= skdt
		}
		panic("missing case")
	case "LARGER":
		return s.m.Size > sk.number
	case "SMALLER":
		return s.m.Size < sk.number
	case "MODSEQ":
		// ../rfc/7162:1045
		return s.m.ModSeq.Client() >= *sk.clientModseq
	}

	if s.p == nil {
		c.log.Info("missing parsed message, not matching", mlog.Field("uid", s.uid))
		return false
	}

	// Parsed message, more info.
	switch sk.op {
	case "BCC":
		return filterHeader("Bcc", sk.astring)
	case "BODY", "TEXT":
		headerToo := sk.op == "TEXT"
		lower := strings.ToLower(sk.astring)
		return mailContains(c, s.uid, s.p, lower, headerToo)
	case "CC":
		return filterHeader("Cc", sk.astring)
	case "FROM":
		return filterHeader("From", sk.astring)
	case "SUBJECT":
		return filterHeader("Subject", sk.astring)
	case "TO":
		return filterHeader("To", sk.astring)
	case "HEADER":
		// ../rfc/9051:3895
		lower := strings.ToLower(sk.astring)
		h, err := s.p.Header()
		if err != nil {
			c.log.Errorx("parsing header for search", err, mlog.Field("uid", s.uid))
			return false
		}
		k := textproto.CanonicalMIMEHeaderKey(sk.headerField)
		for _, v := range h.Values(k) {
			if lower == "" || strings.Contains(strings.ToLower(v), lower) {
				return true
			}
		}
		return false
	case "SENTBEFORE", "SENTON", "SENTSINCE":
		if s.p.Envelope == nil || s.p.Envelope.Date.IsZero() {
			return false
		}
		dt := s.p.Envelope.Date.Format("2006-01-02")
		skdt := sk.date.Format("2006-01-02")
		switch sk.op {
		case "SENTBEFORE":
			return dt < skdt
		case "SENTON":
			return dt == skdt
		case "SENTSINCE":
			return dt > skdt
		}
		panic("missing case")
	}
	panic(serverError{fmt.Errorf("missing case for search key op %q", sk.op)})
}

// mailContains returns whether the mail message or part represented by p contains (case-insensitive) string lower.
// The (decoded) text bodies are tested for a match.
// If headerToo is set, the header part of the message is checked as well.
func mailContains(c *conn, uid store.UID, p *message.Part, lower string, headerToo bool) bool {
	if headerToo && mailContainsReader(c, uid, p.HeaderReader(), lower) {
		return true
	}

	if len(p.Parts) == 0 {
		if p.MediaType != "TEXT" {
			// todo: for types we could try to find a library for parsing and search in there too
			return false
		}
		// todo: for html and perhaps other types, we could try to parse as text and filter on the text.
		return mailContainsReader(c, uid, p.Reader(), lower)
	}
	for _, pp := range p.Parts {
		headerToo = pp.MediaType == "MESSAGE" && (pp.MediaSubType == "RFC822" || pp.MediaSubType == "GLOBAL")
		if mailContains(c, uid, &pp, lower, headerToo) {
			return true
		}
	}
	return false
}

func mailContainsReader(c *conn, uid store.UID, r io.Reader, lower string) bool {
	// todo: match as we read
	buf, err := io.ReadAll(r)
	if err != nil {
		c.log.Errorx("reading for search text match", err, mlog.Field("uid", uid))
		return false
	}
	return strings.Contains(strings.ToLower(string(buf)), lower)
}
