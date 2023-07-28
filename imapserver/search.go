package imapserver

import (
	"fmt"
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

	// We gather word and not-word searches from the top-level, turn them
	// into a WordSearch for a more efficient search.
	// todo optimize: also gather them out of AND searches.
	var textWords, textNotWords, bodyWords, bodyNotWords []string
	n := 0
	for _, xsk := range sk.searchKeys {
		switch xsk.op {
		case "BODY":
			bodyWords = append(bodyWords, xsk.astring)
			continue
		case "TEXT":
			textWords = append(textWords, xsk.astring)
			continue
		case "NOT":
			switch xsk.searchKey.op {
			case "BODY":
				bodyNotWords = append(bodyNotWords, xsk.searchKey.astring)
				continue
			case "TEXT":
				textNotWords = append(textNotWords, xsk.searchKey.astring)
				continue
			}
		}
		sk.searchKeys[n] = xsk
		n++
	}
	// We may be left with an empty but non-nil sk.searchKeys, which is important for
	// matching.
	sk.searchKeys = sk.searchKeys[:n]
	var bodySearch, textSearch *store.WordSearch
	if len(bodyWords) > 0 || len(bodyNotWords) > 0 {
		ws := store.PrepareWordSearch(bodyWords, bodyNotWords)
		bodySearch = &ws
	}
	if len(textWords) > 0 || len(textNotWords) > 0 {
		ws := store.PrepareWordSearch(textWords, textNotWords)
		textSearch = &ws
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
				if match, modseq := c.searchMatch(tx, msgseq(i+1), uid, *sk, bodySearch, textSearch, &expungeIssued); match {
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
				if match, modseq := c.searchMatch(tx, msgseq(i+1), c.uids[i], *sk, bodySearch, textSearch, &expungeIssued); match {
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

func (c *conn) searchMatch(tx *bstore.Tx, seq msgseq, uid store.UID, sk searchKey, bodySearch, textSearch *store.WordSearch, expungeIssued *bool) (bool, store.ModSeq) {
	s := search{c: c, tx: tx, seq: seq, uid: uid, expungeIssued: expungeIssued, hasModseq: sk.hasModseq()}
	defer func() {
		if s.mr != nil {
			err := s.mr.Close()
			c.xsanity(err, "closing messagereader")
			s.mr = nil
		}
	}()
	return s.match(sk, bodySearch, textSearch)
}

func (s *search) match(sk searchKey, bodySearch, textSearch *store.WordSearch) (match bool, modseq store.ModSeq) {
	// Instead of littering all the cases in match0 with calls to get modseq, we do it once
	// here in case of a match.
	defer func() {
		if match && s.hasModseq {
			if s.m.ID == 0 {
				match = s.xensureMessage()
			}
			modseq = s.m.ModSeq
		}
	}()

	match = s.match0(sk)
	if match && bodySearch != nil {
		if !s.xensurePart() {
			match = false
			return
		}
		var err error
		match, err = bodySearch.MatchPart(s.c.log, s.p, false)
		xcheckf(err, "search words in bodies")
	}
	if match && textSearch != nil {
		if !s.xensurePart() {
			match = false
			return
		}
		var err error
		match, err = textSearch.MatchPart(s.c.log, s.p, true)
		xcheckf(err, "search words in headers and bodies")
	}
	return
}

func (s *search) xensureMessage() bool {
	if s.m.ID > 0 {
		return true
	}

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

// ensure message, reader and part are loaded. returns whether that was
// successful.
func (s *search) xensurePart() bool {
	if s.mr != nil {
		return s.p != nil
	}

	if !s.xensureMessage() {
		return false
	}

	// Closed by searchMatch after all (recursive) search.match calls are finished.
	s.mr = s.c.account.MessageReader(s.m)

	if s.m.ParsedBuf == nil {
		s.c.log.Error("missing parsed message")
		return false
	}
	p, err := s.m.LoadPart(s.mr)
	xcheckf(err, "load parsed message")
	s.p = &p
	return true
}

func (s *search) match0(sk searchKey) bool {
	c := s.c

	// Difference between sk.searchKeys nil and length 0 is important. Because we take
	// out word/notword searches, the list may be empty but non-nil.
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

	// Parsed part.
	if !s.xensurePart() {
		return false
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
		// We gathered word/notword searches from the top-level, but we can also get them
		// nested.
		// todo optimize: handle deeper nested word/not-word searches more efficiently.
		headerToo := sk.op == "TEXT"
		match, err := store.PrepareWordSearch([]string{sk.astring}, nil).MatchPart(s.c.log, s.p, headerToo)
		xcheckf(err, "word search")
		return match
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
