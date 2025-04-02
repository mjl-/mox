package imapserver

import (
	"cmp"
	"fmt"
	"log/slog"
	"maps"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/store"
)

// If last search output was this long ago, we write an untagged inprogress
// response. Changed during tests. ../rfc/9585:109
var inProgressPeriod = time.Duration(10 * time.Second)

// ESEARCH allows searching multiple mailboxes, referenced through mailbox filters
// borrowed from the NOTIFY extension. Unlike the regular extended SEARCH/UID
// SEARCH command that always returns an ESEARCH response, the ESEARCH command only
// returns ESEARCH responses when there were matches in a mailbox.
//
// ../rfc/7377:159
func (c *conn) cmdEsearch(tag, cmd string, p *parser) {
	c.cmdxSearch(true, true, tag, cmd, p)
}

// Search returns messages matching criteria specified in parameters.
//
// State: Selected for SEARCH and UID SEARCH, Authenticated or selectd for ESEARCH.
func (c *conn) cmdxSearch(isUID, isE bool, tag, cmd string, p *parser) {
	// Command: ../rfc/9051:3716 ../rfc/7377:159 ../rfc/6237:142 ../rfc/4731:31 ../rfc/4466:354 ../rfc/3501:2723
	// Examples: ../rfc/9051:3986 ../rfc/7377:385 ../rfc/6237:323 ../rfc/4731:153 ../rfc/3501:2975
	// Syntax: ../rfc/9051:6918 ../rfc/7377:462 ../rfc/6237:403 ../rfc/4466:611 ../rfc/3501:4954

	// We will respond with ESEARCH instead of SEARCH if "RETURN" is present or for IMAP4rev2 or for isE (ESEARCH command).
	var eargs map[string]bool // Options except SAVE. Nil means old-style SEARCH response.
	var save bool             // For SAVE option. Kept separately for easier handling of MIN/MAX later.

	if c.enabled[capIMAP4rev2] || isE {
		eargs = map[string]bool{}
	}

	// The ESEARCH command has various ways to specify which mailboxes are to be
	// searched. We parse and gather the request first, and evaluate them to mailboxes
	// after parsing, when we start and have a DB transaction.
	type mailboxSpec struct {
		Kind string
		Args []string
	}
	var mailboxSpecs []mailboxSpec

	// ../rfc/7377:468
	if isE && p.take(" IN (") {
		for {
			mbs := mailboxSpec{}
			mbs.Kind = p.xtakelist("SELECTED", "INBOXES", "PERSONAL", "SUBSCRIBED", "SUBTREE-ONE", "SUBTREE", "MAILBOXES")
			switch mbs.Kind {
			case "SUBTREE", "SUBTREE-ONE", "MAILBOXES":
				p.xtake(" ")
				if p.take("(") {
					for {
						mbs.Args = append(mbs.Args, p.xmailbox())
						if !p.take(" ") {
							break
						}
					}
					p.xtake(")")
				} else {
					mbs.Args = []string{p.xmailbox()}
				}
			}
			mailboxSpecs = append(mailboxSpecs, mbs)

			if !p.take(" ") {
				break
			}
		}
		p.xtake(")")
		// We are not parsing the scope-options since there aren't any defined yet. ../rfc/7377:469
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
	var min1, max1 int
	if eargs["MIN"] {
		min1 = 1
	}
	if eargs["MAX"] {
		max1 = 1
	}

	// We'll have one Result per mailbox we are searching. For regular (UID) SEARCH
	// commands, we'll have just one, for the selected mailbox.
	type Result struct {
		Mailbox   store.Mailbox
		MaxModSeq store.ModSeq
		UIDs      []store.UID
	}
	var results []Result

	// We periodically send an untagged OK with INPROGRESS code while searching, to let
	// clients doing slow searches know we're still working.
	inProgressLast := time.Now()
	// Only respond with tag if it can't be confused as end of response code. ../rfc/9585:122
	inProgressTag := "nil"
	if !strings.Contains(tag, "]") {
		inProgressTag = dquote(tag).pack(c)
	}

	c.xdbread(func(tx *bstore.Tx) {
		// Gather mailboxes to operate on. Usually just the selected mailbox. But with the
		// ESEARCH command, we may be searching multiple.
		var mailboxes []store.Mailbox
		if len(mailboxSpecs) > 0 {
			// While gathering, we deduplicate mailboxes. ../rfc/7377:312
			m := map[int64]store.Mailbox{}
			for _, mbs := range mailboxSpecs {
				switch mbs.Kind {
				case "SELECTED":
					// ../rfc/7377:306
					if c.state != stateSelected {
						xsyntaxErrorf("cannot use ESEARCH with selected when state is not selected")
					}

					mb := c.xmailboxID(tx, c.mailboxID) // Validate.
					m[mb.ID] = mb

				case "INBOXES":
					// Inbox and everything below. And we look at destinations and rulesets. We all
					// mailboxes from the destinations, and all from the rulesets except when
					// ListAllowDomain is non-empty.
					// ../rfc/5465:822
					q := bstore.QueryTx[store.Mailbox](tx)
					q.FilterEqual("Expunged", false)
					q.FilterGreaterEqual("Name", "Inbox")
					q.SortAsc("Name")
					for mb, err := range q.All() {
						xcheckf(err, "list mailboxes")
						if mb.Name != "Inbox" && !strings.HasPrefix(mb.Name, "Inbox/") {
							break
						}
						m[mb.ID] = mb
					}

					conf, _ := c.account.Conf()
					for _, dest := range conf.Destinations {
						if dest.Mailbox != "" && dest.Mailbox != "Inbox" {
							mb, err := c.account.MailboxFind(tx, dest.Mailbox)
							xcheckf(err, "find mailbox from destination")
							if mb != nil {
								m[mb.ID] = *mb
							}
						}

						for _, rs := range dest.Rulesets {
							if rs.ListAllowDomain != "" || rs.Mailbox == "" {
								continue
							}

							mb, err := c.account.MailboxFind(tx, rs.Mailbox)
							xcheckf(err, "find mailbox from ruleset")
							if mb != nil {
								m[mb.ID] = *mb
							}
						}
					}

				case "PERSONAL":
					// All mailboxes in the personal namespace. Which is all mailboxes for us.
					// ../rfc/5465:817
					for mb, err := range bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).All() {
						xcheckf(err, "list mailboxes")
						m[mb.ID] = mb
					}

				case "SUBSCRIBED":
					// Mailboxes that are subscribed. Will typically be same as personal, since we
					// subscribe to all mailboxes. But user can manage subscriptions differently.
					// ../rfc/5465:831
					for mb, err := range bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).All() {
						xcheckf(err, "list mailboxes")
						if err := tx.Get(&store.Subscription{Name: mb.Name}); err == nil {
							m[mb.ID] = mb
						} else if err != bstore.ErrAbsent {
							xcheckf(err, "lookup subscription for mailbox")
						}
					}

				case "SUBTREE", "SUBTREE-ONE":
					// The mailbox name itself, and children. ../rfc/5465:847
					// SUBTREE is arbitrarily deep, SUBTREE-ONE is one level deeper than requested
					// mailbox. The mailbox itself is included too ../rfc/7377:274

					// We don't have to worry about loops. Mailboxes are not in the file system.
					// ../rfc/7377:291

					for _, name := range mbs.Args {
						name = xcheckmailboxname(name, true)

						one := mbs.Kind == "SUBTREE-ONE"
						var ntoken int
						if one {
							ntoken = len(strings.Split(name, "/"))
						}

						q := bstore.QueryTx[store.Mailbox](tx)
						q.FilterEqual("Expunged", false)
						q.FilterGreaterEqual("Name", name)
						q.SortAsc("Name")
						for mb, err := range q.All() {
							xcheckf(err, "list mailboxes")
							if mb.Name != name && !strings.HasPrefix(mb.Name, name+"/") {
								break
							}
							if !one || mb.Name == name || len(strings.Split(mb.Name, "/")) == ntoken+1 {
								m[mb.ID] = mb
							}
						}
					}

				case "MAILBOXES":
					// Just the specified mailboxes. ../rfc/5465:853
					for _, name := range mbs.Args {
						name = xcheckmailboxname(name, true)

						// If a mailbox doesn't exist, we don't treat it as an error. Seems reasonable
						// giving we are searching. Messages may not exist. And likewise for the mailbox.
						// Just results in no hits.
						mb, err := c.account.MailboxFind(tx, name)
						xcheckf(err, "looking up mailbox")
						if mb != nil {
							m[mb.ID] = *mb
						}
					}

				default:
					panic("missing case")
				}
			}
			mailboxes = slices.Collect(maps.Values(m))
			slices.SortFunc(mailboxes, func(a, b store.Mailbox) int {
				return cmp.Compare(a.Name, b.Name)
			})

			// If no source mailboxes were specified (no mailboxSpecs), the selected mailbox is
			// used below. ../rfc/7377:298
		} else {
			mb := c.xmailboxID(tx, c.mailboxID) // Validate.
			mailboxes = []store.Mailbox{mb}
		}

		if save && !(len(mailboxes) == 1 && mailboxes[0].ID == c.mailboxID) {
			// ../rfc/7377:319
			xsyntaxErrorf("can only use SAVE on selected mailbox")
		}

		runlock()
		runlock = func() {}

		// Determine if search has a sequence set without search results. If so, we need
		// sequence numbers for matching, and we must always go through the messages in
		// forward order. No reverse search for MAX only.
		needSeq := (len(mailboxes) > 1 || len(mailboxes) == 1 && mailboxes[0].ID != c.mailboxID) && sk.needSeq()

		forward := eargs == nil || max1 == 0 || len(eargs) != 1 || needSeq
		reverse := max1 == 1 && (len(eargs) == 1 || min1+max1 == len(eargs)) && !needSeq

		// We set a worst-case "goal" of having gone through all messages in all mailboxes.
		// Sometimes, we can be faster, when we only do a MIN and/or MAX query and we can
		// stop early. We'll account for that as we go. For the selected mailbox, we'll
		// only look at those the session has already seen.
		goal := "nil"
		var total uint32
		for _, mb := range mailboxes {
			if mb.ID == c.mailboxID {
				total += uint32(len(c.uids))
			} else {
				total += uint32(mb.Total + mb.Deleted)
			}
		}
		if total > 0 {
			// Goal is always non-zero. ../rfc/9585:232
			goal = fmt.Sprintf("%d", total)
		}

		var progress uint32
		for _, mb := range mailboxes {
			var lastUID store.UID

			result := Result{Mailbox: mb}

			msgCount := uint32(mb.MailboxCounts.Total + mb.MailboxCounts.Deleted)
			if mb.ID == c.mailboxID {
				msgCount = uint32(len(c.uids))
			}

			// Used for interpreting UID sets with a star, like "1:*" and "10:*". Only called
			// for UIDs that are higher than the number, since "10:*" evaluates to "10:5" if 5
			// is the highest UID, and UID 5-10 would all match.
			var cachedHighestUID store.UID
			highestUID := func() (store.UID, error) {
				if cachedHighestUID > 0 {
					return cachedHighestUID, nil
				}

				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				q.FilterEqual("Expunged", false)
				q.SortDesc("UID")
				q.Limit(1)
				m, err := q.Get()
				cachedHighestUID = m.UID
				return cachedHighestUID, err
			}

			progressOrig := progress

			if forward {
				// We track this for non-selected mailboxes. searchMatch will look the message
				// sequence number for this session up if we are searching the selected mailbox.
				var seq msgseq = 1

				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				q.FilterEqual("Expunged", false)
				q.SortAsc("UID")
				for m, err := range q.All() {
					xcheckf(err, "list messages in mailbox")

					// We track this for the "reverse" case, we'll stop before seeing lastUID.
					lastUID = m.UID

					if time.Since(inProgressLast) > inProgressPeriod {
						c.xwritelinef("* OK [INPROGRESS (%s %d %s)] still searching", inProgressTag, progress, goal)
						inProgressLast = time.Now()
					}
					progress++

					if c.searchMatch(tx, msgCount, seq, m, *sk, bodySearch, textSearch, highestUID) {
						result.UIDs = append(result.UIDs, m.UID)
						result.MaxModSeq = max(result.MaxModSeq, m.ModSeq)
						if min1 == 1 && min1+max1 == len(eargs) {
							if !needSeq {
								break
							}
							// We only need a MIN and a MAX, but we also need sequence numbers so we are
							// walking through and collecting all UIDs. Correct for that, keeping only the MIN
							// (first)
							// and MAX (second).
							if len(result.UIDs) == 3 {
								result.UIDs[1] = result.UIDs[2]
								result.UIDs = result.UIDs[:2]
							}
						}
					}
					seq++
				}
			}
			// And reverse search for MAX if we have only MAX or MAX combined with MIN, and
			// don't need sequence numbers. We just need a single match, then we stop.
			if reverse {
				q := bstore.QueryTx[store.Message](tx)
				q.FilterNonzero(store.Message{MailboxID: mb.ID})
				q.FilterEqual("Expunged", false)
				q.FilterGreater("UID", lastUID)
				q.SortDesc("UID")
				for m, err := range q.All() {
					xcheckf(err, "list messages in mailbox")

					if time.Since(inProgressLast) > inProgressPeriod {
						c.xwritelinef("* OK [INPROGRESS (%s %d %s)] still searching", inProgressTag, progress, goal)
						inProgressLast = time.Now()
					}
					progress++

					var seq msgseq // Filled in by searchMatch for messages in selected mailbox.
					if c.searchMatch(tx, msgCount, seq, m, *sk, bodySearch, textSearch, highestUID) {
						result.UIDs = append(result.UIDs, m.UID)
						result.MaxModSeq = max(result.MaxModSeq, m.ModSeq)
						break
					}
				}
			}

			// We could have finished searching the mailbox with fewer
			mailboxProcessed := progress - progressOrig
			mailboxTotal := uint32(mb.MailboxCounts.Total + mb.MailboxCounts.Deleted)
			progress += max(0, mailboxTotal-mailboxProcessed)

			results = append(results, result)
		}
	})

	if eargs == nil {
		// We'll only have a result for the one selected mailbox.
		result := results[0]

		// In IMAP4rev1, an untagged SEARCH response is required. ../rfc/3501:2728
		if len(result.UIDs) == 0 {
			c.xbwritelinef("* SEARCH")
		}

		// Old-style SEARCH response. We must spell out each number. So we may be splitting
		// into multiple responses. ../rfc/9051:6809 ../rfc/3501:4833
		for len(result.UIDs) > 0 {
			n := len(result.UIDs)
			if n > 100 {
				n = 100
			}
			s := ""
			for _, v := range result.UIDs[:n] {
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
				modseq = fmt.Sprintf(" (MODSEQ %d)", result.MaxModSeq.Client())
			}

			c.xbwritelinef("* SEARCH%s%s", s, modseq)
			result.UIDs = result.UIDs[n:]
		}
	} else {
		// New-style ESEARCH response syntax: ../rfc/9051:6546 ../rfc/4466:522

		if save {
			// ../rfc/9051:3784 ../rfc/5182:13
			c.searchResult = results[0].UIDs
			if sanityChecks {
				checkUIDs(c.searchResult)
			}
		}

		// No untagged ESEARCH response if nothing was requested. ../rfc/9051:4160
		if len(eargs) > 0 {
			for _, result := range results {
				// For the ESEARCH command, we must not return a response if there were no matching
				// messages. This is unlike the later IMAP4rev2, where an ESEARCH response must be
				// sent if there were no matches. ../rfc/7377:243 ../rfc/9051:3775
				if isE && len(result.UIDs) == 0 {
					continue
				}

				// The tag was originally a string, became an astring in IMAP4rev2, better stick to
				// string. ../rfc/4466:707 ../rfc/5259:1163 ../rfc/9051:7087
				if isE {
					fmt.Fprintf(c.xbw, `* ESEARCH (TAG "%s" MAILBOX %s UIDVALIDITY %d)`, tag, result.Mailbox.Name, result.Mailbox.UIDValidity)
				} else {
					fmt.Fprintf(c.xbw, `* ESEARCH (TAG "%s")`, tag)
				}
				if isUID {
					fmt.Fprintf(c.xbw, " UID")
				}

				// NOTE: we are potentially converting UIDs to msgseq, but keep the store.UID type
				// for convenience.
				nums := result.UIDs
				if !isUID {
					// If searchResult is hanging on to the slice, we need to work on a copy.
					if save {
						nums = slices.Clone(nums)
					}
					for i, uid := range nums {
						nums[i] = store.UID(c.xsequence(uid))
					}
				}

				// If no matches, then no MIN/MAX response. ../rfc/4731:98 ../rfc/9051:3758
				if eargs["MIN"] && len(nums) > 0 {
					fmt.Fprintf(c.xbw, " MIN %d", nums[0])
				}
				if eargs["MAX"] && len(result.UIDs) > 0 {
					fmt.Fprintf(c.xbw, " MAX %d", nums[len(nums)-1])
				}
				if eargs["COUNT"] {
					fmt.Fprintf(c.xbw, " COUNT %d", len(nums))
				}
				if eargs["ALL"] && len(nums) > 0 {
					fmt.Fprintf(c.xbw, " ALL %s", compactUIDSet(nums).String())
				}

				// Interaction between ESEARCH and CONDSTORE: ../rfc/7162:1211 ../rfc/4731:273
				// Summary: send the highest modseq of the returned messages.
				if sk.hasModseq() && len(nums) > 0 {
					fmt.Fprintf(c.xbw, " MODSEQ %d", result.MaxModSeq.Client())
				}

				c.xbwritelinef("")
			}
		}
	}

	c.ok(tag, cmd)
}

type search struct {
	c          *conn
	tx         *bstore.Tx
	msgCount   uint32 // Number of messages in mailbox (or session when selected).
	seq        msgseq // Can be 0, for other mailboxes than selected in case of MAX.
	m          store.Message
	mr         *store.MsgReader
	p          *message.Part
	highestUID func() (store.UID, error)
}

func (c *conn) searchMatch(tx *bstore.Tx, msgCount uint32, seq msgseq, m store.Message, sk searchKey, bodySearch, textSearch *store.WordSearch, highestUID func() (store.UID, error)) bool {
	if m.MailboxID == c.mailboxID {
		seq = c.sequence(m.UID)
		if seq == 0 {
			// Session has not yet seen this message, and is not expecting to get a result that
			// includes it.
			return false
		}
	}

	s := search{c: c, tx: tx, msgCount: msgCount, seq: seq, m: m, highestUID: highestUID}
	defer func() {
		if s.mr != nil {
			err := s.mr.Close()
			c.xsanity(err, "closing messagereader")
			s.mr = nil
		}
	}()
	return s.match(sk, bodySearch, textSearch)
}

func (s *search) match(sk searchKey, bodySearch, textSearch *store.WordSearch) (match bool) {
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

// ensure message, reader and part are loaded. returns whether that was
// successful.
func (s *search) xensurePart() bool {
	if s.mr != nil {
		return s.p != nil
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
		if sk.seqSet.searchResult {
			// Interpreting search results on a mailbox that isn't selected during multisearch
			// is likely a mistake. No mention about it in the RFC. ../rfc/7377:257
			if s.m.MailboxID != c.mailboxID {
				xuserErrorf("can only use search result with the selected mailbox")
			}
			return uidSearch(c.searchResult, s.m.UID) > 0
		}
		// For multisearch, we have arranged to have a seq for non-selected mailboxes too.
		return sk.seqSet.containsSeqCount(s.seq, s.msgCount)
	}

	filterHeader := func(field, value string) bool {
		lower := strings.ToLower(value)
		h, err := s.p.Header()
		if err != nil {
			c.log.Debugx("parsing message header", err, slog.Any("uid", s.m.UID), slog.Int64("msgid", s.m.ID))
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
		if sk.uidSet.searchResult && s.m.MailboxID != c.mailboxID {
			// Interpreting search results on a mailbox that isn't selected during multisearch
			// is likely a mistake. No mention about it in the RFC. ../rfc/7377:257
			xuserErrorf("cannot use search result from another mailbox")
		}
		match, err := sk.uidSet.containsKnownUID(s.m.UID, c.searchResult, s.highestUID)
		xcheckf(err, "checking for presence in uid set")
		return match
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
			return slices.Contains(s.m.Keywords, kw)
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
			return !slices.Contains(s.m.Keywords, kw)
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
	case "SAVEDBEFORE", "SAVEDON", "SAVEDSINCE":
		// If we don't have a savedate for this message (for messages received before we
		// implemented this feature), we use the "internal date" (received timestamp) of
		// the message. ../rfc/8514:237
		rt := s.m.Received
		if s.m.SaveDate != nil {
			rt = *s.m.SaveDate
		}

		skdt := sk.date.Format("2006-01-02")
		rdt := rt.Format("2006-01-02")
		switch sk.op {
		case "SAVEDBEFORE":
			return rdt < skdt
		case "SAVEDON":
			return rdt == skdt
		case "SAVEDSINCE":
			return rdt >= skdt
		}
		panic("missing case")
	case "SAVEDATESUPPORTED":
		// We return whether we have a savedate for this message. We support it on all
		// mailboxes, but we only have this metadata from the time we implemented this
		// feature.
		return s.m.SaveDate != nil
	case "OLDER":
		// ../rfc/5032:76
		seconds := int64(time.Since(s.m.Received) / time.Second)
		return seconds >= sk.number
	case "YOUNGER":
		seconds := int64(time.Since(s.m.Received) / time.Second)
		return seconds <= sk.number
	}

	if s.p == nil {
		c.log.Info("missing parsed message, not matching", slog.Any("uid", s.m.UID), slog.Int64("msgid", s.m.ID))
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
			c.log.Errorx("parsing header for search", err, slog.Any("uid", s.m.UID), slog.Int64("msgid", s.m.ID))
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
