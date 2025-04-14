package imapserver

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
)

var searchMsg = strings.ReplaceAll(`Date: Mon, 1 Jan 2022 10:00:00 +0100 (CEST)
From: mjl <mjl@mox.example>
Subject: mox
To: mox <mox@mox.example>
Cc: <xcc@mox.example>
Bcc: <bcc@mox.example>
Reply-To: <noreply@mox.example>
Message-Id: <123@mox.example>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=x

--x
Content-Type: text/plain; charset=utf-8

this is plain text.

--x
Content-Type: text/html; charset=utf-8

this is html.

--x--
`, "\n", "\r\n")

func uint32ptr(v uint32) *uint32 {
	return &v
}

func (tc *testconn) xsearch(nums ...uint32) {
	tc.t.Helper()

	tc.xuntagged(imapclient.UntaggedSearch(nums))
}

func (tc *testconn) xsearchmodseq(modseq int64, nums ...uint32) {
	tc.t.Helper()

	if len(nums) == 0 {
		tc.xnountagged()
		return
	}
	tc.xuntagged(imapclient.UntaggedSearchModSeq{Nums: nums, ModSeq: modseq})
}

func (tc *testconn) xesearch(exp imapclient.UntaggedEsearch) {
	tc.t.Helper()

	exp.Tag = tc.client.LastTag()
	tc.xuntagged(exp)
}

func TestSearch(t *testing.T) {
	testSearch(t, false)
}

func TestSearchUIDOnly(t *testing.T) {
	testSearch(t, true)
}

func testSearch(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Add 5 and delete first 4 messages. So UIDs start at 5.
	received := time.Date(2020, time.January, 1, 10, 0, 0, 0, time.UTC)
	saveDate := time.Now()
	for range 5 {
		tc.client.Append("inbox", makeAppendTime(exampleMsg, received))
	}
	tc.client.UIDStoreFlagsSet("1:4", true, `\Deleted`)
	tc.client.Expunge()

	received = time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	tc.client.Append("inbox", makeAppendTime(searchMsg, received))

	received = time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	mostFlags := []string{
		`\Deleted`,
		`\Seen`,
		`\Answered`,
		`\Flagged`,
		`\Draft`,
		`$Forwarded`,
		`$Junk`,
		`$Notjunk`,
		`$Phishing`,
		`$MDNSent`,
		`custom1`,
		`Custom2`,
	}
	tc.client.Append("inbox", imapclient.Append{Flags: mostFlags, Received: &received, Size: int64(len(searchMsg)), Data: strings.NewReader(searchMsg)})

	// We now have sequence numbers 1,2,3 and UIDs 5,6,7.

	if uidonly {
		// We need to be selected. Not the case for ESEARCH command.
		tc.client.Unselect()
		tc.transactf("no", "uid search all")
		tc.client.Select("inbox")
	} else {
		// We need to be selected. Not the case for ESEARCH command.
		tc.client.Unselect()
		tc.transactf("no", "search all")
		tc.client.Select("inbox")

		tc.transactf("ok", "search all")
		tc.xsearch(1, 2, 3)
	}

	tc.transactf("ok", "uid search all")
	tc.xsearch(5, 6, 7)

	esearchall := func(ss string) imapclient.UntaggedEsearch {
		return imapclient.UntaggedEsearch{All: esearchall0(ss)}
	}

	if !uidonly {
		tc.transactf("ok", "search answered")
		tc.xsearch(3)

		tc.transactf("ok", `search bcc "bcc@mox.example"`)
		tc.xsearch(2, 3)

		tc.transactf("ok", "search before 1-Jan-2038")
		tc.xsearch(1, 2, 3)
		tc.transactf("ok", "search before 1-Jan-2020")
		tc.xsearch() // Before is about received, not date header of message.

		// WITHIN extension with OLDER & YOUNGER.
		tc.transactf("ok", "search older 60")
		tc.xsearch(1, 2, 3)
		tc.transactf("ok", "search younger 60")
		tc.xsearch()

		// SAVEDATE extension.
		tc.transactf("ok", "search savedbefore %s", saveDate.Add(24*time.Hour).Format("2-Jan-2006"))
		tc.xsearch(1, 2, 3)
		tc.transactf("ok", "search savedbefore %s", saveDate.Add(-24*time.Hour).Format("2-Jan-2006"))
		tc.xsearch()
		tc.transactf("ok", "search savedon %s", saveDate.Format("2-Jan-2006"))
		tc.xsearch(1, 2, 3)
		tc.transactf("ok", "search savedon %s", saveDate.Add(-24*time.Hour).Format("2-Jan-2006"))
		tc.xsearch()
		tc.transactf("ok", "search savedsince %s", saveDate.Add(-24*time.Hour).Format("2-Jan-2006"))
		tc.xsearch(1, 2, 3)
		tc.transactf("ok", "search savedsince %s", saveDate.Add(24*time.Hour).Format("2-Jan-2006"))
		tc.xsearch()

		tc.transactf("ok", `search body "Joe"`)
		tc.xsearch(1)
		tc.transactf("ok", `search body "Joe" body "bogus"`)
		tc.xsearch()
		tc.transactf("ok", `search body "Joe" text "Blurdybloop"`)
		tc.xsearch(1)
		tc.transactf("ok", `search body "Joe" not text "mox"`)
		tc.xsearch(1)
		tc.transactf("ok", `search body "Joe" not not body "Joe"`)
		tc.xsearch(1)
		tc.transactf("ok", `search body "this is plain text"`)
		tc.xsearch(2, 3)
		tc.transactf("ok", `search body "this is html"`)
		tc.xsearch(2, 3)

		tc.transactf("ok", `search cc "xcc@mox.example"`)
		tc.xsearch(2, 3)

		tc.transactf("ok", `search deleted`)
		tc.xsearch(3)

		tc.transactf("ok", `search flagged`)
		tc.xsearch(3)

		tc.transactf("ok", `search from "foobar@Blurdybloop.example"`)
		tc.xsearch(1)

		tc.transactf("ok", `search keyword $Forwarded`)
		tc.xsearch(3)

		tc.transactf("ok", `search keyword Custom1`)
		tc.xsearch(3)

		tc.transactf("ok", `search keyword custom2`)
		tc.xsearch(3)

		tc.transactf("ok", `search new`)
		tc.xsearch() // New requires a message to be recent. We pretend all messages are not recent.

		tc.transactf("ok", `search old`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search on 1-Jan-2022`)
		tc.xsearch(2, 3)

		tc.transactf("ok", `search recent`)
		tc.xsearch()

		tc.transactf("ok", `search seen`)
		tc.xsearch(3)

		tc.transactf("ok", `search since 1-Jan-2020`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search subject "afternoon"`)
		tc.xsearch(1)

		tc.transactf("ok", `search text "Joe"`)
		tc.xsearch(1)

		tc.transactf("ok", `search to "mooch@owatagu.siam.edu.example"`)
		tc.xsearch(1)

		tc.transactf("ok", `search unanswered`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search undeleted`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search unflagged`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search unkeyword $Junk`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search unkeyword custom1`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search unseen`)
		tc.xsearch(1, 2)

		tc.transactf("ok", `search draft`)
		tc.xsearch(3)

		tc.transactf("ok", `search header "subject" "afternoon"`)
		tc.xsearch(1)

		tc.transactf("ok", `search larger 1`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search not text "mox"`)
		tc.xsearch(1)

		tc.transactf("ok", `search or seen unseen`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search or unseen seen`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search sentbefore 8-Feb-1994`)
		tc.xsearch(1)

		tc.transactf("ok", `search senton 7-Feb-1994`)
		tc.xsearch(1)

		tc.transactf("ok", `search sentsince 6-Feb-1994`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search smaller 9999999`)
		tc.xsearch(1, 2, 3)

		tc.transactf("ok", `search uid 1`)
		tc.xsearch()

		tc.transactf("ok", `search uid 5`)
		tc.xsearch(1)

		tc.transactf("ok", `search or larger 1000000 smaller 1`)
		tc.xsearch()

		tc.transactf("ok", `search undraft`)
		tc.xsearch(1, 2)

		tc.transactf("no", `search charset unknown text "mox"`)
		tc.transactf("ok", `search charset us-ascii text "mox"`)
		tc.xsearch(2, 3)
		tc.transactf("ok", `search charset utf-8 text "mox"`)
		tc.xsearch(2, 3)

		// Check for properly formed INPROGRESS response code.
		orig := inProgressPeriod
		inProgressPeriod = 0
		tc.cmdf("tag1", "search undraft")
		tc.response("ok")

		inprogress := func(cur, goal uint32) imapclient.UntaggedResult {
			return imapclient.UntaggedResult{
				Status: "OK",
				Code:   imapclient.CodeInProgress{Tag: "tag1", Current: &cur, Goal: &goal},
				Text:   "still searching",
			}
		}
		tc.xuntagged(
			imapclient.UntaggedSearch([]uint32{1, 2}),
			// Due to inProgressPeriod 0, we get an inprogress response for each message in the mailbox.
			inprogress(0, 3),
			inprogress(1, 3),
			inprogress(2, 3),
		)
		inProgressPeriod = orig

		// Do new-style ESEARCH requests with RETURN. We should get an ESEARCH response.
		tc.transactf("ok", "search return () all")
		tc.xesearch(esearchall("1:3")) // Without any options, "ALL" is implicit.

		tc.transactf("ok", "search return (min max count all) all")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 3, Count: uint32ptr(3), All: esearchall0("1:3")})

		tc.transactf("ok", "search return (min) all")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1})

		tc.transactf("ok", "search return (min) 3")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 3})

		tc.transactf("ok", "search return (min) NOT all")
		tc.xesearch(imapclient.UntaggedEsearch{}) // Min not present if no match.

		tc.transactf("ok", "search return (max) all")
		tc.xesearch(imapclient.UntaggedEsearch{Max: 3})

		tc.transactf("ok", "search return (max) 1")
		tc.xesearch(imapclient.UntaggedEsearch{Max: 1})

		tc.transactf("ok", "search return (max) not all")
		tc.xesearch(imapclient.UntaggedEsearch{}) // Max not present if no match.

		tc.transactf("ok", "search return (min max) all")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 3})

		tc.transactf("ok", "search return (min max) 1")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 1})

		tc.transactf("ok", "search return (min max) not all")
		tc.xesearch(imapclient.UntaggedEsearch{})

		tc.transactf("ok", "search return (all) not all")
		tc.xesearch(imapclient.UntaggedEsearch{}) // All not present if no match.

		tc.transactf("ok", "search return (min max all) not all")
		tc.xesearch(imapclient.UntaggedEsearch{})

		tc.transactf("ok", "search return (min max all count) not all")
		tc.xesearch(imapclient.UntaggedEsearch{Count: uint32ptr(0)})

		tc.transactf("ok", "search return (min max count all) 1,3")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 3, Count: uint32ptr(2), All: esearchall0("1,3")})

		tc.transactf("ok", "search return (min max count all) UID 5,7")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 3, Count: uint32ptr(2), All: esearchall0("1,3")})
	}

	tc.transactf("ok", "UID search return (min max count all) all")
	tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(3), All: esearchall0("5:7")})

	if !uidonly {
		tc.transactf("ok", "uid search return (min max count all) 1,3")
		tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(2), All: esearchall0("5,7")})
	}

	tc.transactf("ok", "uid search return (min max count all) UID 5,7")
	tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(2), All: esearchall0("5,7")})

	if !uidonly {
		tc.transactf("no", `search return () charset unknown text "mox"`)
		tc.transactf("ok", `search return () charset us-ascii text "mox"`)
		tc.xesearch(esearchall("2:3"))
		tc.transactf("ok", `search return () charset utf-8 text "mox"`)
		tc.xesearch(esearchall("2:3"))

		tc.transactf("bad", `search return (unknown) all`)

		tc.transactf("ok", "search return (save) 2")
		tc.xnountagged() // ../rfc/9051:3800
		tc.transactf("ok", "fetch $ (uid)")
		tc.xuntagged(tc.untaggedFetch(2, 6))

		tc.transactf("ok", "search return (all) $")
		tc.xesearch(esearchall("2"))

		tc.transactf("ok", "search return (save) $")
		tc.xnountagged()

		tc.transactf("ok", "search return (save all) all")
		tc.xesearch(esearchall("1:3"))

		tc.transactf("ok", "search return (all save) all")
		tc.xesearch(esearchall("1:3"))

		tc.transactf("ok", "search return (min save) all")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1})
		tc.transactf("ok", "fetch $ (uid)")
		tc.xuntagged(tc.untaggedFetch(1, 5))
	}

	// Do a seemingly old-style search command with IMAP4rev2 enabled. We'll still get ESEARCH responses.
	tc.client.Enable(imapclient.CapIMAP4rev2)

	if !uidonly {
		tc.transactf("ok", `search undraft`)
		tc.xesearch(esearchall("1:2"))
	}

	// Long commands should be rejected, not allocating too much memory.
	lit := make([]byte, 100*1024+1)
	for i := range lit {
		lit[i] = 'x'
	}
	writeTextLit := func(n int, expok bool) {
		_, err := fmt.Fprintf(tc.client, " TEXT ")
		tcheck(t, err, "write text")

		_, err = fmt.Fprintf(tc.client, "{%d}\r\n", n)
		tcheck(t, err, "write literal size")
		line, err := tc.client.Readline()
		tcheck(t, err, "read line")
		if expok && !strings.HasPrefix(line, "+") {
			tcheck(t, fmt.Errorf("no continuation after writing size: %s", line), "sending literal")
		} else if !expok && !strings.HasPrefix(line, "x0 BAD [TOOBIG]") {
			tcheck(t, fmt.Errorf("got line %s", line), "expected TOOBIG error")
		}
		if !expok {
			return
		}
		_, err = tc.client.Write(lit[:n])
		tcheck(t, err, "write literal data")
	}

	// More than 100k for a literal.
	_, err := fmt.Fprintf(tc.client, "x0 uid search")
	tcheck(t, err, "write start of uit search")
	writeTextLit(100*1024+1, false)

	// More than 1mb total for literals.
	_, err = fmt.Fprintf(tc.client, "x0 uid search")
	tcheck(t, err, "write start of uit search")
	for range 10 {
		writeTextLit(100*1024, true)
	}
	writeTextLit(1, false)

	// More than 1000 literals.
	_, err = fmt.Fprintf(tc.client, "x0 uid search")
	tcheck(t, err, "write start of uit search")
	for range 1000 {
		writeTextLit(1, true)
	}
	writeTextLit(1, false)
}

// esearchall makes an UntaggedEsearch response with All set, for comparisons.
func esearchall0(ss string) imapclient.NumSet {
	seqset := imapclient.NumSet{}
	for _, rs := range strings.Split(ss, ",") {
		t := strings.Split(rs, ":")
		if len(t) > 2 {
			panic("bad seqset")
		}
		var first uint32
		var last *uint32
		if t[0] != "*" {
			v, err := strconv.ParseUint(t[0], 10, 32)
			if err != nil {
				panic("parse first")
			}
			first = uint32(v)
		}
		if len(t) == 2 {
			if t[1] != "*" {
				v, err := strconv.ParseUint(t[1], 10, 32)
				if err != nil {
					panic("parse last")
				}
				u := uint32(v)
				last = &u
			}
		}
		seqset.Ranges = append(seqset.Ranges, imapclient.NumRange{First: first, Last: last})
	}
	return seqset
}

func TestSearchMultiUnselected(t *testing.T) {
	testSearchMulti(t, false, false)
}

func TestSearchMultiSelected(t *testing.T) {
	testSearchMulti(t, true, false)
}

func TestSearchMultiSelectedUIDOnly(t *testing.T) {
	testSearchMulti(t, true, true)
}

// Test the MULTISEARCH extension, with and without selected mailbx. Operating
// without messag sequence numbers, and return untagged esearch responses that
// include the mailbox and uidvalidity.
func testSearchMulti(t *testing.T, selected, uidonly bool) {
	defer mockUIDValidity()()

	tc := start(t, uidonly)
	defer tc.close()
	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	// Add 5 messages to Inbox and delete first 4 messages. So UIDs start at 5.
	received := time.Date(2020, time.January, 1, 10, 0, 0, 0, time.UTC)
	for range 6 {
		tc.client.Append("inbox", makeAppendTime(exampleMsg, received))
	}
	tc.client.UIDStoreFlagsSet("1:4", true, `\Deleted`)
	tc.client.Expunge()

	// Unselecting mailbox, esearch works in authenticated state.
	if !selected {
		tc.client.Unselect()
	}

	received = time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	tc.client.Append("inbox", makeAppendTime(searchMsg, received))

	received = time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	mostFlags := []string{
		`\Deleted`,
		`\Seen`,
		`\Answered`,
		`\Flagged`,
		`\Draft`,
		`$Forwarded`,
		`$Junk`,
		`$Notjunk`,
		`$Phishing`,
		`$MDNSent`,
		`custom1`,
		`Custom2`,
	}
	tc.client.Append("Archive", imapclient.Append{Flags: mostFlags, Received: &received, Size: int64(len(searchMsg)), Data: strings.NewReader(searchMsg)})

	// We now have sequence numbers 1,2,3 and UIDs 5,6,7 in Inbox, and UID 1 in Archive.

	// Basic esearch with mailboxes.
	tc.cmdf("Tag1", `Esearch In (Personal) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:7")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, All: esearchall0("1")},
	)

	// Again, but with progress information.
	orig := inProgressPeriod
	inProgressPeriod = 0
	inprogress := func(cur, goal uint32) imapclient.UntaggedResult {
		return imapclient.UntaggedResult{
			Status: "OK",
			Code:   imapclient.CodeInProgress{Tag: "Tag1", Current: &cur, Goal: &goal},
			Text:   "still searching",
		}
	}
	tc.cmdf("Tag1", `Esearch In (Personal) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:7")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, All: esearchall0("1")},
		inprogress(0, 4),
		inprogress(1, 4),
		inprogress(2, 4),
		inprogress(3, 4),
	)
	inProgressPeriod = orig

	// Explicit mailboxes listed, including non-existent one that is ignored,
	// duplicates are ignored as well.
	tc.cmdf("Tag1", `Esearch In (Mailboxes (INBOX Archive Archive)) Return (Min Max Count All) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 7, Count: uint32ptr(3), All: esearchall0("5:7")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Min: 1, Max: 1, Count: uint32ptr(1), All: esearchall0("1")},
	)

	// No response if none of the mailboxes exist.
	tc.cmdf("Tag1", `Esearch In (Mailboxes bogus Mailboxes (nonexistent)) Return (Min Max Count All) All`)
	tc.response("ok")
	tc.xuntagged()

	// Inboxes evaluates to just inbox on new account. We'll add more mailboxes
	// matching "inboxes" later on.
	tc.cmdf("Tag1", `Esearch In (Inboxes) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:7")},
	)

	// Subscribed is set for created mailboxes by default.
	tc.cmdf("Tag1", `Esearch In (Subscribed) Return (Max) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Max: 7},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Max: 1},
	)

	// Asking for max does a reverse search.
	tc.cmdf("Tag1", `Esearch In (Personal) Return (Max) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Max: 7},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Max: 1},
	)

	// Min stops early.
	tc.cmdf("Tag1", `Esearch In (Personal) Return (Min) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Min: 1},
	)

	// Min and max do forward and reverse search, stopping early.
	tc.cmdf("Tag1", `Esearch In (Personal) Return (Min Max) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 7},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Min: 1, Max: 1},
	)

	if selected {
		// With only 1 inbox, we can use SAVE with Inboxes. Can't anymore when we have multiple.
		tc.transactf("ok", `Esearch In (Inboxes) Return (Save) All`)
		tc.xuntagged()

		// Using search result ($) works with selected mailbox.
		tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
		tc.response("ok")
		tc.xuntagged(
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:7")},
		)
	} else {
		// Cannot use "selected" if we are not in selected state.
		tc.transactf("bad", `Esearch In (Selected) Return () All`)
	}

	// Add more "inboxes", and other mailboxes for testing "subtree" and "subtree-one".
	more := []string{
		"Inbox/Sub1",
		"Inbox/Sub2",
		"Inbox/Sub2/SubA",
		"Inbox/Sub2/SubB",
		"Other",
		"Other/Sub1", // sub1@mox.example in config.
		"Other/Sub2",
		"Other/Sub2/SubA", // ruleset for sub2@mox.example in config.
		"Other/Sub2/SubB",
		"List", // ruleset for a mailing list
	}
	for _, name := range more {
		tc.client.Create(name, nil)
		tc.client.Append(name, makeAppendTime(exampleMsg, received))
	}

	// Cannot use SAVE with multiple mailboxes that match.
	tc.transactf("bad", `Esearch In (Inboxes) Return (Save) All`)

	// "inboxes" includes everything below Inbox, and also anything that we might
	// deliver to based on account addresses and rulesets, but not mailing lists.
	tc.cmdf("Tag1", `Esearch In (Inboxes) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:7")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox/Sub1", UIDValidity: 3, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox/Sub2", UIDValidity: 4, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox/Sub2/SubA", UIDValidity: 5, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox/Sub2/SubB", UIDValidity: 6, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub1", UIDValidity: 8, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub2/SubA", UIDValidity: 10, UID: true, All: esearchall0("1")},
	)

	// subtree
	tc.cmdf("Tag1", `Esearch In (Subtree Other) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other", UIDValidity: 7, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub1", UIDValidity: 8, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub2", UIDValidity: 9, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub2/SubA", UIDValidity: 10, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub2/SubB", UIDValidity: 11, UID: true, All: esearchall0("1")},
	)

	// subtree-one
	tc.cmdf("Tag1", `Esearch In (Subtree-One Other) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other", UIDValidity: 7, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub1", UIDValidity: 8, UID: true, All: esearchall0("1")},
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Other/Sub2", UIDValidity: 9, UID: true, All: esearchall0("1")},
	)

	// Search with sequence set also for non-selected mailboxes(!). The min/max would
	// get the first and last message, but the message sequence set forces a scan. Not
	// allowed with UIDONLY.
	if !uidonly {
		tc.cmdf("Tag1", `Esearch In (Mailboxes Inbox) Return (Min Max) 1:*`)
		tc.response("ok")
		tc.xuntagged(
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 7},
		)
	}

	// Search with uid set with "$highnum:*" forces getting highest uid.
	tc.cmdf("Tag1", `Esearch In (Mailboxes Inbox) Return (Min Max) Uid *:100`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 7, Max: 7},
	)
	tc.cmdf("Tag1", `Esearch In (Mailboxes Inbox) Return (Min Max) Uid 100:*`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 7, Max: 7},
	)
	tc.cmdf("Tag1", `Esearch In (Mailboxes Inbox) Return (Min Max) Uid 1:*`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 7},
	)

	// We use another session to add a new message to Inbox and to Archive. Searching
	// with Inbox selected will not return the new message since it isn't available in
	// the session yet. The message in Archive is returned, since there is no session
	// limitation.
	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Append("inbox", makeAppendTime(searchMsg, received))
	tc2.client.Append("Archive", makeAppendTime(searchMsg, received))

	tc.cmdf("Tag1", `Esearch In (Mailboxes (Inbox Archive)) Return (Count) All`)
	tc.response("ok")
	if selected {
		tc.xuntagged(
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Count: uint32ptr(3)},
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Count: uint32ptr(2)},
			imapclient.UntaggedExists(4),
			tc.untaggedFetch(4, 8, imapclient.FetchFlags(nil)),
		)
	} else {
		tc.xuntagged(
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Count: uint32ptr(4)},
			imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Archive", UIDValidity: 1, UID: true, Count: uint32ptr(2)},
		)
	}

	if selected {
		// Saving a search result, and then using it with another mailbox results in error.
		tc.transactf("ok", `Esearch In (Mailboxes Inbox) Return (Save) All`)
		tc.transactf("no", `Esearch In (Mailboxes Archive) Return () $`)
	} else {
		tc.transactf("bad", `Esearch In (Inboxes) Return (Save) All`) // Need a selected mailbox with SAVE.
		tc.transactf("no", `Esearch In (Inboxes) Return () $`)        // Cannot use saved result with non-selected mailbox.
	}

	tc.transactf("bad", `Esearch In () Return () All`)                    // Missing values for "IN"-list.
	tc.transactf("bad", `Esearch In (Bogus) Return () All`)               // Bogus word for "IN".
	tc.transactf("bad", `Esearch In ("Selected") Return () All`)          // IN-words can't be quoted.
	tc.transactf("bad", `Esearch In (Selected-Delayed) Return () All`)    // From NOTIFY, not in ESEARCH.
	tc.transactf("bad", `Esearch In (Subtree-One) Return () All`)         // After subtree-one we need a list.
	tc.transactf("bad", `Esearch In (Subtree-One ) Return () All`)        // After subtree-one we need a list.
	tc.transactf("bad", `Esearch In (Subtree-One (Test) ) Return () All`) // Bogus space.

	if !selected {
		return
	}
	// From now on, we are in selected state.

	tc.cmdf("Tag1", `Esearch In (Selected) Return () All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:8")},
	)

	// Testing combinations of SAVE with MIN/MAX/others ../rfc/9051:4100
	tc.transactf("ok", `Esearch In (Selected) Return (Save) All`)
	tc.xuntagged()

	tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:8")},
	)

	// Inbox happens to be the selected mailbox, so OK.
	tc.cmdf("Tag1", `Esearch In (Mailboxes Inbox) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:8")},
	)

	// Non-selected mailboxes aren't allowed to use the saved result.
	tc.transactf("no", `Esearch In (Mailboxes Archive) Return () $`)
	tc.transactf("no", `Esearch In (Mailboxes Archive) Return () uid $`)

	tc.cmdf("Tag1", `Esearch In (Selected) Return (Save Min Max) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 8},
	)
	tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5,8")},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return (Save Min) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5")},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return (Save Max) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Max: 8},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("8")},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return (Save Min Max Count) All`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, Min: 5, Max: 8, Count: uint32ptr(4)},
	)

	tc.cmdf("Tag1", `Esearch In (Selected) Return () $`)
	tc.response("ok")
	tc.xuntagged(
		imapclient.UntaggedEsearch{Tag: "Tag1", Mailbox: "Inbox", UIDValidity: 1, UID: true, All: esearchall0("5:8")},
	)
}
