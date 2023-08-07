package imapserver

import (
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

	exp.Correlator = tc.client.LastTag
	tc.xuntagged(exp)
}

func TestSearch(t *testing.T) {
	tc := start(t)
	defer tc.close()
	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Select("inbox")

	// Add 5 and delete first 4 messages. So UIDs start at 5.
	received := time.Date(2020, time.January, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		tc.client.Append("inbox", nil, &received, []byte(exampleMsg))
	}
	tc.client.StoreFlagsSet("1:4", true, `\Deleted`)
	tc.client.Expunge()

	received = time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	tc.client.Append("inbox", nil, &received, []byte(searchMsg))

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
	tc.client.Append("inbox", mostFlags, &received, []byte(searchMsg))

	// We now have sequence numbers 1,2,3 and UIDs 5,6,7.

	tc.transactf("ok", "search all")
	tc.xsearch(1, 2, 3)

	tc.transactf("ok", "uid search all")
	tc.xsearch(5, 6, 7)

	tc.transactf("ok", "search answered")
	tc.xsearch(3)

	tc.transactf("ok", `search bcc "bcc@mox.example"`)
	tc.xsearch(2, 3)

	tc.transactf("ok", "search before 1-Jan-2038")
	tc.xsearch(1, 2, 3)
	tc.transactf("ok", "search before 1-Jan-2020")
	tc.xsearch() // Before is about received, not date header of message.

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

	esearchall := func(ss string) imapclient.UntaggedEsearch {
		return imapclient.UntaggedEsearch{All: esearchall0(ss)}
	}

	uint32ptr := func(v uint32) *uint32 {
		return &v
	}

	// Do new-style ESEARCH requests with RETURN. We should get an ESEARCH response.
	tc.transactf("ok", "search return () all")
	tc.xesearch(esearchall("1:3")) // Without any options, "ALL" is implicit.

	tc.transactf("ok", "search return (min max count all) all")
	tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 3, Count: uint32ptr(3), All: esearchall0("1:3")})

	tc.transactf("ok", "UID search return (min max count all) all")
	tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(3), All: esearchall0("5:7")})

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

	tc.transactf("ok", "uid search return (min max count all) 1,3")
	tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(2), All: esearchall0("5,7")})

	tc.transactf("ok", "uid search return (min max count all) UID 5,7")
	tc.xesearch(imapclient.UntaggedEsearch{UID: true, Min: 5, Max: 7, Count: uint32ptr(2), All: esearchall0("5,7")})

	tc.transactf("no", `search return () charset unknown text "mox"`)
	tc.transactf("ok", `search return () charset us-ascii text "mox"`)
	tc.xesearch(esearchall("2:3"))
	tc.transactf("ok", `search return () charset utf-8 text "mox"`)
	tc.xesearch(esearchall("2:3"))

	tc.transactf("bad", `search return (unknown) all`)

	tc.transactf("ok", "search return (save) 2")
	tc.xnountagged() // ../rfc/9051:3800
	tc.transactf("ok", "fetch $ (uid)")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(6)}})

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
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(5)}})

	// Do a seemingly old-style search command with IMAP4rev2 enabled. We'll still get ESEARCH responses.
	tc.client.Enable("IMAP4rev2")
	tc.transactf("ok", `search undraft`)
	tc.xesearch(esearchall("1:2"))
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
