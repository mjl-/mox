package imapserver

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
	"slices"
)

func TestCondstore(t *testing.T) {
	testCondstoreQresync(t, false, false)
}

func TestCondstoreUIDOnly(t *testing.T) {
	testCondstoreQresync(t, false, true)
}

func TestQresync(t *testing.T) {
	testCondstoreQresync(t, true, false)
}

func TestQresyncUIDOnly(t *testing.T) {
	testCondstoreQresync(t, true, true)
}

func testCondstoreQresync(t *testing.T, qresync, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	// todo: check whether marking \seen will cause modseq to be returned in case of qresync.

	// Check basic requirements of CONDSTORE.

	capability := imapclient.CapCondstore
	if qresync {
		capability = imapclient.CapQresync
	}

	tc.login("mjl@mox.example", password0)
	tc.client.Enable(capability)
	tc.transactf("ok", "Select inbox")
	tc.xuntaggedOpt(false, imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(2), Text: "x"})

	// First some tests without any messages.

	tc.transactf("ok", "Status inbox (Highestmodseq)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusHighestModSeq: 2}})

	// No messages, no matches.
	tc.transactf("ok", "Uid Fetch 1:* (Flags) (Changedsince 12345)")
	tc.xuntagged()

	// Also no messages with modseq 1, which we internally turn into modseq 0.
	tc.transactf("ok", "Uid Fetch 1:* (Flags) (Changedsince 1)")
	tc.xuntagged()

	// Also try with modseq attribute.
	tc.transactf("ok", "Uid Fetch 1:* (Flags Modseq) (Changedsince 1)")
	tc.xuntagged()

	if !uidonly {
		// Search with modseq search criteria.
		tc.transactf("ok", "Search Modseq 0") // Zero is valid, matches all.
		tc.xsearch()

		tc.transactf("ok", "Search Modseq 1") // Converted to zero internally.
		tc.xsearch()

		tc.transactf("ok", "Search Modseq 12345")
		tc.xsearch()

		tc.transactf("ok", `Search Modseq "/Flags/\\Draft" All 12345`)
		tc.xsearch()

		tc.transactf("ok", `Search Or Modseq 12345 Modseq 54321`)
		tc.xsearch()

		// esearch
		tc.transactf("ok", "Search Return (All) Modseq 123")
		tc.xesearch(imapclient.UntaggedEsearch{})
	}

	// Now we add, delete, expunge, modify some message flags and check if the
	// responses are correct. We check in both a condstore-enabled and one without that
	// we get the correct notifications.

	// First we add 3 messages as if they were added before we implemented CONDSTORE.
	// Later on, we'll update the second, and delete the third, leaving the first
	// unmodified. Those messages have modseq 0 in the database. We use append for
	// convenience, then adjust the records in the database.
	// We have a workaround below to prevent triggering the consistency checker.
	tc.account.SetSkipMessageModSeqZeroCheck(true)
	defer tc.account.SetSkipMessageModSeqZeroCheck(false)
	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	_, err := bstore.QueryDB[store.Message](ctxbg, tc.account.DB).UpdateFields(map[string]any{
		"ModSeq":    0,
		"CreateSeq": 0,
	})
	tcheck(t, err, "clearing modseq from messages")
	err = tc.account.DB.Update(ctxbg, &store.SyncState{ID: 1, LastModSeq: 1})
	tcheck(t, err, "resetting modseq state")

	tc.client.Create("otherbox", nil)

	// tc2 is a client without condstore, so no modseq responses.
	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()
	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	// tc3 is a client with condstore, so with modseq responses.
	tc3 := startNoSwitchboard(t, uidonly)
	defer tc3.closeNoWait()
	tc3.login("mjl@mox.example", password0)
	tc3.client.Enable(capability)
	tc3.client.Select("inbox")

	var clientModseq int64 = 2 // We track the client-side modseq for inbox. Not a store.ModSeq.

	// Add messages to: inbox, otherbox, inbox, inbox.
	// We have these messages in order of modseq: 2+1 in inbox, 1 in otherbox, 2 in inbox.
	// The original two in inbox appear to have modseq 1 (with 0 stored in the database).
	// Creation of otherbox got modseq 2.
	// The ones we insert below will start with modseq 3. So we'll have messages with modseq 1 and 3-6.
	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.xuntagged(imapclient.UntaggedExists(4))
	tc.xcode(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("4")})

	tc.transactf("ok", "Append otherbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.xuntagged()
	tc.xcode(imapclient.CodeAppendUID{UIDValidity: 3, UIDs: xparseUIDRange("1")})

	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.xuntagged(imapclient.UntaggedExists(5))
	tc.xcode(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("5")})

	tc.transactf("ok", "Append inbox () \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.xuntagged(imapclient.UntaggedExists(6))
	tc.xcode(imapclient.CodeAppendUID{UIDValidity: 1, UIDs: xparseUIDRange("6")})

	tc2.transactf("ok", "Noop")
	noflags := imapclient.FetchFlags(nil)
	tc2.xuntagged(
		imapclient.UntaggedExists(6),
		tc2.untaggedFetch(4, 4, noflags),
		tc2.untaggedFetch(5, 5, noflags),
		tc2.untaggedFetch(6, 6, noflags),
	)

	tc3.transactf("ok", "Noop")
	tc3.xuntagged(
		imapclient.UntaggedExists(6),
		tc3.untaggedFetch(4, 4, noflags, imapclient.FetchModSeq(clientModseq+1)),
		tc3.untaggedFetch(5, 5, noflags, imapclient.FetchModSeq(clientModseq+3)),
		tc3.untaggedFetch(6, 6, noflags, imapclient.FetchModSeq(clientModseq+4)),
	)

	if !uidonly {
		mox.SetPedantic(true)
		tc.transactf("bad", `Fetch 1 Flags (Changedsince 0)`) // 0 not allowed in syntax.
		mox.SetPedantic(false)
	}
	tc.transactf("ok", "Uid fetch 1 (Flags) (Changedsince 0)")
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(1)))

	// Check highestmodseq for mailboxes.
	tc.transactf("ok", "Status inbox (highestmodseq)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusHighestModSeq: clientModseq + 4}})

	tc.transactf("ok", "Status otherbox (highestmodseq)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "otherbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusHighestModSeq: clientModseq + 2}})

	// Check highestmodseq when we select.
	tc.transactf("ok", "Examine otherbox")
	tc.xuntaggedOpt(false, imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(clientModseq + 2), Text: "x"})

	tc.transactf("ok", "Select inbox")
	tc.xuntaggedOpt(false, imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(clientModseq + 4), Text: "x"})

	clientModseq += 4

	if !uidonly {
		// Check fetch modseq response and changedsince.
		tc.transactf("ok", `Fetch 1 (Modseq)`)
		tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchModSeq(1)))
	}

	// Without modseq attribute, even with condseq enabled, there is no modseq response.
	// For QRESYNC, we must always send MODSEQ for UID FETCH commands, but not for FETCH commands. ../rfc/7162:1427
	tc.transactf("ok", `Uid Fetch 1 Flags`)
	if qresync {
		tc.xuntagged(tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(1)))
	} else {
		tc.xuntagged(tc.untaggedFetch(1, 1, noflags))
	}

	if !uidonly {
		tc.transactf("ok", `Fetch 1 Flags`)
		tc.xuntagged(tc.untaggedFetch(1, 1, noflags))
	}

	if !uidonly {
		// When CHANGEDSINCE is present, MODSEQ is automatically added to the response.
		// ../rfc/7162:871
		// ../rfc/7162:877
		tc.transactf("ok", `Fetch 1 Flags (Changedsince 1)`)
		tc.xuntagged()
		tc.transactf("ok", `Fetch 1,4 Flags (Changedsince 1)`)
		tc.xuntagged(tc.untaggedFetch(4, 4, noflags, imapclient.FetchModSeq(3)))
		tc.transactf("ok", `Fetch 2 Flags (Changedsince 2)`)
		tc.xuntagged()
	}

	// store and uid store.

	if !uidonly {
		// unchangedsince 0 never passes the check. ../rfc/7162:640
		tc.transactf("ok", `Store 1 (Unchangedsince 0) +Flags ()`)
		tc.xcode(imapclient.CodeModified(xparseNumSet("1")))
		tc.xuntagged(tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(1)))
	}

	// Modseq is 2 for first condstore-aware-appended message, so also no match.
	tc.transactf("ok", `Uid Store 4 (Unchangedsince 1) +Flags ()`)
	tc.xcode(imapclient.CodeModified(xparseNumSet("4")))

	if uidonly {
		tc.transactf("ok", `Uid Store 1 (Unchangedsince 1) +Flags (label1)`)
	} else {
		// Modseq is 1 for original message.
		tc.transactf("ok", `Store 1 (Unchangedsince 1) +Flags (label1)`)
	}
	tc.xcode(nil) // No MODIFIED.
	clientModseq++
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"label1"}, imapclient.FetchModSeq(clientModseq)))
	tc2.transactf("ok", "Noop")
	tc2.xuntagged(
		tc2.untaggedFetch(1, 1, imapclient.FetchFlags{"label1"}),
	)
	tc3.transactf("ok", "Noop")
	tc3.xuntagged(
		tc3.untaggedFetch(1, 1, imapclient.FetchFlags{"label1"}, imapclient.FetchModSeq(clientModseq)),
	)

	// Modify same message twice. Check that second application doesn't fail due to
	// modseq change made in the first application. ../rfc/7162:823
	tc.transactf("ok", `Uid Store 1,1 (Unchangedsince %d) -Flags (label1)`, clientModseq)
	clientModseq++
	tc.xcode(nil) // No MODIFIED.
	tc.xuntagged(
		tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil), imapclient.FetchModSeq(clientModseq)),
	)
	// We do broadcast the changes twice. Not great, but doesn't hurt. This isn't common.
	tc2.transactf("ok", "Noop")
	tc2.xuntagged(
		tc2.untaggedFetch(1, 1, imapclient.FetchFlags(nil)),
	)
	tc3.transactf("ok", "Noop")
	tc3.xuntagged(
		tc3.untaggedFetch(1, 1, imapclient.FetchFlags(nil), imapclient.FetchModSeq(clientModseq)),
	)

	if !uidonly {
		// Modify without actually changing flags, there will be no new modseq and no broadcast.
		tc.transactf("ok", `Store 1 (Unchangedsince %d) -Flags (label1)`, clientModseq)
		tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil), imapclient.FetchModSeq(clientModseq)))
		tc.xcode(nil) // No MODIFIED.
		tc2.transactf("ok", "Noop")
		tc2.xuntagged()
		tc3.transactf("ok", "Noop")
		tc3.xuntagged()

		// search with modseq criteria and modseq in response
		tc.transactf("ok", "Search Modseq %d", clientModseq)
		tc.xsearchmodseq(clientModseq, 1)
	}

	tc.transactf("ok", "Uid Search Or Modseq %d Modseq %d", clientModseq, clientModseq)
	tc.xsearchmodseq(clientModseq, 1)

	if !uidonly {
		// esearch
		tc.transactf("ok", "Search Return (Min Max All) 1:* Modseq %d", clientModseq)
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 1, All: esearchall0("1"), ModSeq: clientModseq})

		tc.transactf("ok", "Search Return (Count) 1:* Modseq 0")
		tc.xesearch(imapclient.UntaggedEsearch{Count: uint32ptr(6), ModSeq: clientModseq})

		tc.transactf("ok", "Search Return (Min Max) 1:* Modseq 0")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 6, ModSeq: clientModseq})

		tc.transactf("ok", "Search Return (Min) 1:* Modseq 0")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, ModSeq: clientModseq})

		// expunge, we expunge the third and fourth messages. The third was originally with
		// modseq 0, the fourth was added with condstore-aware append.
		tc.transactf("ok", `Store 3:4 +Flags (\Deleted)`)
		clientModseq++
	} else {
		tc.transactf("ok", `Uid Store 3,4 +Flags (\Deleted)`)
		clientModseq++
	}
	tc2.transactf("ok", "Noop")
	tc3.transactf("ok", "Noop")
	tc.transactf("ok", "Expunge")
	clientModseq++
	if qresync || uidonly {
		tc.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("3:4")})
	} else {
		tc.xuntagged(imapclient.UntaggedExpunge(3), imapclient.UntaggedExpunge(3))
	}
	tc.xcode(imapclient.CodeHighestModSeq(clientModseq))
	tc2.transactf("ok", "Noop")
	if uidonly {
		tc2.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("3:4")})
	} else {
		tc2.xuntagged(imapclient.UntaggedExpunge(3), imapclient.UntaggedExpunge(3))
	}
	tc3.transactf("ok", "Noop")
	if qresync || uidonly {
		tc3.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("3:4")})
	} else {
		tc3.xuntagged(imapclient.UntaggedExpunge(3), imapclient.UntaggedExpunge(3))
	}

	// Again after expunge: status, select, conditional store/fetch/search
	tc.transactf("ok", "Status inbox (Highestmodseq Messages Unseen Deleted)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 4, imapclient.StatusUnseen: 4, imapclient.StatusDeleted: 0, imapclient.StatusHighestModSeq: clientModseq}})

	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox")
	tc.xuntaggedOpt(false,
		imapclient.UntaggedExists(4),
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(clientModseq), Text: "x"},
	)

	if !uidonly {
		tc.transactf("ok", `Fetch 1:* (Modseq)`)
		tc.xuntagged(
			tc.untaggedFetch(1, 1, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(2, 2, imapclient.FetchModSeq(1)),
			tc.untaggedFetch(3, 5, imapclient.FetchModSeq(5)),
			tc.untaggedFetch(4, 6, imapclient.FetchModSeq(6)),
		)
	}
	// Expunged messages, with higher modseq, should not show up.
	tc.transactf("ok", "Uid Fetch 1:* (flags) (Changedsince 8)")
	tc.xuntagged()

	if !uidonly {
		// search
		tc.transactf("ok", "Search Modseq 8")
		tc.xsearchmodseq(8, 1)
		tc.transactf("ok", "Search Modseq 9")
		tc.xsearch()

		// esearch
		tc.transactf("ok", "Search Return (Min Max All) 1:* Modseq 8")
		tc.xesearch(imapclient.UntaggedEsearch{Min: 1, Max: 1, All: esearchall0("1"), ModSeq: 8})
		tc.transactf("ok", "Search Return (Min Max All) 1:* Modseq 9")
		tc.xuntagged(imapclient.UntaggedEsearch{Tag: tc.client.LastTag()})
	}

	// store, cannot modify expunged messages.
	tc.transactf("ok", `Uid Store 3,4 (Unchangedsince %d) +Flags (label2)`, clientModseq)
	tc.xuntagged()
	tc.xcode(nil) // Not MODIFIED.
	tc.transactf("ok", `Uid Store 3,4 +Flags (label2)`)
	tc.xuntagged()
	tc.xcode(nil) // Not MODIFIED.

	// Check all condstore-enabling commands (and their syntax), ../rfc/7162:368

	// We start a new connection, do the thing that should enable condstore, then
	// change flags of a message in another connection, do a noop in the new connection
	// which should result in an untagged fetch that includes modseq, the indicator
	// that condstore was indeed enabled. It's a bit complicated, but i don't think
	// there is a clearly specified mechanism to find out which capabilities are
	// enabled at any point.
	var tagcount int
	checkCondstoreEnabled := func(fn func(xtc *testconn)) {
		t.Helper()

		xtc := startNoSwitchboard(t, uidonly)
		// We have modified modseq & createseq to 0 above for testing that case. Don't
		// trigger the consistency checker.
		defer xtc.closeNoWait()
		xtc.login("mjl@mox.example", password0)
		fn(xtc)
		tagcount++
		label := fmt.Sprintf("l%d", tagcount)
		tc.transactf("ok", "Uid Store 6 Flags (%s)", label)
		clientModseq++
		xtc.transactf("ok", "Noop")
		xtc.xuntagged(xtc.untaggedFetch(4, 6, imapclient.FetchFlags{label}, imapclient.FetchModSeq(clientModseq)))
	}
	// SELECT/EXAMINE with CONDSTORE parameter, ../rfc/7162:373
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Select inbox (Condstore)")
	})
	// STATUS with HIGHESTMODSEQ attribute, ../rfc/7162:375
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Status otherbox (Highestmodseq)")
		xtc.transactf("ok", "Select inbox")
	})
	// FETCH with MODSEQ ../rfc/7162:377
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Select inbox")
		xtc.transactf("ok", "Uid Fetch 6 (Modseq)")
	})
	// SEARCH with MODSEQ ../rfc/7162:377
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Select inbox")
		xtc.transactf("ok", "Uid Search Uid 6 Modseq 1")
	})
	// FETCH with CHANGEDSINCE ../rfc/7162:380
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Select inbox")
		xtc.transactf("ok", "Uid Fetch 6 (Flags) (Changedsince %d)", clientModseq)
	})
	// STORE with UNCHANGEDSINCE ../rfc/7162:382
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Select inbox")
		xtc.transactf("ok", "Uid Store 6 (Unchangedsince 0) Flags ()")
	})
	// ENABLE CONDSTORE ../rfc/7162:384
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Enable Condstore")
		xtc.transactf("ok", "Select inbox")
	})
	// ENABLE QRESYNC ../rfc/7162:1390
	checkCondstoreEnabled(func(xtc *testconn) {
		t.Helper()
		xtc.transactf("ok", "Enable Qresync")
		xtc.transactf("ok", "Select inbox")
	})

	if qresync {
		tc.transactf("ok", "Uid Store 6 Flags ()")
		clientModseq++

		testQresync(t, tc, uidonly, clientModseq)
	}

	// Continue with some tests that further change the data.
	// First we copy messages to a new mailbox, and check we get new modseq for those
	// messages.
	tc.transactf("ok", "Select otherbox")
	tc2.transactf("ok", "Noop")
	tc3.transactf("ok", "Noop")
	tc.transactf("ok", "Uid Copy 1 inbox")
	clientModseq++
	tc2.transactf("ok", "Noop")
	tc3.transactf("ok", "Noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(5),
		tc2.untaggedFetch(5, 7, noflags),
	)
	tc3.xuntagged(
		imapclient.UntaggedExists(5),
		tc3.untaggedFetch(5, 7, noflags, imapclient.FetchModSeq(clientModseq)),
	)

	// Then we move some messages, and check if we get expunged/vanished in original
	// and untagged fetch with modseq in destination mailbox.
	// tc2o is a client without condstore, so no modseq responses.
	tc2o := startNoSwitchboard(t, uidonly)
	defer tc2o.closeNoWait()
	tc2o.login("mjl@mox.example", password0)
	tc2o.client.Select("otherbox")

	// tc3o is a client with condstore, so with modseq responses.
	tc3o := startNoSwitchboard(t, uidonly)
	defer tc3o.closeNoWait()
	tc3o.login("mjl@mox.example", password0)
	tc3o.client.Enable(capability)
	tc3o.client.Select("otherbox")

	tc.transactf("ok", "Select inbox")
	tc.transactf("ok", "Uid Move 2:4 otherbox") // Only UID 2, because UID 3 and 4 have already been expunged.
	clientModseq++
	if qresync {
		tc.xuntaggedOpt(false, imapclient.UntaggedVanished{UIDs: xparseNumSet("2")})
		tc.xcode(imapclient.CodeHighestModSeq(clientModseq))
	} else if uidonly {
		tc.xuntaggedOpt(false, imapclient.UntaggedVanished{UIDs: xparseNumSet("2")})
		tc.xcode(nil)
	} else {
		tc.xuntaggedOpt(false, imapclient.UntaggedExpunge(2))
		tc.xcode(nil)
	}
	tc2.transactf("ok", "Noop")
	if uidonly {
		tc2.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("2")})
	} else {
		tc2.xuntagged(imapclient.UntaggedExpunge(2))
	}
	tc3.transactf("ok", "Noop")
	if qresync || uidonly {
		tc3.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("2")})
	} else {
		tc3.xuntagged(imapclient.UntaggedExpunge(2))
	}
	tc2o.transactf("ok", "Noop")
	tc2o.xuntagged(
		imapclient.UntaggedExists(2),
		tc2o.untaggedFetch(2, 2, noflags),
	)
	tc3o.transactf("ok", "Noop")
	tc3o.xuntagged(
		imapclient.UntaggedExists(2),
		tc2o.untaggedFetch(2, 2, noflags, imapclient.FetchModSeq(clientModseq)),
	)

	tc2o.closeNoWait()
	tc2o = nil
	tc3o.closeNoWait()
	tc3o = nil

	// Then we rename inbox, which is special because it moves messages away instead of
	// actually moving the mailbox. The mailbox stays and is cleared, so we check if we
	// get expunged/vanished messages.
	tc.transactf("ok", "Rename inbox oldbox")
	// todo spec: server doesn't respond with untagged responses, find rfc reference that says this is ok.
	tc2.transactf("ok", "Noop")
	if uidonly {
		tc2.xuntagged(
			imapclient.UntaggedList{Separator: '/', Mailbox: "oldbox"},
			imapclient.UntaggedVanished{UIDs: xparseNumSet("1,5:7")},
		)
	} else {
		tc2.xuntagged(
			imapclient.UntaggedList{Separator: '/', Mailbox: "oldbox"},
			imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1),
		)
	}
	tc3.transactf("ok", "Noop")
	if qresync || uidonly {
		tc3.xuntagged(
			imapclient.UntaggedList{Separator: '/', Mailbox: "oldbox"},
			imapclient.UntaggedVanished{UIDs: xparseNumSet("1,5:7")},
		)
	} else {
		tc3.xuntagged(
			imapclient.UntaggedList{Separator: '/', Mailbox: "oldbox"},
			imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1),
		)
	}

	// Then we delete otherbox (we cannot delete inbox). We don't keep any history for removed mailboxes, so not actually a special case.
	tc.transactf("ok", "Delete otherbox")
}

func testQresync(t *testing.T, tc *testconn, uidonly bool, clientModseq int64) {
	// Vanished on non-uid fetch is not allowed. ../rfc/7162:1693
	tc.transactf("bad", "fetch 1:* (Flags) (Changedsince 1 Vanished)")

	// Vanished without changedsince is not allowed. ../rfc/7162:1701
	tc.transactf("bad", "Uid Fetch 1:* (Flags) (Vanished)")

	// Vanished not allowed without first enabling qresync. ../rfc/7162:1697
	xtc := startNoSwitchboard(t, uidonly)
	xtc.login("mjl@mox.example", password0)
	xtc.transactf("ok", "Select inbox (Condstore)")
	xtc.transactf("bad", "Uid Fetch 1:* (Flags) (Changedsince 1 Vanished)")
	xtc.closeNoWait()
	xtc = nil

	// Check that we get proper vanished responses.
	tc.transactf("ok", "Uid Fetch 1:* (Flags) (Changedsince 1 Vanished)")
	noflags := imapclient.FetchFlags(nil)
	tc.xuntagged(
		imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
		tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
		tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
		tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
	)

	// select/examine with qresync parameters, including the various optional fields.
	tc.transactf("ok", "Close")

	// Must enable qresync explicitly before using. ../rfc/7162:1446
	xtc = startNoSwitchboard(t, uidonly)
	xtc.login("mjl@mox.example", password0)
	xtc.transactf("bad", "Select inbox (Qresync 1 0)")
	// Prevent triggering the consistency checker, we still have modseq/createseq at 0.
	xtc.closeNoWait()
	xtc = nil

	tc.transactf("bad", "Select inbox (Qresync (0 1))")               // Both args must be > 0.
	tc.transactf("bad", "Select inbox (Qresync (1 0))")               // Both args must be > 0.
	tc.transactf("bad", "Select inbox (Qresync)")                     // Two args are minimum.
	tc.transactf("bad", "Select inbox (Qresync (1))")                 // Two args are minimum.
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:*))")           // Known UIDs, * not allowed.
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:6 (1:* 1:6)))") // Known seqset cannot have *.
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:6 (1:6 1:*)))") // Known uidset cannot have *.
	tc.transactf("bad", "Select inbox (Qresync (1 1) qresync (1 1))") // Duplicate qresync.

	flags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent l1 l2 l3 l4 l5 l6 l7 l8 label1`, " ")
	permflags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*`, " ")
	uflags := imapclient.UntaggedFlags(flags)
	upermflags := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodePermanentFlags(permflags), Text: "x"}

	baseUntagged := []imapclient.Untagged{
		uflags,
		upermflags,
		imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"},
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDNext(7), Text: "x"},
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDValidity(1), Text: "x"},
		imapclient.UntaggedRecent(0),
		imapclient.UntaggedExists(4),
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(clientModseq), Text: "x"},
	}
	if !uidonly {
		baseUntagged = append(baseUntagged,
			imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUnseen(1), Text: "x"},
		)
	}

	makeUntagged := func(l ...imapclient.Untagged) []imapclient.Untagged {
		return slices.Concat(baseUntagged, l)
	}

	// uidvalidity 1, highest known modseq 1, sends full current state.
	tc.transactf("ok", "Select inbox (Qresync (1 1))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
			tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// Uidvalidity mismatch, server will not send any changes, so it's just a regular open.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (2 1))")
	tc.xuntagged(baseUntagged...)

	// We can tell which UIDs we know. First, send broader range then exist, should work.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1 1:7))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
			tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// Now send just the ones that exist. We won't get the vanished messages.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1 1,2,5:6))")
	tc.xuntagged(
		makeUntagged(
			tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
			tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// We'll only get updates for UIDs we specify.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1 5))")
	tc.xuntagged(
		makeUntagged(
			tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
		)...,
	)

	// We'll only get updates for UIDs we specify. ../rfc/7162:1523
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1 3))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3")},
		)...,
	)

	// If we specify the latest modseq, we'll get no changes.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 %d))", clientModseq)
	tc.xuntagged(baseUntagged...)

	// We can provide our own seqs & uids, and have server determine which uids we
	// know. But the seqs & uids must be of equal length. First try with a few combinations
	// that aren't valid. ../rfc/7162:1579
	tc.transactf("ok", "Close")
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:6 (1 1,2)))") // Not same length.
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:6 (1,2 1)))") // Not same length.
	if !uidonly {
		tc.transactf("no", "Select inbox (Qresync (1 1 1:6 (1,2 1,1)))") // Not ascending.
	}
	tc.transactf("bad", "Select inbox (Qresync (1 1 1:6 (1:* 1:4)))") // Star not allowed.

	if uidonly {
		return
	}

	// With valid parameters, based on what a client would know at this stage.
	tc.transactf("ok", "Select inbox (Qresync (1 1 1:6 (1,3,6 1,3,6)))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(3, 5, noflags, imapclient.FetchModSeq(5)),
			tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// The 3rd parameter is optional, try without.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 5 (1,3,6 1,3,6)))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(1, 1, noflags, imapclient.FetchModSeq(8)),
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 9 (1,3,6 1,3,6)))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// Client will claim a highestmodseq but then include uids that have been removed
	// since that time. Server detects this, sends full vanished history and continues
	// working with modseq changed to 1 before the expunged uid.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 10 (1,3,6 1,3,6)))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeWord("ALERT"), Text: "Synchronization inconsistency in client detected. Client tried to sync with a UID that was removed at or after the MODSEQ it sent in the request. Sending all historic message removals for selected mailbox. Full synchronization recommended."},
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)

	// Client will claim a highestmodseq but then include uids that have been removed
	// since that time. Server detects this, sends full vanished history and continues
	// working with modseq changed to 1 before the expunged uid.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 18 (1,3,6 1,3,6)))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeWord("ALERT"), Text: "Synchronization inconsistency in client detected. Client tried to sync with a UID that was removed at or after the MODSEQ it sent in the request. Sending all historic message removals for selected mailbox. Full synchronization recommended."},
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("3:4")},
			tc.untaggedFetch(4, 6, noflags, imapclient.FetchModSeq(clientModseq)),
		)...,
	)
}

func TestQresyncHistory(t *testing.T) {
	testQresyncHistory(t, false)
}

func TestQresyncHistoryUIDOnly(t *testing.T) {
	testQresyncHistory(t, true)
}

func testQresyncHistory(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Enable(imapclient.CapQresync)
	tc.transactf("ok", "Append inbox {1+}\r\nx")
	tc.transactf("ok", "Append inbox {1+}\r\nx") // modseq 6
	tc.transactf("ok", "Append inbox {1+}\r\nx")
	tc.transactf("ok", "Select inbox")
	tc.client.UIDStoreFlagsAdd("1,3", true, `\Deleted`) // modseq 8
	tc.client.Expunge()                                 // modseq 9
	tc.client.UIDStoreFlagsAdd("2", true, `\Seen`)      // modseq 10
	// We have UID 2, no more UID 1 and 3.

	flags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent`, " ")
	permflags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent \*`, " ")
	uflags := imapclient.UntaggedFlags(flags)
	upermflags := imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodePermanentFlags(permflags), Text: "x"}
	baseUntagged := []imapclient.Untagged{
		uflags,
		upermflags,
		imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"},
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDNext(4), Text: "x"},
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeUIDValidity(1), Text: "x"},
		imapclient.UntaggedRecent(0),
		imapclient.UntaggedExists(1),
		imapclient.UntaggedResult{Status: imapclient.OK, Code: imapclient.CodeHighestModSeq(10), Text: "x"},
	}

	makeUntagged := func(l ...imapclient.Untagged) []imapclient.Untagged {
		return slices.Concat(baseUntagged, l)
	}

	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("1,3")},
			tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)),
		)...,
	)

	err := tc.account.DB.Write(ctxbg, func(tx *bstore.Tx) error {
		syncState := store.SyncState{ID: 1}
		err := tx.Get(&syncState)
		tcheck(t, err, "get syncstate")

		syncState.HighestDeletedModSeq = 9
		err = tx.Update(&syncState)
		tcheck(t, err, "update syncstate")

		q := bstore.QueryTx[store.Message](tx)
		q.FilterNonzero(store.Message{Expunged: true})
		q.FilterLessEqual("ModSeq", syncState.HighestDeletedModSeq)
		n, err := q.Delete()
		tcheck(t, err, "delete history")
		if n != 2 {
			t.Fatalf("removed %d message history records, expected 2", n)
		}
		return nil
	})
	tcheck(t, err, "db write")

	// We should still get VANISHED EARLIER for 1,3, even though we don't have history for it.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("1,3")},
			tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)),
		)...,
	)

	// Similar with explicit UIDs.
	tc.transactf("ok", "Close")
	tc.transactf("ok", "Select inbox (Qresync (1 1 1:3))")
	tc.xuntagged(
		makeUntagged(
			imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("1,3")},
			tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)),
		)...,
	)

	// Fetch with changedsince also returns VANISHED EARLIER when we don't have history anymore.
	tc.transactf("ok", "uid fetch 1:3 flags (Changedsince 10)")
	tc.xuntagged() // We still have history, nothing changed.

	tc.transactf("ok", "uid fetch 1:3 flags (Changedsince 9)")
	tc.xuntagged(tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)))

	// Missing history, but no vanished requested.
	tc.transactf("ok", "uid fetch 1:4 flags (Changedsince 1)")
	tc.xuntagged(
		tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)),
	)

	// Same, but with vanished requested.
	tc.transactf("ok", "uid fetch 1:3 flags (Vanished Changedsince 10)")
	tc.xuntagged() // We still have history, nothing changed.

	tc.transactf("ok", "uid fetch 1:3 flags (Vanished Changedsince 9)")
	tc.xuntagged(tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)))

	// We return vanished for 1,3. Not for 4, since that is uidnext.
	tc.transactf("ok", "uid fetch 1:4 flags (Vanished Changedsince 1)")
	tc.xuntagged(
		tc.untaggedFetch(1, 2, imapclient.FetchFlags{`\Seen`}, imapclient.FetchModSeq(10)),
		imapclient.UntaggedVanished{Earlier: true, UIDs: xparseNumSet("1,3")},
	)
}
