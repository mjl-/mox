package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestMove(t *testing.T) {
	testMove(t, false)
}

func TestMoveUIDOnly(t *testing.T) {
	testMove(t, true)
}

func testMove(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()

	tc3 := startNoSwitchboard(t, uidonly)
	defer tc3.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("Trash")

	tc3.login("mjl@mox.example", password0)
	tc3.client.Select("inbox")

	tc.transactf("bad", "move")          // Missing params.
	tc.transactf("bad", "move 1")        // Missing params.
	tc.transactf("bad", "move 1 inbox ") // Leftover.

	// Seqs 1,2 and UIDs 3,4.
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.UIDStoreFlagsSet("1:2", true, `\Deleted`)
	tc.client.Expunge()
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))

	if uidonly {
		tc.transactf("ok", "uid move 1:* Trash")
	} else {
		tc.client.Unselect()
		tc.client.Examine("inbox")
		tc.transactf("no", "move 1 Trash") // Opened readonly.
		tc.client.Unselect()
		tc.client.Select("inbox")

		tc.transactf("no", "move 1 nonexistent")
		tc.xcodeWord("TRYCREATE")

		tc.transactf("no", "move 1 expungebox")
		tc.xcodeWord("TRYCREATE")

		tc.transactf("no", "move 1 inbox") // Cannot move to same mailbox.

		tc2.transactf("ok", "noop") // Drain.
		tc3.transactf("ok", "noop") // Drain.

		tc.transactf("ok", "move 1:* Trash")
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 3, Last: uint32ptr(4)}}, To: []imapclient.NumRange{{First: 1, Last: uint32ptr(2)}}}, Text: "moved"},
			imapclient.UntaggedExpunge(1),
			imapclient.UntaggedExpunge(1),
		)
		tc2.transactf("ok", "noop")
		tc2.xuntagged(
			imapclient.UntaggedExists(2),
			tc.untaggedFetch(1, 1, imapclient.FetchFlags(nil)),
			tc.untaggedFetch(2, 2, imapclient.FetchFlags(nil)),
		)
		tc3.transactf("ok", "noop")
		tc3.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1))
	}

	// UIDs 5,6
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc2.transactf("ok", "noop") // Drain.
	tc3.transactf("ok", "noop") // Drain.

	tc.transactf("no", "uid move 1:4 Trash") // No match.
	tc.transactf("ok", "uid move 6:5 Trash")
	if uidonly {
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 5, Last: uint32ptr(6)}}, To: []imapclient.NumRange{{First: 3, Last: uint32ptr(4)}}}, Text: "moved"},
			imapclient.UntaggedVanished{UIDs: xparseNumSet("5:6")},
		)
	} else {
		tc.xuntagged(
			imapclient.UntaggedResult{Status: "OK", Code: imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 5, Last: uint32ptr(6)}}, To: []imapclient.NumRange{{First: 3, Last: uint32ptr(4)}}}, Text: "moved"},
			imapclient.UntaggedExpunge(1),
			imapclient.UntaggedExpunge(1),
		)
	}
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(4),
		tc2.untaggedFetch(3, 3, imapclient.FetchFlags(nil)),
		tc2.untaggedFetch(4, 4, imapclient.FetchFlags(nil)),
	)
	tc3.transactf("ok", "noop")
	if uidonly {
		tc3.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("5:6")})
	} else {
		tc3.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1))
	}
}
