package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestMove(t *testing.T) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.closeNoWait()

	tc3 := startNoSwitchboard(t)
	defer tc3.closeNoWait()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc2.client.Login("mjl@mox.example", password0)
	tc2.client.Select("Trash")

	tc3.client.Login("mjl@mox.example", password0)
	tc3.client.Select("inbox")

	tc.transactf("bad", "move")          // Missing params.
	tc.transactf("bad", "move 1")        // Missing params.
	tc.transactf("bad", "move 1 inbox ") // Leftover.

	// Seqs 1,2 and UIDs 3,4.
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.StoreFlagsSet("1:2", true, `\Deleted`)
	tc.client.Expunge()
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))

	tc.client.Unselect()
	tc.client.Examine("inbox")
	tc.transactf("no", "move 1 Trash") // Opened readonly.
	tc.client.Unselect()
	tc.client.Select("inbox")

	tc.transactf("no", "move 1 nonexistent")
	tc.xcode("TRYCREATE")

	tc.transactf("no", "move 1 expungebox")
	tc.xcode("TRYCREATE")

	tc.transactf("no", "move 1 inbox") // Cannot move to same mailbox.

	tc2.transactf("ok", "noop") // Drain.
	tc3.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "move 1:* Trash")
	ptr := func(v uint32) *uint32 { return &v }
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", RespText: imapclient.RespText{Code: "COPYUID", CodeArg: imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 3, Last: ptr(4)}}, To: []imapclient.NumRange{{First: 1, Last: ptr(2)}}}, More: "moved"}},
		imapclient.UntaggedExpunge(1),
		imapclient.UntaggedExpunge(1),
	)
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(2),
		imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1), imapclient.FetchFlags(nil)}},
		imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(2), imapclient.FetchFlags(nil)}},
	)
	tc3.transactf("ok", "noop")
	tc3.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1))

	// UIDs 5,6
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc2.transactf("ok", "noop") // Drain.
	tc3.transactf("ok", "noop") // Drain.

	tc.transactf("no", "uid move 1:4 Trash") // No match.
	tc.transactf("ok", "uid move 6:5 Trash")
	tc.xuntagged(
		imapclient.UntaggedResult{Status: "OK", RespText: imapclient.RespText{Code: "COPYUID", CodeArg: imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 5, Last: ptr(6)}}, To: []imapclient.NumRange{{First: 3, Last: ptr(4)}}}, More: "moved"}},
		imapclient.UntaggedExpunge(1),
		imapclient.UntaggedExpunge(1),
	)
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(4),
		imapclient.UntaggedFetch{Seq: 3, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(3), imapclient.FetchFlags(nil)}},
		imapclient.UntaggedFetch{Seq: 4, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(4), imapclient.FetchFlags(nil)}},
	)
	tc3.transactf("ok", "noop")
	tc3.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(1))
}
