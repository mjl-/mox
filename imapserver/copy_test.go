package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestCopy(t *testing.T) {
	testCopy(t, false)
}

func TestCopyUIDOnly(t *testing.T) {
	testCopy(t, true)
}

func testCopy(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("Trash")

	tc.transactf("bad", "copy")          // Missing params.
	tc.transactf("bad", "copy 1")        // Missing params.
	tc.transactf("bad", "copy 1 inbox ") // Leftover.

	// Seqs 1,2 and UIDs 3,4.
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.transactf("ok", `Uid Store 1:2 +Flags.Silent (\Deleted)`)
	tc.client.Expunge()
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))

	if uidonly {
		tc.transactf("ok", "uid copy 3:* Trash")
	} else {
		tc.transactf("no", "copy 1 nonexistent")
		tc.xcodeWord("TRYCREATE")
		tc.transactf("no", "copy 1 expungebox")
		tc.xcodeWord("TRYCREATE")

		tc.transactf("no", "copy 1 inbox") // Cannot copy to same mailbox.

		tc2.transactf("ok", "noop") // Drain.

		tc.transactf("ok", "copy 1:* Trash")
		tc.xcode(mustParseCode("COPYUID 1 3:4 1:2"))
	}
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(2),
		tc2.untaggedFetch(1, 1, imapclient.FetchFlags(nil)),
		tc2.untaggedFetch(2, 2, imapclient.FetchFlags(nil)),
	)

	tc.transactf("no", "uid copy 1,2 Trash") // No match.
	tc.transactf("ok", "uid copy 4,3 Trash")
	tc.xcode(mustParseCode("COPYUID 1 3:4 3:4"))
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(4),
		tc2.untaggedFetch(3, 3, imapclient.FetchFlags(nil)),
		tc2.untaggedFetch(4, 4, imapclient.FetchFlags(nil)),
	)

	tclimit := startArgs(t, uidonly, false, false, true, true, "limit")
	defer tclimit.close()
	tclimit.login("limit@mox.example", password0)
	tclimit.client.Select("inbox")
	// First message of 1 byte is within limits.
	tclimit.transactf("ok", "append inbox (\\Seen Label1 $label2) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tclimit.xuntagged(imapclient.UntaggedExists(1))
	// Second message would take account past limit.
	tclimit.transactf("no", "uid copy 1:* Trash")
	tclimit.xcodeWord("OVERQUOTA")
}
