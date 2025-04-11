package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestExpunge(t *testing.T) {
	testExpunge(t, false)
}

func TestExpungeUIDOnly(t *testing.T) {
	testExpunge(t, true)
}

func testExpunge(t *testing.T, uidonly bool) {
	defer mockUIDValidity()()
	tc := start(t, uidonly)
	defer tc.close()

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc2.login("mjl@mox.example", password0)
	tc2.client.Select("inbox")

	tc.transactf("bad", "expunge leftover") // Leftover data.
	tc.transactf("ok", "expunge")           // Nothing to remove though.
	tc.xuntagged()

	tc.client.Unselect()
	tc.client.Examine("inbox")
	tc.transactf("no", "expunge")       // Read-only.
	tc.transactf("no", "uid expunge 1") // Read-only.

	tc.client.Unselect()
	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.transactf("ok", "expunge") // Still nothing to remove.
	tc.xuntagged()

	tc.transactf("ok", `uid store 1,3 +flags.silent \Deleted`)

	tc2.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "expunge")
	if uidonly {
		tc.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("1,3")})
	} else {
		tc.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(2))
	}

	tc2.transactf("ok", "noop") // Drain.
	if uidonly {
		tc2.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("1,3")})
	} else {
		tc2.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(2))
	}

	tc.transactf("ok", "expunge") // Nothing to remove anymore.
	tc.xuntagged()

	// Only UID 2 is still left. We'll add 3 more. Getting us to UIDs 2,4,5,6.
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Append("inbox", makeAppend(exampleMsg))

	tc.transactf("bad", "uid expunge")            // Missing uid set.
	tc.transactf("bad", "uid expunge 1 leftover") // Leftover data.
	tc.transactf("bad", "uid expunge 1 leftover") // Leftover data.

	tc.transactf("ok", `uid store 2,4,6 +flags.silent \Deleted`)

	tc.transactf("ok", "uid expunge 1")
	tc.xuntagged() // No match.

	tc2.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "uid expunge 4:6") // Removes UID 4,6 at seqs 2,4.
	if uidonly {
		tc.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("4,6")})
	} else {
		tc.xuntagged(imapclient.UntaggedExpunge(2), imapclient.UntaggedExpunge(3))
	}

	tc2.transactf("ok", "noop")
	if uidonly {
		tc2.xuntagged(imapclient.UntaggedVanished{UIDs: xparseNumSet("4,6")})
	} else {
		tc2.xuntagged(imapclient.UntaggedExpunge(2), imapclient.UntaggedExpunge(3))
	}
}
