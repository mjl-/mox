package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestExpunge(t *testing.T) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Select("inbox")

	tc2.client.Login("mjl@mox.example", "testtest")
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
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.transactf("ok", "expunge") // Still nothing to remove.
	tc.xuntagged()

	tc.client.StoreFlagsAdd("1,3", true, `\Deleted`)

	tc2.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "expunge")
	tc.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(2))

	tc2.transactf("ok", "noop") // Drain.
	tc2.xuntagged(imapclient.UntaggedExpunge(1), imapclient.UntaggedExpunge(2))

	tc.transactf("ok", "expunge") // Nothing to remove anymore.
	tc.xuntagged()

	// Only UID 2 is still left. We'll add 3 more. Getting us to UIDs 2,4,5,6.
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))

	tc.transactf("bad", "uid expunge")            // Missing uid set.
	tc.transactf("bad", "uid expunge 1 leftover") // Leftover data.
	tc.transactf("bad", "uid expunge 1 leftover") // Leftover data.

	tc.client.StoreFlagsAdd("1,2,4", true, `\Deleted`) // Marks UID 2,4,6 as deleted.

	tc.transactf("ok", "uid expunge 1")
	tc.xuntagged() // No match.

	tc2.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "uid expunge 4:6") // Removes UID 4,6 at seqs 2,4.
	tc.xuntagged(imapclient.UntaggedExpunge(2), imapclient.UntaggedExpunge(3))

	tc2.transactf("ok", "noop")
	tc.xuntagged(imapclient.UntaggedExpunge(2), imapclient.UntaggedExpunge(3))
}
