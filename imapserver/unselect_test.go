package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestUnselect(t *testing.T) {
	testUnselect(t, false)
}

func TestUnselectUIDOnly(t *testing.T) {
	testUnselect(t, true)
}

func testUnselect(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc.transactf("bad", "unselect bogus") // Leftover data.
	tc.transactf("ok", "unselect")
	tc.transactf("no", "fetch 1 all") // Invalid when not selected.

	tc.client.Select("inbox")
	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.UIDStoreFlagsAdd("1", true, `\Deleted`)
	tc.transactf("ok", "unselect")
	tc.transactf("ok", "status inbox (messages)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1}}) // Message not removed.
}
