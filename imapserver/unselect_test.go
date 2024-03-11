package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestUnselect(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)
	tc.client.Select("inbox")

	tc.transactf("bad", "unselect bogus") // Leftover data.
	tc.transactf("ok", "unselect")
	tc.transactf("no", "fetch 1 all") // Invalid when not selected.

	tc.client.Select("inbox")
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.StoreFlagsAdd("1", true, `\Deleted`)
	tc.transactf("ok", "unselect")
	tc.transactf("ok", "status inbox (messages)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1}}) // Message not removed.
}
