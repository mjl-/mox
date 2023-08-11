package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestStatus(t *testing.T) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")

	tc.transactf("bad", "status")                      // Missing param.
	tc.transactf("bad", "status inbox")                // Missing param.
	tc.transactf("bad", "status inbox ()")             // At least one attribute required.
	tc.transactf("bad", "status inbox (uidvalidity) ") // Leftover data.
	tc.transactf("bad", "status inbox (unknown)")      // Unknown attribute.

	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"MESSAGES": 0, "UIDVALIDITY": 1, "UIDNEXT": 1, "UNSEEN": 0, "DELETED": 0, "SIZE": 0, "RECENT": 0, "APPENDLIMIT": 0}})

	// Again, now with a message in the mailbox.
	tc.transactf("ok", "append inbox {4+}\r\ntest")
	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"MESSAGES": 1, "UIDVALIDITY": 1, "UIDNEXT": 2, "UNSEEN": 1, "DELETED": 0, "SIZE": 4, "RECENT": 0, "APPENDLIMIT": 0}})

	tc.client.Select("inbox")
	tc.client.StoreFlagsSet("1", true, `\Deleted`)
	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"MESSAGES": 1, "UIDVALIDITY": 1, "UIDNEXT": 2, "UNSEEN": 1, "DELETED": 1, "SIZE": 4, "RECENT": 0, "APPENDLIMIT": 0}})
}
