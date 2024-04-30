package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestStatus(t *testing.T) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	tc.transactf("bad", "status")                      // Missing param.
	tc.transactf("bad", "status inbox")                // Missing param.
	tc.transactf("bad", "status inbox ()")             // At least one attribute required.
	tc.transactf("bad", "status inbox (uidvalidity) ") // Leftover data.
	tc.transactf("bad", "status inbox (unknown)")      // Unknown attribute.

	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")
	tc.xuntagged(imapclient.UntaggedStatus{
		Mailbox: "Inbox",
		Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 0,
			imapclient.StatusUIDValidity: 1,
			imapclient.StatusUIDNext:     1,
			imapclient.StatusUnseen:      0,
			imapclient.StatusDeleted:     0,
			imapclient.StatusSize:        0,
			imapclient.StatusRecent:      0,
			imapclient.StatusAppendLimit: 0,
		},
	})

	// Again, now with a message in the mailbox.
	tc.transactf("ok", "append inbox {4+}\r\ntest")
	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")

	tc.xuntagged(imapclient.UntaggedStatus{
		Mailbox: "Inbox",
		Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1,
			imapclient.StatusUIDValidity: 1,
			imapclient.StatusUIDNext:     2,
			imapclient.StatusUnseen:      1,
			imapclient.StatusDeleted:     0,
			imapclient.StatusSize:        4,
			imapclient.StatusRecent:      0,
			imapclient.StatusAppendLimit: 0,
		},
	})

	tc.client.Select("inbox")
	tc.client.StoreFlagsSet("1", true, `\Deleted`)
	tc.transactf("ok", "status inbox (messages uidnext uidvalidity unseen deleted size recent appendlimit)")
	tc.xuntagged(imapclient.UntaggedStatus{
		Mailbox: "Inbox",
		Attrs: map[imapclient.StatusAttr]int64{imapclient.StatusMessages: 1,
			imapclient.StatusUIDValidity: 1,
			imapclient.StatusUIDNext:     2,
			imapclient.StatusUnseen:      1,
			imapclient.StatusDeleted:     1,
			imapclient.StatusSize:        4,
			imapclient.StatusRecent:      0,
			imapclient.StatusAppendLimit: 0,
		},
	})

}
