package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

// todo: check that UIDValidity is indeed updated properly.
func TestRename(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc2.client.Login("mjl@mox.example", "testtest")

	tc.transactf("bad", "rename")      // Missing parameters.
	tc.transactf("bad", "rename x")    // Missing destination.
	tc.transactf("bad", "rename x y ") // Leftover data.

	tc.transactf("no", "rename doesnotexist newbox") // Does not exist.
	tc.xcode("NONEXISTENT")                          // ../rfc/9051:5140
	tc.transactf("no", `rename "Sent" "Trash"`)      // Already exists.
	tc.xcode("ALREADYEXISTS")

	tc.client.Create("x")
	tc.client.Subscribe("sub")
	tc.client.Create("a/b/c")
	tc.client.Subscribe("x/y/c") // For later rename, but not affected by rename of x.
	tc2.transactf("ok", "noop")  // Drain.

	tc.transactf("ok", "rename x y")
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Separator: '/', Mailbox: "y", OldName: "x"})

	// Rename to a mailbox that only exists in database as subscribed.
	tc.transactf("ok", "rename y sub")
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "sub", OldName: "y"})

	// Cannot rename a child to a parent. It already exists.
	tc.transactf("no", "rename a/b/c a/b")
	tc.xcode("ALREADYEXISTS")
	tc.transactf("no", "rename a/b a")
	tc.xcode("ALREADYEXISTS")

	tc2.transactf("ok", "noop")          // Drain.
	tc.transactf("ok", "rename a/b x/y") // This will cause new parent "x" to be created, and a/b and a/b/c to be renamed.
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "x"}, imapclient.UntaggedList{Separator: '/', Mailbox: "x/y", OldName: "a/b"}, imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "x/y/c", OldName: "a/b/c"})

	tc.client.Create("k/l")
	tc.transactf("ok", "rename k/l k/l/m") // With "l" renamed, a new "k" will be created.
	tc.transactf("ok", `list "" "k*" return (subscribed)`)
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "k"}, imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "k/l"}, imapclient.UntaggedList{Separator: '/', Mailbox: "k/l/m"})

	// Similar, but with missing parent not subscribed.
	tc.transactf("ok", "rename k/l/m k/ll")
	tc.transactf("ok", "delete k/l")
	tc.transactf("ok", "rename k/ll k/l") // Restored to previous mailboxes now.
	tc.client.Unsubscribe("k")
	tc.transactf("ok", "rename k/l k/l/m") // With "l" renamed, a new "k" will be created.
	tc.transactf("ok", `list "" "k*" return (subscribed)`)
	tc.xuntagged(imapclient.UntaggedList{Separator: '/', Mailbox: "k"}, imapclient.UntaggedList{Flags: []string{"\\Subscribed"}, Separator: '/', Mailbox: "k/l"}, imapclient.UntaggedList{Separator: '/', Mailbox: "k/l/m"})

	// Renaming inbox keeps inbox in existence, moves messages, and does not rename children.
	tc.transactf("ok", "create inbox/a")
	// To check if UIDs are renumbered properly, we add UIDs 1 and 2. Expunge 1,
	// keeping only 2. Then rename the inbox, which should renumber UID 2 in the old
	// inbox to UID 1 in the newly created mailbox.
	tc.transactf("ok", "append inbox (\\deleted) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.transactf("ok", "append inbox (label1) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tc.transactf("ok", `select inbox`)
	tc.transactf("ok", "expunge")
	tc.transactf("ok", "rename inbox minbox")
	tc.transactf("ok", `list "" (inbox inbox/a minbox)`)
	tc.xuntagged(imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox"}, imapclient.UntaggedList{Separator: '/', Mailbox: "Inbox/a"}, imapclient.UntaggedList{Separator: '/', Mailbox: "minbox"})
	tc.transactf("ok", `select minbox`)
	tc.transactf("ok", `uid fetch 1:* flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1), imapclient.FetchFlags{"label1"}}})

	// Renaming to new hiearchy that does not have any subscribes.
	tc.transactf("ok", "rename minbox w/w")
	tc.transactf("ok", `list "" "w*"`)
	tc.xuntagged(imapclient.UntaggedList{Separator: '/', Mailbox: "w"}, imapclient.UntaggedList{Separator: '/', Mailbox: "w/w"})

	// todo: test create+delete+rename of/to a name results in a higher uidvalidity.
}
