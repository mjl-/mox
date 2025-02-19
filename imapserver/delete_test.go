package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestDelete(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.close()

	tc3 := startNoSwitchboard(t)
	defer tc3.close()

	tc.client.Login("mjl@mox.example", password0)
	tc2.client.Login("mjl@mox.example", password0)
	tc3.client.Login("mjl@mox.example", password0)

	tc.transactf("bad", "delete")              // Missing mailbox.
	tc.transactf("no", "delete inbox")         // Cannot delete inbox.
	tc.transactf("no", "delete nonexistent")   // Cannot delete mailbox that does not exist.
	tc.transactf("no", `delete "nonexistent"`) // Again, with quoted string syntax.

	tc.client.Subscribe("x")
	tc.transactf("no", "delete x") // Subscription does not mean there is a mailbox that can be deleted.

	tc.client.Create("a/b", nil)
	tc2.transactf("ok", "noop") // Drain changes.
	tc3.transactf("ok", "noop")

	// ../rfc/9051:2000
	tc.transactf("no", "delete a") // Still has child.
	tc.xcode("HASCHILDREN")

	tc3.client.Enable("IMAP4rev2") // For \NonExistent support.
	tc.transactf("ok", "delete a/b")
	tc2.transactf("ok", "noop")
	tc2.xuntagged() // No IMAP4rev2, no \NonExistent.
	tc3.transactf("ok", "noop")
	tc3.xuntagged(imapclient.UntaggedList{Flags: []string{`\NonExistent`}, Separator: '/', Mailbox: "a/b"})

	tc.transactf("no", "delete a/b") // Already removed.
	tc.transactf("ok", "delete a")   // Parent can now be removed.
	tc.transactf("ok", `list (subscribed) "" (a/b a) return (subscribed)`)
	// Subscriptions still exist.
	tc.xuntagged(
		imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "a"},
		imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "a/b"},
	)

	// Let's try again with a message present.
	tc.client.Create("msgs", nil)
	tc.client.Append("msgs", nil, nil, []byte(exampleMsg))
	tc.transactf("ok", "delete msgs")

	// Delete for inbox/* is allowed.
	tc.client.Create("inbox/a", nil)
	tc.transactf("ok", "delete inbox/a")

}
