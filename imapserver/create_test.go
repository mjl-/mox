package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestCreate(t *testing.T) {
	testCreate(t, false)
}

func TestCreateUIDOnly(t *testing.T) {
	testCreate(t, true)
}

func testCreate(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()

	tc2 := startNoSwitchboard(t, uidonly)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc2.login("mjl@mox.example", password0)

	tc.transactf("no", "create inbox") // Already exists and not allowed. ../rfc/9051:1913
	tc.transactf("no", "create Inbox") // Idem.

	// Don't allow names that can cause trouble when exporting to directories.
	tc.transactf("no", "create .")
	tc.transactf("no", "create ..")
	tc.transactf("no", "create legit/..")
	tc.transactf("ok", "create ...") // No special meaning.

	// ../rfc/9051:1937
	tc.transactf("ok", "create inbox/a/c")
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a"}, imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a/c"})

	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "..."},
		imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a"},
		imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a/c"},
	)

	tc.transactf("no", "create inbox/a/c") // Exists.

	tc.transactf("ok", "create inbox/a/x")
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a/x"})

	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "Inbox/a/x"})

	// ../rfc/9051:1934
	tc.transactf("ok", "create mailbox/")
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "mailbox"})

	// OldName is only set for IMAP4rev2 or NOTIFY.
	tc.client.Enable(imapclient.CapIMAP4rev2)
	tc.transactf("ok", "create mailbox2/")
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "mailbox2", OldName: "mailbox2/"})

	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "mailbox"}, imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "mailbox2"})

	// If we are already subscribed, create should still work, and we still want to see the subscribed flag.
	tc.transactf("ok", "subscribe newbox")
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "newbox"})

	tc.transactf("ok", "create newbox")
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "newbox"})
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`}, Separator: '/', Mailbox: "newbox"})

	// todo: test create+delete+create of a name results in a higher uidvalidity.

	tc.transactf("no", "create /bad/root")
	tc.transactf("no", "create bad//root") // Cannot have internal duplicate slashes.
	tc.transactf("no", `create ""`)        // Refuse empty mailbox name.
	// We are not allowing special characters.
	tc.transactf("bad", `create "\n"`)
	tc.transactf("bad", `create "\x7f"`)
	tc.transactf("bad", `create "\x9f"`)
	tc.transactf("bad", `create "\u2028"`)
	tc.transactf("bad", `create "\u2029"`)
	tc.transactf("ok", `create "%%"`)
	tc.transactf("ok", `create "*"`)
	tc.transactf("no", `create "#"`) // Leading hash not allowed.
	tc.transactf("ok", `create "test#"`)

	// Create with flags.
	tc.transactf("no", `create "newwithflags" (use (\unknown))`)
	tc.transactf("no", `create "newwithflags" (use (\all))`)
	tc.transactf("ok", `create "newwithflags" (use (\archive))`)
	tc.transactf("ok", "noop")
	tc.xuntagged()
	tc.transactf("ok", `create "newwithflags2" (use (\archive) use (\drafts \sent))`)

	// UTF-7 checks are only for IMAP4 before rev2 and without UTF8=ACCEPT.
	tc.transactf("ok", `create "&"`)      // Interpreted as UTF-8, no UTF-7.
	tc2.transactf("bad", `create "&"`)    // Bad UTF-7.
	tc2.transactf("ok", `create "&Jjo-"`) // ☺, valid UTF-7.

	tc.transactf("ok", "create expungebox") // Existed in past.
	tc.transactf("ok", "delete expungebox") // Gone again.
}
