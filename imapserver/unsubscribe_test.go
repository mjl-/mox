package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestUnsubscribe(t *testing.T) {
	tc := start(t, false)
	defer tc.close()

	tc2 := startNoSwitchboard(t, false)
	defer tc2.closeNoWait()

	tc.login("mjl@mox.example", password0)
	tc2.login("mjl@mox.example", password0)

	tc.transactf("bad", "unsubscribe")       // Missing param.
	tc.transactf("bad", "unsubscribe ")      // Missing param.
	tc.transactf("bad", "unsubscribe fine ") // Leftover data.

	tc.transactf("no", "unsubscribe a/b")        // Does not exist and is not subscribed.
	tc.transactf("ok", "unsubscribe expungebox") // Does not exist anymore but is still subscribed.
	tc.transactf("no", "unsubscribe expungebox") // Not subscribed.
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\NonExistent`}, Separator: '/', Mailbox: "expungebox"})

	tc.transactf("ok", "create a/b")
	tc2.transactf("ok", "noop")
	tc.transactf("ok", "unsubscribe a/b")
	tc.transactf("ok", "unsubscribe a/b") // Can unsubscribe even if there is no subscription.
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string(nil), Separator: '/', Mailbox: "a/b"})

	tc.transactf("ok", "subscribe a/b")
	tc.transactf("ok", "unsubscribe a/b")
}
