package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestSubscribe(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc2.client.Login("mjl@mox.example", "testtest")

	tc.transactf("bad", "subscribe")       // Missing param.
	tc.transactf("bad", "subscribe ")      // Missing param.
	tc.transactf("bad", "subscribe fine ") // Leftover data.

	tc.transactf("ok", "subscribe a/b")
	tc2.transactf("ok", "noop")
	tc2.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "a/b"})
	tc.transactf("ok", "subscribe a/b") // Already subscribed, which is fine.
	tc2.transactf("ok", "noop")
	tc2.xuntagged() // But no new changes.

	tc.transactf("ok", `list (subscribed) "" "a*" return (subscribed)`)
	tc.xuntagged(imapclient.UntaggedList{Flags: []string{`\Subscribed`, `\NonExistent`}, Separator: '/', Mailbox: "a/b"})
}
