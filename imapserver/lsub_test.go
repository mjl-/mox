package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestLsub(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	tc.transactf("bad", "lsub")       // Missing params.
	tc.transactf("bad", `lsub ""`)    // Missing param.
	tc.transactf("bad", `lsub "" x `) // Leftover data.

	tc.transactf("ok", `lsub "" x*`)
	tc.xuntagged()

	tc.transactf("ok", "create a/b/c")
	tc.transactf("ok", `lsub "" a/*`)
	tc.xuntagged(imapclient.UntaggedLsub{Separator: '/', Mailbox: "a/b"}, imapclient.UntaggedLsub{Separator: '/', Mailbox: "a/b/c"})

	// ../rfc/3501:2394
	tc.transactf("ok", "unsubscribe a")
	tc.transactf("ok", "unsubscribe a/b")
	tc.transactf("ok", `lsub "" a/%%`)
	tc.xuntagged(imapclient.UntaggedLsub{Flags: []string{`\NoSelect`}, Separator: '/', Mailbox: "a/b"})

	tc.transactf("ok", "unsubscribe a/b/c")
	tc.transactf("ok", `lsub "" a/%%`)
	tc.xuntagged()
}
