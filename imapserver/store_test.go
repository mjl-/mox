package imapserver

import (
	"strings"
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestStore(t *testing.T) {
	testStore(t, false)
}

func TestStoreUIDOnly(t *testing.T) {
	testStore(t, true)
}

func testStore(t *testing.T, uidonly bool) {
	tc := start(t, uidonly)
	defer tc.close()

	tc.login("mjl@mox.example", password0)
	tc.client.Enable(imapclient.CapIMAP4rev2)

	tc.client.Append("inbox", makeAppend(exampleMsg))
	tc.client.Select("inbox")

	noflags := imapclient.FetchFlags(nil)

	if !uidonly {
		tc.transactf("ok", "store 1 flags.silent ()")
		tc.xuntagged()
	}

	tc.transactf("ok", `uid store 1 flags ()`)
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags))
	tc.transactf("ok", `uid fetch 1 flags`)
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags))

	tc.transactf("ok", `uid store 1 flags.silent (\Seen)`)
	tc.xuntagged()
	tc.transactf("ok", `uid fetch 1 flags`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Seen`}))

	tc.transactf("ok", `uid store 1 flags ($Junk)`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`$Junk`}))
	tc.transactf("ok", `uid fetch 1 flags`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`$Junk`}))

	tc.transactf("ok", `uid store 1 +flags ()`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`$Junk`}))
	tc.transactf("ok", `uid store 1 +flags (\Deleted)`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Deleted`, `$Junk`}))
	tc.transactf("ok", `uid fetch 1 flags`)
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{`\Deleted`, `$Junk`}))

	tc.transactf("ok", `uid store 1 -flags \Deleted $Junk`)
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags))
	tc.transactf("ok", `uid fetch 1 flags`)
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags))

	if !uidonly {
		tc.transactf("bad", "store 2 flags ()") // ../rfc/9051:7018
	}

	tc.transactf("ok", "uid store 1 flags ()")
	tc.xuntagged(tc.untaggedFetch(1, 1, noflags))

	tc.transactf("ok", "uid store 1 flags (new)") // New flag.
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"new"}))
	tc.transactf("ok", "uid store 1 flags (new new a b c)") // Duplicates are ignored.
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"a", "b", "c", "new"}))
	tc.transactf("ok", "uid store 1 +flags (new new c d e)")
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"a", "b", "c", "d", "e", "new"}))
	tc.transactf("ok", "uid store 1 -flags (new new e a c)")
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"b", "d"}))
	tc.transactf("ok", "uid store 1 flags ($Forwarded Different)")
	tc.xuntagged(tc.untaggedFetch(1, 1, imapclient.FetchFlags{"$Forwarded", "different"}))

	tc.transactf("bad", "store")          // Need numset, flags and args.
	tc.transactf("bad", "store 1")        // Need flags.
	tc.transactf("bad", "store 1 +")      // Need flags.
	tc.transactf("bad", "store 1 -")      // Need flags.
	tc.transactf("bad", "store 1 flags ") // Need flags.
	tc.transactf("bad", "store 1 flags ") // Need flags.

	tc.client.Unselect()
	tc.transactf("ok", "examine inbox") // Open read-only.

	// Flags are added to mailbox, not removed.
	flags := strings.Split(`\Seen \Answered \Flagged \Deleted \Draft $Forwarded $Junk $NotJunk $Phishing $MDNSent a b c d different e new`, " ")
	tc.xuntaggedOpt(false, imapclient.UntaggedFlags(flags))

	tc.transactf("no", `uid store 1 flags ()`) // No permission to set flags.
}
