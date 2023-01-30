package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestStore(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Enable("imap4rev2")

	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Select("inbox")

	uid1 := imapclient.FetchUID(1)
	noflags := imapclient.FetchFlags(nil)

	tc.transactf("ok", "store 1 flags.silent ()")
	tc.xuntagged()

	tc.transactf("ok", `store 1 flags ()`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})
	tc.transactf("ok", `fetch 1 flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})

	tc.transactf("ok", `store 1 flags.silent (\Seen)`)
	tc.xuntagged()
	tc.transactf("ok", `fetch 1 flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`\Seen`}}})

	tc.transactf("ok", `store 1 flags ($Junk)`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`$Junk`}}})
	tc.transactf("ok", `fetch 1 flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`$Junk`}}})

	tc.transactf("ok", `store 1 +flags ()`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`$Junk`}}})
	tc.transactf("ok", `store 1 +flags (\Deleted)`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`\Deleted`, `$Junk`}}})
	tc.transactf("ok", `fetch 1 flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, imapclient.FetchFlags{`\Deleted`, `$Junk`}}})

	tc.transactf("ok", `store 1 -flags \Deleted $Junk`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})
	tc.transactf("ok", `fetch 1 flags`)
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})

	tc.transactf("bad", "store 2 flags ()") // ../rfc/9051:7018

	tc.transactf("ok", "uid store 1 flags ()")
	tc.xuntagged(imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{uid1, noflags}})

	tc.transactf("bad", "store")                 // Need numset, flags and args.
	tc.transactf("bad", "store 1")               // Need flags.
	tc.transactf("bad", "store 1 +")             // Need flags.
	tc.transactf("bad", "store 1 -")             // Need flags.
	tc.transactf("bad", "store 1 flags ")        // Need flags.
	tc.transactf("bad", "store 1 flags ")        // Need flags.
	tc.transactf("bad", "store 1 flags (bogus)") // Unknown flag.

	tc.client.Unselect()
	tc.client.Examine("inbox")             // Open read-only.
	tc.transactf("no", `store 1 flags ()`) // No permission to set flags.
}
