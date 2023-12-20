package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestCopy(t *testing.T) {
	defer mockUIDValidity()()
	tc := start(t)
	defer tc.close()

	tc2 := startNoSwitchboard(t)
	defer tc2.close()

	tc.client.Login("mjl@mox.example", "testtest")
	tc.client.Select("inbox")

	tc2.client.Login("mjl@mox.example", "testtest")
	tc2.client.Select("Trash")

	tc.transactf("bad", "copy")          // Missing params.
	tc.transactf("bad", "copy 1")        // Missing params.
	tc.transactf("bad", "copy 1 inbox ") // Leftover.

	// Seqs 1,2 and UIDs 3,4.
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.StoreFlagsSet("1:2", true, `\Deleted`)
	tc.client.Expunge()
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))
	tc.client.Append("inbox", nil, nil, []byte(exampleMsg))

	tc.transactf("no", "copy 1 nonexistent")
	tc.xcode("TRYCREATE")

	tc.transactf("no", "copy 1 inbox") // Cannot copy to same mailbox.

	tc2.transactf("ok", "noop") // Drain.

	tc.transactf("ok", "copy 1:* Trash")
	ptr := func(v uint32) *uint32 { return &v }
	tc.xcodeArg(imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 3, Last: ptr(4)}}, To: []imapclient.NumRange{{First: 1, Last: ptr(2)}}})
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(2),
		imapclient.UntaggedFetch{Seq: 1, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(1), imapclient.FetchFlags(nil)}},
		imapclient.UntaggedFetch{Seq: 2, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(2), imapclient.FetchFlags(nil)}},
	)

	tc.transactf("no", "uid copy 1,2 Trash") // No match.
	tc.transactf("ok", "uid copy 4,3 Trash")
	tc.xcodeArg(imapclient.CodeCopyUID{DestUIDValidity: 1, From: []imapclient.NumRange{{First: 3, Last: ptr(4)}}, To: []imapclient.NumRange{{First: 3, Last: ptr(4)}}})
	tc2.transactf("ok", "noop")
	tc2.xuntagged(
		imapclient.UntaggedExists(4),
		imapclient.UntaggedFetch{Seq: 3, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(3), imapclient.FetchFlags(nil)}},
		imapclient.UntaggedFetch{Seq: 4, Attrs: []imapclient.FetchAttr{imapclient.FetchUID(4), imapclient.FetchFlags(nil)}},
	)

	tclimit := startArgs(t, false, false, true, true, "limit")
	defer tclimit.close()
	tclimit.client.Login("limit@mox.example", "testtest")
	tclimit.client.Select("inbox")
	// First message of 1 byte is within limits.
	tclimit.transactf("ok", "append inbox (\\Seen Label1 $label2) \" 1-Jan-2022 10:10:00 +0100\" {1+}\r\nx")
	tclimit.xuntagged(imapclient.UntaggedExists(1))
	// Second message would take account past limit.
	tclimit.transactf("no", "copy 1:* Trash")
	tclimit.xcode("OVERQUOTA")
}
