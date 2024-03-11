package imapserver

import (
	"testing"

	"github.com/mjl-/mox/imapclient"
)

func TestQuota1(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	// We don't implement setquota.
	tc.transactf("bad", `setquota "" (STORAGE 123)`)

	tc.transactf("bad", "getquotaroot")             // Missing param.
	tc.transactf("bad", "getquotaroot inbox bogus") // Too many params.

	tc.transactf("bad", "getquota")     // Missing param.
	tc.transactf("bad", "getquota a b") // Too many params.

	// tc does not have a limit.
	tc.transactf("ok", "getquotaroot inbox")
	tc.xuntagged(imapclient.UntaggedQuotaroot([]string{""}))

	tc.transactf("no", "getquota bogusroot")
	tc.transactf("ok", `getquota ""`)
	tc.xuntagged()

	// Check that we get a DELETED-STORAGE status attribute with value 0, also if
	// messages are marked deleted. We don't go through the trouble.
	tc.transactf("ok", "status inbox (DELETED-STORAGE)")
	tc.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"DELETED-STORAGE": 0}})

	// tclimit does have a limit.
	tclimit := startArgs(t, false, false, true, true, "limit")
	defer tclimit.close()

	tclimit.client.Login("limit@mox.example", password0)

	tclimit.transactf("ok", "getquotaroot inbox")
	tclimit.xuntagged(
		imapclient.UntaggedQuotaroot([]string{""}),
		imapclient.UntaggedQuota{Root: "", Resources: []imapclient.QuotaResource{{Name: imapclient.QuotaResourceStorage, Usage: 0, Limit: 1}}},
	)

	tclimit.transactf("ok", `getquota ""`)
	tclimit.xuntagged(imapclient.UntaggedQuota{Root: "", Resources: []imapclient.QuotaResource{{Name: imapclient.QuotaResourceStorage, Usage: 0, Limit: 1}}})

	tclimit.transactf("ok", "status inbox (DELETED-STORAGE)")
	tclimit.xuntagged(imapclient.UntaggedStatus{Mailbox: "Inbox", Attrs: map[string]int64{"DELETED-STORAGE": 0}})
}
