package imapserver

import (
	"testing"
)

func TestUnsubscribe(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	tc.transactf("bad", "unsubscribe")       // Missing param.
	tc.transactf("bad", "unsubscribe ")      // Missing param.
	tc.transactf("bad", "unsubscribe fine ") // Leftover data.

	tc.transactf("no", "unsubscribe a/b")        // Does not exist and is not subscribed.
	tc.transactf("ok", "unsubscribe expungebox") // Does not exist anymore but is still subscribed.
	tc.transactf("no", "unsubscribe expungebox") // Not subscribed.
	tc.transactf("ok", "create a/b")
	tc.transactf("ok", "unsubscribe a/b")
	tc.transactf("ok", "unsubscribe a/b") // Can unsubscribe even if there is no subscription.
	tc.transactf("ok", "subscribe a/b")
	tc.transactf("ok", "unsubscribe a/b")
}
