package imapserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
)

func TestIdle(t *testing.T) {
	tc1 := start(t)
	defer tc1.close()
	tc1.transactf("ok", "login mjl@mox.example testtest")

	tc2 := startNoSwitchboard(t)
	defer tc2.close()
	tc2.transactf("ok", "login mjl@mox.example testtest")

	tc1.transactf("ok", "select inbox")
	tc2.transactf("ok", "select inbox")

	// todo: test with delivery through smtp

	tc2.cmdf("", "idle")
	tc2.readprefixline("+ ")
	done := make(chan error)
	go func() {
		defer func() {
			x := recover()
			if x != nil {
				done <- fmt.Errorf("%v", x)
			}
		}()
		untagged, _ := tc2.client.ReadUntagged()
		var exists imapclient.UntaggedExists
		tuntagged(tc2.t, untagged, &exists)
		// todo: validate the data we got back.
		tc2.writelinef("done")
		done <- nil
	}()

	tc1.transactf("ok", "append inbox () {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		tc1.check(err, "idle")
	case <-timer.C:
		t.Fatalf("idle did not finish")
	}
}
