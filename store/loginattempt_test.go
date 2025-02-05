package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/mox/mox-"
)

func TestLoginAttempt(t *testing.T) {
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)

	xctx, xcancel := context.WithCancel(ctxbg)
	err := Init(xctx)
	tcheck(t, err, "store init")
	// Stop the background LoginAttempt writer for synchronous tests.
	xcancel()
	<-writeLoginAttemptStopped
	defer func() {
		err := Close()
		tcheck(t, err, "store close")
	}()

	a1 := LoginAttempt{
		Last:        time.Now(),
		First:       time.Now(),
		AccountName: "mjl1",
		UserAgent:   "0", // "0" so we update instead of insert when testing automatic cleanup below.
		Result:      AuthError,
	}
	a2 := a1
	a2.AccountName = "mjl2"
	a3 := a1
	a3.AccountName = "mjl3"
	a3.Last = a3.Last.Add(-31 * 24 * time.Hour) // Will be cleaned up.
	a3.First = a3.Last
	LoginAttemptAdd(ctxbg, pkglog, a1)
	LoginAttemptAdd(ctxbg, pkglog, a2)
	LoginAttemptAdd(ctxbg, pkglog, a3)

	// Ensure there are no LoginAttempts that still need to be written.
	loginAttemptDrain := func() {
		for {
			select {
			case la := <-writeLoginAttempt:
				loginAttemptWrite(la)
			default:
				return
			}
		}
	}

	loginAttemptDrain()

	l, err := LoginAttemptList(ctxbg, "", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 3)

	// Test limit.
	l, err = LoginAttemptList(ctxbg, "", 2)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 2)

	// Test account filter.
	l, err = LoginAttemptList(ctxbg, "mjl1", 2)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 1)

	// Cleanup will remove the entry for mjl3 and leave others.
	err = LoginAttemptCleanup(ctxbg)
	tcheck(t, err, "cleanup login attempt")
	l, err = LoginAttemptList(ctxbg, "", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 2)

	// Removing account will keep last entry for mjl2.
	err = LoginAttemptRemoveAccount(ctxbg, "mjl1")
	tcheck(t, err, "remove login attempt account")
	l, err = LoginAttemptList(ctxbg, "", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 1)

	l, err = LoginAttemptList(ctxbg, "mjl2", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), 1)

	// Insert 3 failing entries. Then add another and see we still have 3.
	loginAttemptsMaxPerAccount = 3
	for i := 0; i < loginAttemptsMaxPerAccount; i++ {
		a := a2
		a.UserAgent = fmt.Sprintf("%d", i)
		LoginAttemptAdd(ctxbg, pkglog, a)
	}
	loginAttemptDrain()
	l, err = LoginAttemptList(ctxbg, "", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), loginAttemptsMaxPerAccount)

	a := a2
	a.UserAgent = fmt.Sprintf("%d", loginAttemptsMaxPerAccount)
	LoginAttemptAdd(ctxbg, pkglog, a)
	loginAttemptDrain()
	l, err = LoginAttemptList(ctxbg, "", 0)
	tcheck(t, err, "list login attempts")
	tcompare(t, len(l), loginAttemptsMaxPerAccount)
}
