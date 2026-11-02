package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mox-"
)

func TestAdminToken(t *testing.T) {
	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()

	// Validation.
	_, _, err = AdminTokenAdd(ctxbg, "", time.Time{})
	if err == nil {
		t.Fatalf("expected error for empty name")
	}
	_, _, err = AdminTokenAdd(ctxbg, "past", time.Now().Add(-time.Minute))
	if err == nil {
		t.Fatalf("expected error for expiration in the past")
	}

	token, at, err := AdminTokenAdd(ctxbg, "test", time.Time{})
	tcheck(t, err, "add token")
	if token == "" || at.TokenHash == token {
		t.Fatalf("bad token %q, hash %q", token, at.TokenHash)
	}

	// Duplicate name.
	_, _, err = AdminTokenAdd(ctxbg, "test", time.Time{})
	if !errors.Is(err, ErrAdminTokenExists) {
		t.Fatalf("got err %v, expected ErrAdminTokenExists", err)
	}

	l, err := AdminTokenList(ctxbg)
	tcheck(t, err, "list tokens")
	tcompare(t, len(l), 1)
	tcompare(t, l[0].LastUsed.IsZero(), true)

	// Verify valid token updates LastUsed.
	vat, err := AdminTokenVerify(ctxbg, token)
	tcheck(t, err, "verify token")
	tcompare(t, vat.ID, at.ID)
	tcompare(t, vat.LastUsed.IsZero(), false)

	// Unknown and empty tokens.
	_, err = AdminTokenVerify(ctxbg, "bogus")
	tcompare(t, errors.Is(err, ErrAdminTokenInvalid), true)
	_, err = AdminTokenVerify(ctxbg, "")
	tcompare(t, errors.Is(err, ErrAdminTokenInvalid), true)

	// Expired token.
	token2, at2, err := AdminTokenAdd(ctxbg, "expiring", time.Now().Add(time.Hour))
	tcheck(t, err, "add expiring token")
	_, err = AdminTokenVerify(ctxbg, token2)
	tcheck(t, err, "verify expiring token")
	at2.Expires = time.Now().Add(-time.Second)
	err = AuthDB.Update(ctxbg, &at2)
	tcheck(t, err, "update token expiration")
	_, err = AdminTokenVerify(ctxbg, token2)
	tcompare(t, errors.Is(err, ErrAdminTokenInvalid), true)

	// Removed token is no longer valid.
	err = AdminTokenRemove(ctxbg, at.ID)
	tcheck(t, err, "remove token")
	_, err = AdminTokenVerify(ctxbg, token)
	tcompare(t, errors.Is(err, ErrAdminTokenInvalid), true)
	err = AdminTokenRemove(ctxbg, at.ID)
	tcompare(t, errors.Is(err, bstore.ErrAbsent), true)
}
