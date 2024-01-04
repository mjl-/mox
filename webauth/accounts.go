package webauth

import (
	"context"
	"errors"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/store"
)

// AccountAuth is for user accounts, with username/password, and sessions stored in
// memory and in the database with lifetimes that are automatically extended.
var Accounts SessionAuth = accountSessionAuth{}

type accountSessionAuth struct{}

func (accountSessionAuth) login(ctx context.Context, log mlog.Log, username, password string) (bool, string, error) {
	acc, err := store.OpenEmailAuth(log, username, password)
	if err != nil && errors.Is(err, store.ErrUnknownCredentials) {
		return false, "", nil
	} else if err != nil {
		return false, "", err
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()
	return true, acc.Name, nil
}

func (accountSessionAuth) add(ctx context.Context, log mlog.Log, accountName string, loginAddress string) (sessionToken store.SessionToken, csrfToken store.CSRFToken, rerr error) {
	return store.SessionAdd(ctx, log, accountName, loginAddress)
}

func (accountSessionAuth) use(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken, csrfToken store.CSRFToken) (loginAddress string, rerr error) {
	ls, err := store.SessionUse(ctx, log, accountName, sessionToken, csrfToken)
	if err != nil {
		return "", err
	}
	return ls.LoginAddress, nil
}

func (accountSessionAuth) remove(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken) error {
	return store.SessionRemove(ctx, log, accountName, sessionToken)
}
