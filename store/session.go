package store

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

const sessionsPerAccount = 100            // We remove the oldest when 100th is added.
const sessionLifetime = 24 * time.Hour    // Extended automatically by use.
const sessionWriteDelay = 5 * time.Minute // Per account, for coalescing writes.

var sessions = struct {
	sync.Mutex

	// For each account, we keep all sessions (with fixed maximum number) in memory. If
	// the map for an account is nil, it is initialized from the database on first use.
	accounts map[string]map[SessionToken]LoginSession

	// We flush sessions with extended expiration timestamp to disk with a delay, to
	// coalesce potentially many changes. The delay is short enough that we don't have
	// to care about flushing to disk on shutdown.
	pendingFlushes map[string]map[SessionToken]struct{}
}{
	accounts:       map[string]map[SessionToken]LoginSession{},
	pendingFlushes: map[string]map[SessionToken]struct{}{},
}

// Ensure sessions for account are initialized from database. If the sessions were
// initialized from the database, or when alwaysOpenAccount is true, an open
// account is returned (assuming no error occurred).
//
// must be called with sessions lock held.
func ensureAccountSessions(ctx context.Context, log mlog.Log, accountName string, alwaysOpenAccount bool) (*Account, error) {
	var acc *Account
	accSessions := sessions.accounts[accountName]
	if accSessions == nil {
		var err error
		acc, err = OpenAccount(log, accountName)
		if err != nil {
			return nil, err
		}

		// We still hold the lock, not great...

		accSessions = map[SessionToken]LoginSession{}
		err = bstore.QueryDB[LoginSession](ctx, acc.DB).ForEach(func(ls LoginSession) error {
			// We keep strings around for easy comparison.
			ls.sessionToken = SessionToken(base64.RawURLEncoding.EncodeToString(ls.SessionTokenBinary[:]))
			ls.csrfToken = CSRFToken(base64.RawURLEncoding.EncodeToString(ls.CSRFTokenBinary[:]))

			accSessions[ls.sessionToken] = ls
			return nil
		})
		if err != nil {
			return nil, err
		}

		sessions.accounts[accountName] = accSessions
	}
	if acc == nil && alwaysOpenAccount {
		return OpenAccount(log, accountName)
	}
	return acc, nil
}

// SessionUse checks if a session is valid. If csrfToken is the empty string, no
// CSRF check is done. Otherwise it must be the csrf token associated with the
// session token.
func SessionUse(ctx context.Context, log mlog.Log, accountName string, sessionToken SessionToken, csrfToken CSRFToken) (LoginSession, error) {
	sessions.Lock()
	defer sessions.Unlock()

	acc, err := ensureAccountSessions(ctx, log, accountName, false)
	if err != nil {
		return LoginSession{}, err
	} else if acc != nil {
		if err := acc.Close(); err != nil {
			return LoginSession{}, fmt.Errorf("closing account: %w", err)
		}
	}

	return sessionUse(ctx, log, accountName, sessionToken, csrfToken)
}

// must be called with sessions lock held.
func sessionUse(ctx context.Context, log mlog.Log, accountName string, sessionToken SessionToken, csrfToken CSRFToken) (LoginSession, error) {
	// Check if valid.
	ls, ok := sessions.accounts[accountName][sessionToken]
	if !ok {
		return LoginSession{}, fmt.Errorf("unknown session token")
	} else if time.Until(ls.Expires) < 0 {
		return LoginSession{}, fmt.Errorf("session expired")
	} else if csrfToken != "" && csrfToken != ls.csrfToken {
		return LoginSession{}, fmt.Errorf("mismatch between csrf and session tokens")
	}

	// Extend lifetime.
	ls.Expires = time.Now().Add(sessionLifetime)
	sessions.accounts[accountName][sessionToken] = ls

	// If we haven't scheduled a flush to database yet, schedule one now.
	if sessions.pendingFlushes[accountName] == nil {
		sessions.pendingFlushes[accountName] = map[SessionToken]struct{}{}
		go func() {
			pkglog := mlog.New("store", nil)

			defer func() {
				x := recover()
				if x != nil {
					pkglog.Error("recover from panic", slog.Any("panic", x))
					debug.PrintStack()
					metrics.PanicInc(metrics.Store)
				}
			}()

			time.Sleep(sessionWriteDelay)
			sessionsDelayedFlush(pkglog, accountName)
		}()
	}
	sessions.pendingFlushes[accountName][ls.sessionToken] = struct{}{}

	return ls, nil
}

// wait, then flush all changed sessions for an account.
func sessionsDelayedFlush(log mlog.Log, accountName string) {
	sessions.Lock()
	defer sessions.Unlock()

	sessionTokens := sessions.pendingFlushes[accountName]
	delete(sessions.pendingFlushes, accountName)

	_, ok := sessions.accounts[accountName]
	if !ok {
		// Account may have been removed. Nothing to flush.
		return
	}

	acc, err := OpenAccount(log, accountName)
	if err != nil && errors.Is(err, ErrAccountUnknown) {
		// Account may have been removed. Nothing to flush.
		log.Infox("flushing sessions for account", err, slog.String("account", accountName))
		return
	}
	if err != nil {
		log.Errorx("open account for flushing changed session tokens", err, slog.String("account", accountName))
		return
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	err = acc.DB.Write(mox.Context, func(tx *bstore.Tx) error {
		for sessionToken := range sessionTokens {
			ls, ok := sessions.accounts[accountName][sessionToken]
			if !ok {
				return fmt.Errorf("unknown session token to flush")
			}
			if err := tx.Update(&ls); err != nil {
				return err
			}
		}
		return nil
	})
	log.Check(err, "flushing changed sessions for account", slog.String("account", accountName))
}

// SessionAddTokens adds a prepared or pre-existing LoginSession to the database and
// cache. Can be used to restore a session token that was used to reset a password.
func SessionAddToken(ctx context.Context, log mlog.Log, ls *LoginSession) error {
	sessions.Lock()
	defer sessions.Unlock()

	acc, err := ensureAccountSessions(ctx, log, ls.AccountName, true)
	if err != nil {
		return err
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account after adding session token")
	}()

	return sessionAddToken(ctx, log, acc, ls)
}

// caller must hold sessions lock.
func sessionAddToken(ctx context.Context, log mlog.Log, acc *Account, ls *LoginSession) error {
	ls.ID = 0

	err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
		// Remove sessions if we have too many, starting with expired sessions, and
		// removing the oldest if needed.
		if len(sessions.accounts[ls.AccountName]) >= sessionsPerAccount {
			var oldest LoginSession
			for _, ols := range sessions.accounts[ls.AccountName] {
				if time.Until(ols.Expires) < 0 {
					if err := tx.Delete(&ols); err != nil {
						return err
					}
					delete(sessions.accounts[ls.AccountName], ols.sessionToken)
					continue
				}
				if oldest.ID == 0 || ols.Expires.Before(oldest.Expires) {
					oldest = ols
				}
			}
			if len(sessions.accounts[ls.AccountName]) >= sessionsPerAccount {
				if err := tx.Delete(&oldest); err != nil {
					return err
				}
				delete(sessions.accounts[ls.AccountName], oldest.sessionToken)
			}
		}

		if err := tx.Insert(ls); err != nil {
			return fmt.Errorf("insert: %v", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sessions.accounts[ls.AccountName][ls.sessionToken] = *ls
	return nil
}

// SessionAdd creates a new session token, with csrf token, and adds it to the
// database and in-memory session cache. If there are too many sessions, the oldest
// is removed.
func SessionAdd(ctx context.Context, log mlog.Log, accountName, loginAddress string) (session SessionToken, csrf CSRFToken, rerr error) {
	// Prepare new LoginSession.
	ls := LoginSession{0, time.Time{}, time.Now().Add(sessionLifetime), [16]byte{}, [16]byte{}, accountName, loginAddress, "", ""}
	if _, err := cryptorand.Read(ls.SessionTokenBinary[:]); err != nil {
		return "", "", err
	}
	if _, err := cryptorand.Read(ls.CSRFTokenBinary[:]); err != nil {
		return "", "", err
	}
	ls.sessionToken = SessionToken(base64.RawURLEncoding.EncodeToString(ls.SessionTokenBinary[:]))
	ls.csrfToken = CSRFToken(base64.RawURLEncoding.EncodeToString(ls.CSRFTokenBinary[:]))

	sessions.Lock()
	defer sessions.Unlock()

	acc, err := ensureAccountSessions(ctx, log, accountName, true)
	if err != nil {
		return "", "", err
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	if err := sessionAddToken(ctx, log, acc, &ls); err != nil {
		return "", "", err
	}

	return ls.sessionToken, ls.csrfToken, nil
}

// SessionRemove removes a session from the database and in-memory cache. Future
// operations using the session token will fail.
func SessionRemove(ctx context.Context, log mlog.Log, accountName string, sessionToken SessionToken) error {
	sessions.Lock()
	defer sessions.Unlock()

	acc, err := ensureAccountSessions(ctx, log, accountName, true)
	if err != nil {
		return err
	}
	defer acc.Close()

	ls, ok := sessions.accounts[accountName][sessionToken]
	if !ok {
		return fmt.Errorf("unknown session token")
	}

	if err := acc.DB.Delete(ctx, &ls); err != nil {
		return err
	}

	delete(sessions.accounts[accountName], sessionToken)
	pf := sessions.pendingFlushes[accountName]
	if pf != nil {
		delete(pf, sessionToken)
	}

	return nil
}

// sessionRemoveAll removes all session tokens for an account. Useful after a password reset.
func sessionRemoveAll(ctx context.Context, log mlog.Log, tx *bstore.Tx, accountName string) error {
	sessions.Lock()
	defer sessions.Unlock()

	if _, err := bstore.QueryTx[LoginSession](tx).Delete(); err != nil {
		return err
	}

	sessions.accounts[accountName] = map[SessionToken]LoginSession{}
	if sessions.pendingFlushes[accountName] != nil {
		sessions.pendingFlushes[accountName] = map[SessionToken]struct{}{}
	}

	return nil
}
