package webauth

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/secure/precis"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// Admin is for admin logins, with authentication by password, and sessions only
// stored in memory only, with lifetime 12 hour after last use, with a maximum of
// 10 active sessions.
var Admin SessionAuth = &adminSessionAuth{
	sessions: map[store.SessionToken]adminSession{},
}

// Good chance of fitting one working day.
const adminSessionLifetime = 12 * time.Hour

type adminSession struct {
	sessionToken store.SessionToken
	csrfToken    store.CSRFToken
	expires      time.Time
}

type adminSessionAuth struct {
	sync.Mutex
	sessions map[store.SessionToken]adminSession
}

func (a *adminSessionAuth) login(ctx context.Context, log mlog.Log, username, password string) (valid, disabled bool, name string, rerr error) {
	a.Lock()
	defer a.Unlock()

	p := mox.ConfigDirPath(mox.Conf.Static.AdminPasswordFile)
	buf, err := os.ReadFile(p)
	if err != nil {
		return false, false, "", fmt.Errorf("reading password file: %v", err)
	}
	passwordhash := strings.TrimSpace(string(buf))
	// Transform with precis, if valid. ../rfc/8265:679
	pw, err := precis.OpaqueString.String(password)
	if err == nil {
		password = pw
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordhash), []byte(password)); err != nil {
		return false, false, "", nil
	}

	return true, false, "(admin)", nil
}

func (a *adminSessionAuth) add(ctx context.Context, log mlog.Log, accountName string, loginAddress string) (sessionToken store.SessionToken, csrfToken store.CSRFToken, rerr error) {
	a.Lock()
	defer a.Unlock()

	// Cleanup expired sessions.
	for st, s := range a.sessions {
		if time.Until(s.expires) < 0 {
			delete(a.sessions, st)
		}
	}

	// Ensure we have at most 10 sessions.
	if len(a.sessions) > 10 {
		var oldest *store.SessionToken
		for _, s := range a.sessions {
			if oldest == nil || s.expires.Before(a.sessions[*oldest].expires) {
				oldest = &s.sessionToken
			}
		}
		delete(a.sessions, *oldest)
	}

	// Generate new tokens.
	var sessionData, csrfData [16]byte
	cryptorand.Read(sessionData[:])
	cryptorand.Read(csrfData[:])
	sessionToken = store.SessionToken(base64.RawURLEncoding.EncodeToString(sessionData[:]))
	csrfToken = store.CSRFToken(base64.RawURLEncoding.EncodeToString(csrfData[:]))

	// Register session.
	a.sessions[sessionToken] = adminSession{sessionToken, csrfToken, time.Now().Add(adminSessionLifetime)}
	return sessionToken, csrfToken, nil
}

func (a *adminSessionAuth) use(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken, csrfToken store.CSRFToken) (loginAddress string, rerr error) {
	a.Lock()
	defer a.Unlock()

	s, ok := a.sessions[sessionToken]
	if !ok {
		return "", fmt.Errorf("unknown session (due to server restart or 10 new admin sessions)")
	} else if time.Until(s.expires) < 0 {
		return "", fmt.Errorf("session expired (after 12 hours inactivity)")
	} else if csrfToken != "" && csrfToken != s.csrfToken {
		return "", fmt.Errorf("mismatch between csrf and session tokens")
	}
	s.expires = time.Now().Add(adminSessionLifetime)
	a.sessions[sessionToken] = s
	return "", nil
}

func (a *adminSessionAuth) remove(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken) error {
	a.Lock()
	defer a.Unlock()

	if _, ok := a.sessions[sessionToken]; !ok {
		return fmt.Errorf("unknown session")
	}
	delete(a.sessions, sessionToken)
	return nil
}

// CheckAdminToken authenticates an admin API request through an
// "Authorization: Bearer <token>" header, verifying the token against the admin
// tokens in the database. Performs rate limiting and records the login attempt.
//
// On success, returns the token name and ok=true. 
// On failure, writes an error to the response writer and returns ok=false.
func CheckAdminToken(ctx context.Context, log mlog.Log, isForwarded bool, w http.ResponseWriter, r *http.Request, token string) (tokenName string, ok bool) {
	const kind = "webadmin"

	ip, start, ok := rateLimitAuth(log, kind, isForwarded, w, r, true)
	if !ok {
		return "", false
	}

	la := loginAttempt(ip.String(), r, kind, "admintoken")
	la.AccountName = "(admin)"
	defer func() {
		store.LoginAttemptAdd(context.Background(), log, la)
	}()

	at, err := store.AdminTokenVerify(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrAdminTokenInvalid) {
			la.Result = store.AuthBadCredentials
			time.Sleep(BadAuthDelay)
			respondAuthError(log, w, true, "user:badAuth", err.Error())
		} else {
			log.Errorx("verifying admin token", err)
			respondAuthError(log, w, true, "server:error", "verifying admin token")
		}
		return "", false
	}
	la.LoginAddress = "admin token " + at.Name

	mox.LimiterFailedAuth.Reset(ip, start)
	la.Result = store.AuthSuccess

	addAuthLogAttrs(w, slog.String("authaccount", "(admin)"), slog.String("admintoken", at.Name))
	return at.Name, true
}
