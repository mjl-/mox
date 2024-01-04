package webauth

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

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

func (a *adminSessionAuth) login(ctx context.Context, log mlog.Log, username, password string) (bool, string, error) {
	a.Lock()
	defer a.Unlock()

	p := mox.ConfigDirPath(mox.Conf.Static.AdminPasswordFile)
	buf, err := os.ReadFile(p)
	if err != nil {
		return false, "", fmt.Errorf("reading password file: %v", err)
	}
	passwordhash := strings.TrimSpace(string(buf))
	if err := bcrypt.CompareHashAndPassword([]byte(passwordhash), []byte(password)); err != nil {
		return false, "", nil
	}

	return true, "", nil
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
	if _, err := cryptorand.Read(sessionData[:]); err != nil {
		return "", "", err
	}
	if _, err := cryptorand.Read(csrfData[:]); err != nil {
		return "", "", err
	}
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
		return "", fmt.Errorf("unknown session")
	} else if time.Until(s.expires) < 0 {
		return "", fmt.Errorf("session expired")
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
