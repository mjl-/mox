/*
Package webauth handles authentication and session/csrf token management for
the web interfaces (admin, account, mail).

Authentication of web requests is through a session token in a cookie. For API
requests, and other requests where the frontend can send custom headers, a
header ("x-mox-csrf") with a CSRF token is also required and verified to belong
to the session token. For other form POSTS, a field "csrf" is required. Session
tokens and CSRF tokens are different randomly generated values. Session cookies
are "httponly", samesite "strict", and with the path set to the root of the
webadmin/webaccount/webmail. Cookies set over HTTPS are marked "secure".
Cookies don't have an expiration, they can be extended indefinitely by using
them.

To login, a call to LoginPrep must first be made. It sets a random login token
in a cookie, and returns it. The loginToken must be passed to the Login call,
along with login credentials. If the loginToken is missing, the login attempt
fails before checking any credentials. This should prevent third party websites
from tricking a browser into logging in.

Sessions are stored server-side, and their lifetime automatically extended each
time they are used. This makes it easy to invalidate existing sessions after a
password change, and keeps the frontend free from handling long-term vs
short-term sessions.

Sessions for the admin interface have a lifetime of 12 hours after last use,
are only stored in memory (don't survive a server restart), and only 10
sessions can exist at a time (the oldest session is dropped).

Sessions for the account and mail interfaces have a lifetime of 24 hours after
last use, are kept in memory and stored in the database (do survive a server
restart), and only 100 sessions can exist per account (the oldest session is
dropped).
*/
package webauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// Delay before responding in case of bad authentication attempt.
var BadAuthDelay = time.Second

// SessionAuth handles login and session storage, used for both account and
// admin authentication.
type SessionAuth interface {
	// Login verifies the password. Valid indicates the attempt was successful. If
	// disabled is true, the error must be non-nil and contain details.
	login(ctx context.Context, log mlog.Log, username, password string) (valid bool, disabled bool, accountName string, rerr error)

	// Add a new session for account and login address.
	add(ctx context.Context, log mlog.Log, accountName string, loginAddress string) (sessionToken store.SessionToken, csrfToken store.CSRFToken, rerr error)

	// Use an existing session. If csrfToken is empty, no CSRF check must be done.
	// Otherwise the CSRF token must be associated with the session token, as returned
	// by add. If the token is not valid (e.g. expired, unknown, malformed), an error
	// must be returned.
	use(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken, csrfToken store.CSRFToken) (loginAddress string, rerr error)

	// Removes a session, invalidating any future use. Must return an error if the
	// session is not valid.
	remove(ctx context.Context, log mlog.Log, accountName string, sessionToken store.SessionToken) error
}

// loginAttempt initializes a loginAttempt, for adding to the store after filling in the results and other details.
func loginAttempt(remoteIP string, r *http.Request, protocol, authMech string) store.LoginAttempt {
	return store.LoginAttempt{
		RemoteIP:  remoteIP,
		TLS:       store.LoginAttemptTLS(r.TLS),
		Protocol:  protocol,
		AuthMech:  authMech,
		UserAgent: r.UserAgent(),
		Result:    store.AuthError, // Replaced by caller.
	}
}

// Check authentication for a request based on session token in cookie and matching
// csrf in case requireCSRF is set (from header, unless formCSRF is set). Also
// performs rate limiting.
//
// If the returned boolean is true, the request is authenticated. If the returned
// boolean is false, an HTTP error response has already been returned. If rate
// limiting applies (after too many failed authentication attempts), an HTTP status
// 429 is returned. Otherwise, for API requests an error object with either code
// "user:noAuth" or "user:badAuth" is returned. Other unauthenticated requests
// result in HTTP status 403.
//
// sessionAuth verifies login attempts and handles session management.
//
// kind is used for the cookie name (webadmin, webaccount, webmail), and for
// logging/metrics.
func Check(ctx context.Context, log mlog.Log, sessionAuth SessionAuth, kind string, isForwarded bool, w http.ResponseWriter, r *http.Request, isAPI, requireCSRF, postFormCSRF bool) (accountName string, sessionToken store.SessionToken, loginAddress string, ok bool) {
	// Respond with an authentication error.
	respondAuthError := func(code, msg string) {
		if isAPI {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			var result = struct {
				Error sherpa.Error `json:"error"`
			}{
				sherpa.Error{Code: code, Message: msg},
			}
			err := json.NewEncoder(w).Encode(result)
			log.Check(err, "writing error response")
		} else {
			http.Error(w, "403 - forbidden - "+msg, http.StatusForbidden)
		}
	}

	// The frontends cannot inject custom headers for all requests, e.g. images loaded
	// as resources. For those, we don't require the CSRF and rely on the session
	// cookie with samesite=strict.
	// todo future: possibly get a session-tied value to use in paths for resources, and verify server-side that it matches the session token.
	var csrfValue string
	if requireCSRF && postFormCSRF {
		csrfValue = r.PostFormValue("csrf")
	} else {
		csrfValue = r.Header.Get("x-mox-csrf")
	}
	csrfToken := store.CSRFToken(csrfValue)
	if requireCSRF && csrfToken == "" {
		respondAuthError("user:noAuth", "missing required csrf header")
		return "", "", "", false
	}

	// Cookies are named "webmailsession", "webaccountsession", "webadminsession".
	cookie, _ := r.Cookie(kind + "session")
	if cookie == nil {
		respondAuthError("user:noAuth", fmt.Sprintf("no session for %q web interface", strings.TrimPrefix(kind, "web")))
		return "", "", "", false
	}

	ip := RemoteIP(log, isForwarded, r)
	if ip == nil {
		respondAuthError("user:noAuth", "cannot find ip for rate limit check (missing x-forwarded-for header?)")
		return "", "", "", false
	}
	start := time.Now()
	if !mox.LimiterFailedAuth.Add(ip, start, 1) {
		metrics.AuthenticationRatelimitedInc(kind)
		http.Error(w, "429 - too many auth attempts", http.StatusTooManyRequests)
		return
	}

	la := loginAttempt(ip.String(), r, kind, "websession")
	defer func() {
		store.LoginAttemptAdd(context.Background(), log, la)
	}()

	// Cookie values are of the form: token SP accountname.
	// For admin sessions, the accountname is empty (there is no login address either).
	t := strings.SplitN(cookie.Value, " ", 2)
	if len(t) != 2 {
		time.Sleep(BadAuthDelay)
		respondAuthError("user:badAuth", "malformed session")
		return "", "", "", false
	}
	sessionToken = store.SessionToken(t[0])

	var err error
	accountName, err = url.QueryUnescape(t[1])
	if err != nil {
		time.Sleep(BadAuthDelay)
		respondAuthError("user:badAuth", "malformed session account name")
		return "", "", "", false
	}
	la.AccountName = accountName

	loginAddress, err = sessionAuth.use(ctx, log, accountName, sessionToken, csrfToken)
	if err != nil {
		la.Result = store.AuthBadCredentials
		time.Sleep(BadAuthDelay)
		respondAuthError("user:badAuth", err.Error())
		return "", "", "", false
	}
	la.LoginAddress = loginAddress

	mox.LimiterFailedAuth.Reset(ip, start)
	la.Result = store.AuthSuccess

	// Add to HTTP logging that this is an authenticated request.
	if lw, ok := w.(interface{ AddAttr(a slog.Attr) }); ok {
		lw.AddAttr(slog.String("authaccount", accountName))
	}
	return accountName, sessionToken, loginAddress, true
}

func RemoteIP(log mlog.Log, isForwarded bool, r *http.Request) net.IP {
	if isForwarded {
		s := r.Header.Get("X-Forwarded-For")
		ipstr := strings.TrimSpace(strings.Split(s, ",")[0])
		return net.ParseIP(ipstr)
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

func isHTTPS(isForwarded bool, r *http.Request) bool {
	if isForwarded {
		return r.Header.Get("X-Forwarded-Proto") == "https"
	}
	return r.TLS != nil
}

// LoginPrep is an API call that returns a loginToken and also sets it as cookie
// with the same value. The loginToken must be passed to a subsequent call to
// Login, which will check that the loginToken and cookie are both present and
// match before checking the actual login attempt. This would prevent a third party
// site from triggering login attempts by the browser.
func LoginPrep(ctx context.Context, log mlog.Log, kind, cookiePath string, isForwarded bool, w http.ResponseWriter, r *http.Request, token string) {
	// todo future: we could sign the login token, and verify it on use, so subdomains cannot set it to known values.

	http.SetCookie(w, &http.Cookie{
		Name:     kind + "login",
		Value:    token,
		Path:     cookiePath,
		Secure:   isHTTPS(isForwarded, r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30, // Only for one login attempt.
	})
}

// Login handles a login attempt, checking against the rate limiter, verifying the
// credentials through sessionAuth, and setting a session token cookie on the HTTP
// response and returning the associated CSRF token.
//
// In case of a user error, a *sherpa.Error is returned that sherpa handlers can
// pass to panic. For bad credentials, the error code is "user:loginFailed".
func Login(ctx context.Context, log mlog.Log, sessionAuth SessionAuth, kind, cookiePath string, isForwarded bool, w http.ResponseWriter, r *http.Request, loginToken, username, password string) (store.CSRFToken, error) {
	loginCookie, _ := r.Cookie(kind + "login")
	if loginCookie == nil || loginCookie.Value != loginToken {
		msg := "missing login token cookie"
		if isForwarded && loginCookie == nil {
			msg += " (hint: reverse proxy must keep path, for login cookie)"
		}
		return "", &sherpa.Error{Code: "user:error", Message: msg}
	}

	ip := RemoteIP(log, isForwarded, r)
	if ip == nil {
		return "", fmt.Errorf("cannot find ip for rate limit check (missing x-forwarded-for header?)")
	}
	start := time.Now()
	if !mox.LimiterFailedAuth.Add(ip, start, 1) {
		metrics.AuthenticationRatelimitedInc(kind)
		return "", &sherpa.Error{Code: "user:error", Message: "too many authentication attempts"}
	}

	username = norm.NFC.String(username)
	valid, disabled, accountName, err := sessionAuth.login(ctx, log, username, password)
	la := loginAttempt(ip.String(), r, kind, "weblogin")
	la.LoginAddress = username
	la.AccountName = accountName
	defer func() {
		store.LoginAttemptAdd(context.Background(), log, la)
	}()
	if disabled {
		la.Result = store.AuthLoginDisabled
		return "", &sherpa.Error{Code: "user:loginFailed", Message: err.Error()}
	} else if err != nil {
		la.Result = store.AuthError
		return "", fmt.Errorf("evaluating login attempt: %v", err)
	} else if !valid {
		time.Sleep(BadAuthDelay)
		la.Result = store.AuthBadCredentials
		return "", &sherpa.Error{Code: "user:loginFailed", Message: "invalid credentials"}
	}
	la.Result = store.AuthSuccess
	mox.LimiterFailedAuth.Reset(ip, start)

	sessionToken, csrfToken, err := sessionAuth.add(ctx, log, accountName, username)
	if err != nil {
		la.Result = store.AuthError
		log.Errorx("adding session after login", err)
		return "", fmt.Errorf("adding session: %v", err)
	}

	// Add session cookie.
	http.SetCookie(w, &http.Cookie{
		Name: kind + "session",
		// Cookies values are ascii only, so we keep the account name query escaped.
		Value:    string(sessionToken) + " " + url.QueryEscape(accountName),
		Path:     cookiePath,
		Secure:   isHTTPS(isForwarded, r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// We don't set a max-age. These makes cookies per-session. Browsers are rarely
		// restarted nowadays, and they have "continue where you left off", keeping session
		// cookies. Our sessions are only valid for max 1 day. Convenience can come from
		// the browser remembering the password.
	})
	// Remove cookie used during login.
	http.SetCookie(w, &http.Cookie{
		Name:     kind + "login",
		Path:     cookiePath,
		Secure:   isHTTPS(isForwarded, r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie
	})
	return csrfToken, nil
}

// Logout removes the session token through sessionAuth, and clears the session
// cookie through the HTTP response.
func Logout(ctx context.Context, log mlog.Log, sessionAuth SessionAuth, kind, cookiePath string, isForwarded bool, w http.ResponseWriter, r *http.Request, accountName string, sessionToken store.SessionToken) error {
	err := sessionAuth.remove(ctx, log, accountName, sessionToken)
	if err != nil {
		return fmt.Errorf("removing session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     kind + "session",
		Path:     cookiePath,
		Secure:   isHTTPS(isForwarded, r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete cookie.
	})
	return nil
}
