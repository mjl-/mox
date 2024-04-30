// Package webaccount provides a web app for users to view and change their account
// settings, and to import/export email.
package webaccount

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "embed"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webauth"
	"github.com/mjl-/mox/webhook"
	"github.com/mjl-/mox/webops"
)

var pkglog = mlog.New("webaccount", nil)

//go:embed api.json
var accountapiJSON []byte

//go:embed account.html
var accountHTML []byte

//go:embed account.js
var accountJS []byte

var webaccountFile = &mox.WebappFile{
	HTML:     accountHTML,
	JS:       accountJS,
	HTMLPath: filepath.FromSlash("webaccount/account.html"),
	JSPath:   filepath.FromSlash("webaccount/account.js"),
}

var accountDoc = mustParseAPI("account", accountapiJSON)

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		pkglog.Fatalx("parsing webaccount api docs", err, slog.String("api", api))
	}
	return doc
}

var sherpaHandlerOpts *sherpa.HandlerOpts

func makeSherpaHandler(cookiePath string, isForwarded bool) (http.Handler, error) {
	return sherpa.NewHandler("/api/", moxvar.Version, Account{cookiePath, isForwarded}, &accountDoc, sherpaHandlerOpts)
}

func init() {
	collector, err := sherpaprom.NewCollector("moxaccount", nil)
	if err != nil {
		pkglog.Fatalx("creating sherpa prometheus collector", err)
	}

	sherpaHandlerOpts = &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none", NoCORS: true}
	// Just to validate.
	_, err = makeSherpaHandler("", false)
	if err != nil {
		pkglog.Fatalx("sherpa handler", err)
	}
}

// Handler returns a handler for the webaccount endpoints, customized for the
// cookiePath.
func Handler(cookiePath string, isForwarded bool) func(w http.ResponseWriter, r *http.Request) {
	sh, err := makeSherpaHandler(cookiePath, isForwarded)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "500 - internal server error - cannot handle requests", http.StatusInternalServerError)
			return
		}
		handle(sh, isForwarded, w, r)
	}
}

func xcheckf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	pkglog.WithContext(ctx).Errorx(msg, err)
	code := "server:error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = "user:error"
	}
	panic(&sherpa.Error{Code: code, Message: errmsg})
}

func xcheckuserf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	pkglog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "user:error", Message: errmsg})
}

// Account exports web API functions for the account web interface. All its
// methods are exported under api/. Function calls require valid HTTP
// Authentication credentials of a user.
type Account struct {
	cookiePath  string // From listener, for setting authentication cookies.
	isForwarded bool   // From listener, whether we look at X-Forwarded-* headers.
}

func handle(apiHandler http.Handler, isForwarded bool, w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	log := pkglog.WithContext(ctx).With(slog.String("userauth", ""))

	// Without authentication. The token is unguessable.
	if r.URL.Path == "/importprogress" {
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed - get required", http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		token := q.Get("token")
		if token == "" {
			http.Error(w, "400 - bad request - missing token", http.StatusBadRequest)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Error("internal error: ResponseWriter not a http.Flusher")
			http.Error(w, "500 - internal error - cannot access underlying connection", 500)
			return
		}

		l := importListener{token, make(chan importEvent, 100), make(chan bool, 1)}
		importers.Register <- &l
		ok = <-l.Register
		if !ok {
			http.Error(w, "400 - bad request - unknown token, import may have finished more than a minute ago", http.StatusBadRequest)
			return
		}
		defer func() {
			importers.Unregister <- &l
		}()

		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		_, err := w.Write([]byte(": keepalive\n\n"))
		if err != nil {
			return
		}
		flusher.Flush()

		cctx := r.Context()
		for {
			select {
			case e := <-l.Events:
				_, err := w.Write(e.SSEMsg)
				flusher.Flush()
				if err != nil {
					return
				}

			case <-cctx.Done():
				return
			}
		}
	}

	// HTML/JS can be retrieved without authentication.
	if r.URL.Path == "/" {
		switch r.Method {
		case "GET", "HEAD":
			webaccountFile.Serve(ctx, log, w, r)
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		}
		return
	}

	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	// Only allow POST for calls, they will not work cross-domain without CORS.
	if isAPI && r.URL.Path != "/api/" && r.Method != "POST" {
		http.Error(w, "405 - method not allowed - use post", http.StatusMethodNotAllowed)
		return
	}

	var loginAddress, accName string
	var sessionToken store.SessionToken
	// All other URLs, except the login endpoint require some authentication.
	if r.URL.Path != "/api/LoginPrep" && r.URL.Path != "/api/Login" {
		var ok bool
		isExport := r.URL.Path == "/export"
		requireCSRF := isAPI || r.URL.Path == "/import" || isExport
		accName, sessionToken, loginAddress, ok = webauth.Check(ctx, log, webauth.Accounts, "webaccount", isForwarded, w, r, isAPI, requireCSRF, isExport)
		if !ok {
			// Response has been written already.
			return
		}
	}

	if isAPI {
		reqInfo := requestInfo{loginAddress, accName, sessionToken, w, r}
		ctx = context.WithValue(ctx, requestInfoCtxKey, reqInfo)
		apiHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	switch r.URL.Path {
	case "/export":
		webops.Export(log, accName, w, r)

	case "/import":
		if r.Method != "POST" {
			http.Error(w, "405 - method not allowed - post required", http.StatusMethodNotAllowed)
			return
		}

		f, _, err := r.FormFile("file")
		if err != nil {
			if errors.Is(err, http.ErrMissingFile) {
				http.Error(w, "400 - bad request - missing file", http.StatusBadRequest)
			} else {
				http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		defer func() {
			err := f.Close()
			log.Check(err, "closing form file")
		}()
		skipMailboxPrefix := r.FormValue("skipMailboxPrefix")
		tmpf, err := os.CreateTemp("", "mox-import")
		if err != nil {
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() {
			if tmpf != nil {
				store.CloseRemoveTempFile(log, tmpf, "upload")
			}
		}()
		if _, err := io.Copy(tmpf, f); err != nil {
			log.Errorx("copying import to temporary file", err)
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		token, isUserError, err := importStart(log, accName, tmpf, skipMailboxPrefix)
		if err != nil {
			log.Errorx("starting import", err, slog.Bool("usererror", isUserError))
			if isUserError {
				http.Error(w, "400 - bad request - "+err.Error(), http.StatusBadRequest)
			} else {
				http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		tmpf = nil // importStart is now responsible for cleanup.

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ImportProgress{Token: token})

	default:
		http.NotFound(w, r)
	}
}

// ImportProgress is returned after uploading a file to import.
type ImportProgress struct {
	// For fetching progress, or cancelling an import.
	Token string
}

type ctxKey string

var requestInfoCtxKey ctxKey = "requestInfo"

type requestInfo struct {
	LoginAddress string
	AccountName  string
	SessionToken store.SessionToken
	Response     http.ResponseWriter
	Request      *http.Request // For Proto and TLS connection state during message submit.
}

// LoginPrep returns a login token, and also sets it as cookie. Both must be
// present in the call to Login.
func (w Account) LoginPrep(ctx context.Context) string {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	var data [8]byte
	_, err := cryptorand.Read(data[:])
	xcheckf(ctx, err, "generate token")
	loginToken := base64.RawURLEncoding.EncodeToString(data[:])

	webauth.LoginPrep(ctx, log, "webaccount", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken)

	return loginToken
}

// Login returns a session token for the credentials, or fails with error code
// "user:badLogin". Call LoginPrep to get a loginToken.
func (w Account) Login(ctx context.Context, loginToken, username, password string) store.CSRFToken {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	csrfToken, err := webauth.Login(ctx, log, webauth.Accounts, "webaccount", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken, username, password)
	if _, ok := err.(*sherpa.Error); ok {
		panic(err)
	}
	xcheckf(ctx, err, "login")
	return csrfToken
}

// Logout invalidates the session token.
func (w Account) Logout(ctx context.Context) {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := webauth.Logout(ctx, log, webauth.Accounts, "webaccount", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, reqInfo.AccountName, reqInfo.SessionToken)
	xcheckf(ctx, err, "logout")
}

// SetPassword saves a new password for the account, invalidating the previous password.
// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
// Password must be at least 8 characters.
func (Account) SetPassword(ctx context.Context, password string) {
	log := pkglog.WithContext(ctx)
	if len(password) < 8 {
		panic(&sherpa.Error{Code: "user:error", Message: "password must be at least 8 characters"})
	}

	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc, err := store.OpenAccount(log, reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	// Retrieve session, resetting password invalidates it.
	ls, err := store.SessionUse(ctx, log, reqInfo.AccountName, reqInfo.SessionToken, "")
	xcheckf(ctx, err, "get session")

	err = acc.SetPassword(log, password)
	xcheckf(ctx, err, "setting password")

	// Session has been invalidated. Add it again.
	err = store.SessionAddToken(ctx, log, &ls)
	xcheckf(ctx, err, "restoring session after password reset")
}

// Account returns information about the account.
// StorageUsed is the sum of the sizes of all messages, in bytes.
// StorageLimit is the maximum storage that can be used, or 0 if there is no limit.
func (Account) Account(ctx context.Context) (account config.Account, storageUsed, storageLimit int64, suppressions []webapi.Suppression) {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	acc, err := store.OpenAccount(log, reqInfo.AccountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	var accConf config.Account
	acc.WithRLock(func() {
		accConf, _ = acc.Conf()

		storageLimit = acc.QuotaMessageSize()
		err := acc.DB.Read(ctx, func(tx *bstore.Tx) error {
			du := store.DiskUsage{ID: 1}
			err := tx.Get(&du)
			storageUsed = du.MessageSize
			return err
		})
		xcheckf(ctx, err, "get disk usage")
	})

	suppressions, err = queue.SuppressionList(ctx, reqInfo.AccountName)
	xcheckf(ctx, err, "list suppressions")

	return accConf, storageUsed, storageLimit, suppressions
}

// AccountSaveFullName saves the full name (used as display name in email messages)
// for the account.
func (Account) AccountSaveFullName(ctx context.Context, fullName string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		acc.FullName = fullName
	})
	xcheckf(ctx, err, "saving account full name")
}

// DestinationSave updates a destination.
// OldDest is compared against the current destination. If it does not match, an
// error is returned. Otherwise newDest is saved and the configuration reloaded.
func (Account) DestinationSave(ctx context.Context, destName string, oldDest, newDest config.Destination) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := mox.AccountSave(ctx, reqInfo.AccountName, func(conf *config.Account) {
		curDest, ok := conf.Destinations[destName]
		if !ok {
			xcheckuserf(ctx, errors.New("not found"), "looking up destination")
		}
		if !curDest.Equal(oldDest) {
			xcheckuserf(ctx, errors.New("modified"), "checking stored destination")
		}

		// Keep fields we manage.
		newDest.DMARCReports = curDest.DMARCReports
		newDest.HostTLSReports = curDest.HostTLSReports
		newDest.DomainTLSReports = curDest.DomainTLSReports

		// Make copy of reference values.
		nd := map[string]config.Destination{}
		for dn, d := range conf.Destinations {
			nd[dn] = d
		}
		nd[destName] = newDest
		conf.Destinations = nd
	})
	xcheckf(ctx, err, "saving destination")
}

// ImportAbort aborts an import that is in progress. If the import exists and isn't
// finished, no changes will have been made by the import.
func (Account) ImportAbort(ctx context.Context, importToken string) error {
	req := importAbortRequest{importToken, make(chan error)}
	importers.Abort <- req
	return <-req.Response
}

// Types exposes types not used in API method signatures, such as the import form upload.
func (Account) Types() (importProgress ImportProgress) {
	return
}

// SuppressionList lists the addresses on the suppression list of this account.
func (Account) SuppressionList(ctx context.Context) (suppressions []webapi.Suppression) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	l, err := queue.SuppressionList(ctx, reqInfo.AccountName)
	xcheckf(ctx, err, "list suppressions")
	return l
}

// SuppressionAdd adds an email address to the suppression list.
func (Account) SuppressionAdd(ctx context.Context, address string, manual bool, reason string) (suppression webapi.Suppression) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	addr, err := smtp.ParseAddress(address)
	xcheckuserf(ctx, err, "parsing address")
	sup := webapi.Suppression{
		Account: reqInfo.AccountName,
		Manual:  manual,
		Reason:  reason,
	}
	err = queue.SuppressionAdd(ctx, addr.Path(), &sup)
	if err != nil && errors.Is(err, bstore.ErrUnique) {
		xcheckuserf(ctx, err, "add suppression")
	}
	xcheckf(ctx, err, "add suppression")
	return sup
}

// SuppressionRemove removes the email address from the suppression list.
func (Account) SuppressionRemove(ctx context.Context, address string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	addr, err := smtp.ParseAddress(address)
	xcheckuserf(ctx, err, "parsing address")
	err = queue.SuppressionRemove(ctx, reqInfo.AccountName, addr.Path())
	if err != nil && err == bstore.ErrAbsent {
		xcheckuserf(ctx, err, "remove suppression")
	}
	xcheckf(ctx, err, "remove suppression")
}

// OutgoingWebhookSave saves a new webhook url for outgoing deliveries. If url
// is empty, the webhook is disabled. If authorization is non-empty it is used for
// the Authorization header in HTTP requests. Events specifies the outgoing events
// to be delivered, or all if empty/nil.
func (Account) OutgoingWebhookSave(ctx context.Context, url, authorization string, events []string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		if url == "" {
			acc.OutgoingWebhook = nil
		} else {
			acc.OutgoingWebhook = &config.OutgoingWebhook{URL: url, Authorization: authorization, Events: events}
		}
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account outgoing webhook")
	}
	xcheckf(ctx, err, "saving account outgoing webhook")
}

// OutgoingWebhookTest makes a test webhook call to urlStr, with optional
// authorization. If the HTTP request is made this call will succeed also for
// non-2xx HTTP status codes.
func (Account) OutgoingWebhookTest(ctx context.Context, urlStr, authorization string, data webhook.Outgoing) (code int, response string, errmsg string) {
	log := pkglog.WithContext(ctx)

	xvalidURL(ctx, urlStr)
	log.Debug("making webhook test call for outgoing message", slog.String("url", urlStr))

	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	enc.SetEscapeHTML(false)
	err := enc.Encode(data)
	xcheckf(ctx, err, "encoding outgoing webhook data")

	code, response, err = queue.HookPost(ctx, log, 1, 1, urlStr, authorization, b.String())
	if err != nil {
		errmsg = err.Error()
	}
	log.Debugx("result for webhook test call for outgoing message", err, slog.Int("code", code), slog.String("response", response))
	return code, response, errmsg
}

// IncomingWebhookSave saves a new webhook url for incoming deliveries. If url is
// empty, the webhook is disabled. If authorization is not empty, it is used in
// the Authorization header in requests.
func (Account) IncomingWebhookSave(ctx context.Context, url, authorization string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		if url == "" {
			acc.IncomingWebhook = nil
		} else {
			acc.IncomingWebhook = &config.IncomingWebhook{URL: url, Authorization: authorization}
		}
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account incoming webhook")
	}
	xcheckf(ctx, err, "saving account incoming webhook")
}

func xvalidURL(ctx context.Context, s string) {
	u, err := url.Parse(s)
	xcheckuserf(ctx, err, "parsing url")
	if u.Scheme != "http" && u.Scheme != "https" {
		xcheckuserf(ctx, errors.New("scheme must be http or https"), "parsing url")
	}
}

// IncomingWebhookTest makes a test webhook HTTP delivery request to urlStr,
// with optional authorization header. If the HTTP call is made, this function
// returns non-error regardless of HTTP status code.
func (Account) IncomingWebhookTest(ctx context.Context, urlStr, authorization string, data webhook.Incoming) (code int, response string, errmsg string) {
	log := pkglog.WithContext(ctx)

	xvalidURL(ctx, urlStr)
	log.Debug("making webhook test call for incoming message", slog.String("url", urlStr))

	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	err := enc.Encode(data)
	xcheckf(ctx, err, "encoding incoming webhook data")
	code, response, err = queue.HookPost(ctx, log, 1, 1, urlStr, authorization, b.String())
	if err != nil {
		errmsg = err.Error()
	}
	log.Debugx("result for webhook test call for incoming message", err, slog.Int("code", code), slog.String("response", response))
	return code, response, errmsg
}

// FromIDLoginAddressesSave saves new login addresses to enable unique SMTP
// MAIL FROM addresses ("fromid") for deliveries from the queue.
func (Account) FromIDLoginAddressesSave(ctx context.Context, loginAddresses []string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		acc.FromIDLoginAddresses = loginAddresses
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account fromid login addresses")
	}
	xcheckf(ctx, err, "saving account fromid login addresses")
}

// KeepRetiredPeriodsSave saves periods to save retired messages and webhooks.
func (Account) KeepRetiredPeriodsSave(ctx context.Context, keepRetiredMessagePeriod, keepRetiredWebhookPeriod time.Duration) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		acc.KeepRetiredMessagePeriod = keepRetiredMessagePeriod
		acc.KeepRetiredWebhookPeriod = keepRetiredWebhookPeriod
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account keep retired periods")
	}
	xcheckf(ctx, err, "saving account keep retired periods")
}

// AutomaticJunkFlagsSave saves settings for automatically marking messages as
// junk/nonjunk when moved to mailboxes matching certain regular expressions.
func (Account) AutomaticJunkFlagsSave(ctx context.Context, enabled bool, junkRegexp, neutralRegexp, notJunkRegexp string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		acc.AutomaticJunkFlags = config.AutomaticJunkFlags{
			Enabled:              enabled,
			JunkMailboxRegexp:    junkRegexp,
			NeutralMailboxRegexp: neutralRegexp,
			NotJunkMailboxRegexp: notJunkRegexp,
		}
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account automatic junk flags")
	}
	xcheckf(ctx, err, "saving account automatic junk flags")
}

// RejectsSave saves the RejectsMailbox and KeepRejects settings.
func (Account) RejectsSave(ctx context.Context, mailbox string, keep bool) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	err := mox.AccountSave(ctx, reqInfo.AccountName, func(acc *config.Account) {
		acc.RejectsMailbox = mailbox
		acc.KeepRejects = keep
	})
	if err != nil && errors.Is(err, mox.ErrConfig) {
		xcheckuserf(ctx, err, "saving account rejects settings")
	}
	xcheckf(ctx, err, "saving account rejects settings")
}
