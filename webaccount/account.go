// Package webaccount provides a web app for users to view and change their account
// settings, and to import/export email.
package webaccount

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "embed"

	"golang.org/x/exp/slog"

	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webauth"
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
		isExport := strings.HasPrefix(r.URL.Path, "/export/")
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
	case "/export/mail-export-maildir.tgz", "/export/mail-export-maildir.zip", "/export/mail-export-mbox.tgz", "/export/mail-export-mbox.zip":
		if r.Method != "POST" {
			http.Error(w, "405 - method not allowed - use post", http.StatusMethodNotAllowed)
			return
		}

		maildir := strings.Contains(r.URL.Path, "maildir")
		tgz := strings.Contains(r.URL.Path, ".tgz")

		acc, err := store.OpenAccount(log, accName)
		if err != nil {
			log.Errorx("open account for export", err)
			http.Error(w, "500 - internal server error", http.StatusInternalServerError)
			return
		}
		defer func() {
			err := acc.Close()
			log.Check(err, "closing account")
		}()

		var archiver store.Archiver
		if tgz {
			// Don't tempt browsers to "helpfully" decompress.
			w.Header().Set("Content-Type", "application/octet-stream")

			gzw := gzip.NewWriter(w)
			defer func() {
				_ = gzw.Close()
			}()
			archiver = store.TarArchiver{Writer: tar.NewWriter(gzw)}
		} else {
			w.Header().Set("Content-Type", "application/zip")
			archiver = store.ZipArchiver{Writer: zip.NewWriter(w)}
		}
		defer func() {
			err := archiver.Close()
			log.Check(err, "exporting mail close")
		}()
		if err := store.ExportMessages(r.Context(), log, acc.DB, acc.Dir, archiver, maildir, ""); err != nil {
			log.Errorx("exporting mail", err)
		}

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

// Account returns information about the account: full name, the default domain,
// and the destinations (keys are email addresses, or localparts to the default
// domain). todo: replace with a function that returns the whole account, when
// sherpadoc understands unnamed struct fields.
func (Account) Account(ctx context.Context) (string, dns.Domain, map[string]config.Destination) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	accConf, ok := mox.Conf.Account(reqInfo.AccountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	return accConf.FullName, accConf.DNSDomain, accConf.Destinations
}

func (Account) AccountSaveFullName(ctx context.Context, fullName string) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	_, ok := mox.Conf.Account(reqInfo.AccountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	err := mox.AccountFullNameSave(ctx, reqInfo.AccountName, fullName)
	xcheckf(ctx, err, "saving account full name")
}

// DestinationSave updates a destination.
// OldDest is compared against the current destination. If it does not match, an
// error is returned. Otherwise newDest is saved and the configuration reloaded.
func (Account) DestinationSave(ctx context.Context, destName string, oldDest, newDest config.Destination) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	accConf, ok := mox.Conf.Account(reqInfo.AccountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	curDest, ok := accConf.Destinations[destName]
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

	err := mox.DestinationSave(ctx, reqInfo.AccountName, destName, newDest)
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
