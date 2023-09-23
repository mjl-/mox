// Package webaccount provides a web app for users to view and change their account
// settings, and to import/export email.
package webaccount

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
)

func init() {
	mox.LimitersInit()
}

var xlog = mlog.New("webaccount")

//go:embed accountapi.json
var accountapiJSON []byte

//go:embed account.html
var accountHTML []byte

var accountDoc = mustParseAPI("account", accountapiJSON)

var accountSherpaHandler http.Handler

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		xlog.Fatalx("parsing api docs", err, mlog.Field("api", api))
	}
	return doc
}

func init() {
	collector, err := sherpaprom.NewCollector("moxaccount", nil)
	if err != nil {
		xlog.Fatalx("creating sherpa prometheus collector", err)
	}

	accountSherpaHandler, err = sherpa.NewHandler("/api/", moxvar.Version, Account{}, &accountDoc, &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none"})
	if err != nil {
		xlog.Fatalx("sherpa handler", err)
	}
}

func xcheckf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	xlog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "server:error", Message: errmsg})
}

func xcheckuserf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	xlog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "user:error", Message: errmsg})
}

// Account exports web API functions for the account web interface. All its
// methods are exported under api/. Function calls require valid HTTP
// Authentication credentials of a user.
type Account struct{}

// CheckAuth checks http basic auth, returns login address and account name if
// valid, and writes http response and returns empty string otherwise.
func CheckAuth(ctx context.Context, log *mlog.Log, kind string, w http.ResponseWriter, r *http.Request) (address, account string) {
	authResult := "error"
	start := time.Now()
	var addr *net.TCPAddr
	defer func() {
		metrics.AuthenticationInc(kind, "httpbasic", authResult)
		if authResult == "ok" && addr != nil {
			mox.LimiterFailedAuth.Reset(addr.IP, start)
		}
	}()

	var err error
	var remoteIP net.IP
	addr, err = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		log.Errorx("parsing remote address", err, mlog.Field("addr", r.RemoteAddr))
	} else if addr != nil {
		remoteIP = addr.IP
	}
	if remoteIP != nil && !mox.LimiterFailedAuth.Add(remoteIP, start, 1) {
		metrics.AuthenticationRatelimitedInc(kind)
		http.Error(w, "429 - too many auth attempts", http.StatusTooManyRequests)
		return "", ""
	}

	// store.OpenEmailAuth has an auth cache, so we don't bcrypt for every auth attempt.
	if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Basic ") {
	} else if authBuf, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err != nil {
		log.Debugx("parsing base64", err)
	} else if t := strings.SplitN(string(authBuf), ":", 2); len(t) != 2 {
		log.Debug("bad user:pass form")
	} else if acc, err := store.OpenEmailAuth(t[0], t[1]); err != nil {
		if errors.Is(err, store.ErrUnknownCredentials) {
			authResult = "badcreds"
			log.Info("failed authentication attempt", mlog.Field("username", t[0]), mlog.Field("remote", remoteIP))
		}
		log.Errorx("open account", err)
	} else {
		authResult = "ok"
		accName := acc.Name
		err := acc.Close()
		log.Check(err, "closing account")
		return t[0], accName
	}
	// note: browsers don't display the realm to prevent users getting confused by malicious realm messages.
	w.Header().Set("WWW-Authenticate", `Basic realm="mox account - login with account email address and password"`)
	http.Error(w, "http 401 - unauthorized - mox account - login with account email address and password", http.StatusUnauthorized)
	return "", ""
}

func Handle(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	log := xlog.WithContext(ctx).Fields(mlog.Field("userauth", ""))

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

	_, accName := CheckAuth(ctx, log, "webaccount", w, r)
	if accName == "" {
		// Response already sent.
		return
	}

	if lw, ok := w.(interface{ AddField(p mlog.Pair) }); ok {
		lw.AddField(mlog.Field("authaccount", accName))
	}

	switch r.URL.Path {
	case "/":
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed - get required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache; max-age=0")
		// We typically return the embedded admin.html, but during development it's handy
		// to load from disk.
		f, err := os.Open("webaccount/account.html")
		if err == nil {
			defer f.Close()
			_, _ = io.Copy(w, f)
		} else {
			_, _ = w.Write(accountHTML)
		}

	case "/mail-export-maildir.tgz", "/mail-export-maildir.zip", "/mail-export-mbox.tgz", "/mail-export-mbox.zip":
		maildir := strings.Contains(r.URL.Path, "maildir")
		tgz := strings.Contains(r.URL.Path, ".tgz")

		acc, err := store.OpenAccount(accName)
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
				err := tmpf.Close()
				log.Check(err, "closing uploaded file")
			}
		}()
		if err := os.Remove(tmpf.Name()); err != nil {
			log.Errorx("removing temporary file", err)
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(tmpf, f); err != nil {
			log.Errorx("copying import to temporary file", err)
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		token, err := importStart(log, accName, tmpf, skipMailboxPrefix)
		if err != nil {
			log.Errorx("starting import", err)
			http.Error(w, "500 - internal server error - "+err.Error(), http.StatusInternalServerError)
			return
		}
		tmpf = nil // importStart is now responsible for closing.

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ImportToken": token})

	default:
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ctx = context.WithValue(ctx, authCtxKey, accName)
			accountSherpaHandler.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		http.NotFound(w, r)
	}
}

type ctxKey string

var authCtxKey ctxKey = "account"

// SetPassword saves a new password for the account, invalidating the previous password.
// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
// Password must be at least 8 characters.
func (Account) SetPassword(ctx context.Context, password string) {
	if len(password) < 8 {
		panic(&sherpa.Error{Code: "user:error", Message: "password must be at least 8 characters"})
	}
	accountName := ctx.Value(authCtxKey).(string)
	acc, err := store.OpenAccount(accountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		xlog.Check(err, "closing account")
	}()
	err = acc.SetPassword(password)
	xcheckf(ctx, err, "setting password")
}

// Account returns information about the account: full name, the default domain,
// and the destinations (keys are email addresses, or localparts to the default
// domain). todo: replace with a function that returns the whole account, when
// sherpadoc understands unnamed struct fields.
func (Account) Account(ctx context.Context) (string, dns.Domain, map[string]config.Destination) {
	accountName := ctx.Value(authCtxKey).(string)
	accConf, ok := mox.Conf.Account(accountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	return accConf.FullName, accConf.DNSDomain, accConf.Destinations
}

func (Account) AccountSaveFullName(ctx context.Context, fullName string) {
	accountName := ctx.Value(authCtxKey).(string)
	_, ok := mox.Conf.Account(accountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	err := mox.AccountFullNameSave(ctx, accountName, fullName)
	xcheckf(ctx, err, "saving account full name")
}

// DestinationSave updates a destination.
// OldDest is compared against the current destination. If it does not match, an
// error is returned. Otherwise newDest is saved and the configuration reloaded.
func (Account) DestinationSave(ctx context.Context, destName string, oldDest, newDest config.Destination) {
	accountName := ctx.Value(authCtxKey).(string)
	accConf, ok := mox.Conf.Account(accountName)
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
	newDest.TLSReports = curDest.TLSReports

	err := mox.DestinationSave(ctx, accountName, destName, newDest)
	xcheckf(ctx, err, "saving destination")
}

// ImportAbort aborts an import that is in progress. If the import exists and isn't
// finished, no changes will have been made by the import.
func (Account) ImportAbort(ctx context.Context, importToken string) error {
	req := importAbortRequest{importToken, make(chan error)}
	importers.Abort <- req
	return <-req.Response
}
