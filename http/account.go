package http

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
)

//go:embed accountapi.json
var accountapiJSON []byte

//go:embed account.html
var accountHTML []byte

var accountDoc = mustParseAPI(accountapiJSON)

var accountSherpaHandler http.Handler

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

// Account exports web API functions for the account web interface. All its
// methods are exported under /api/. Function calls require valid HTTP
// Authentication credentials of a user.
type Account struct{}

// check http basic auth, returns account name if valid, and writes http response
// and returns empty string otherwise.
func checkAccountAuth(ctx context.Context, log *mlog.Log, w http.ResponseWriter, r *http.Request) string {
	authResult := "error"
	start := time.Now()
	var addr *net.TCPAddr
	defer func() {
		metrics.AuthenticationInc("httpaccount", "httpbasic", authResult)
		if authResult == "ok" && addr != nil {
			mox.LimiterFailedAuth.Reset(addr.IP, start)
		}
	}()

	var err error
	addr, err = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		log.Errorx("parsing remote address", err, mlog.Field("addr", r.RemoteAddr))
	}
	if addr != nil && !mox.LimiterFailedAuth.Add(addr.IP, start, 1) {
		metrics.AuthenticationRatelimitedInc("httpaccount")
		http.Error(w, "http 429 - too many auth attempts", http.StatusTooManyRequests)
		return ""
	}

	// store.OpenEmailAuth has an auth cache, so we don't bcrypt for every auth attempt.
	if auth := r.Header.Get("Authorization"); auth == "" || !strings.HasPrefix(auth, "Basic ") {
	} else if authBuf, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err != nil {
		log.Debugx("parsing base64", err)
	} else if t := strings.SplitN(string(authBuf), ":", 2); len(t) != 2 {
		log.Debug("bad user:pass form")
	} else if acc, err := store.OpenEmailAuth(t[0], t[1]); err != nil {
		if errors.Is(err, store.ErrUnknownCredentials) {
			authResult = "badcreds"
		}
		log.Errorx("open account", err)
	} else {
		authResult = "ok"
		accName := acc.Name
		acc.Close()
		return accName
	}
	// note: browsers don't display the realm to prevent users getting confused by malicious realm messages.
	w.Header().Set("WWW-Authenticate", `Basic realm="mox account - login with email address and password"`)
	http.Error(w, "http 401 - unauthorized - mox account - login with email address and password", http.StatusUnauthorized)
	return ""
}

func accountHandle(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	log := xlog.WithContext(ctx).Fields(mlog.Field("userauth", ""))

	accName := checkAccountAuth(ctx, log, w, r)
	if accName == "" {
		// Response already sent.
		return
	}

	switch r.URL.Path {
	case "/":
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed - post required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache; max-age=0")
		// We typically return the embedded admin.html, but during development it's handy
		// to load from disk.
		f, err := os.Open("http/account.html")
		if err == nil {
			defer f.Close()
			io.Copy(w, f)
		} else {
			w.Write(accountHTML)
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
		defer acc.Close()

		var archiver store.Archiver
		if tgz {
			// Don't tempt browsers to "helpfully" decompress.
			w.Header().Set("Content-Type", "application/octet-stream")

			gzw := gzip.NewWriter(w)
			defer func() {
				gzw.Close()
			}()
			archiver = store.TarArchiver{Writer: tar.NewWriter(gzw)}
		} else {
			w.Header().Set("Content-Type", "application/zip")
			archiver = store.ZipArchiver{Writer: zip.NewWriter(w)}
		}
		defer func() {
			if err := archiver.Close(); err != nil {
				log.Errorx("exporting mail close", err)
			}
		}()
		if err := store.ExportMessages(log, acc.DB, acc.Dir, archiver, maildir, ""); err != nil {
			log.Errorx("exporting mail", err)
		}

	default:
		if strings.HasPrefix(r.URL.Path, "/api/") {
			accountSherpaHandler.ServeHTTP(w, r.WithContext(context.WithValue(ctx, authCtxKey, accName)))
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
	defer acc.Close()
	err = acc.SetPassword(password)
	xcheckf(ctx, err, "setting password")
}

// Destinations returns the default domain, and the destinations (keys are email
// addresses, or localparts to the default domain).
// todo: replace with a function that returns the whole account, when sherpadoc understands unnamed struct fields.
func (Account) Destinations(ctx context.Context) (dns.Domain, map[string]config.Destination) {
	accountName := ctx.Value(authCtxKey).(string)
	accConf, ok := mox.Conf.Account(accountName)
	if !ok {
		xcheckf(ctx, errors.New("not found"), "looking up account")
	}
	return accConf.DNSDomain, accConf.Destinations
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
		xcheckf(ctx, errors.New("not found"), "looking up destination")
	}

	if !curDest.Equal(oldDest) {
		xcheckf(ctx, errors.New("modified"), "checking stored destination")
	}

	// Keep fields we manage.
	newDest.DMARCReports = curDest.DMARCReports
	newDest.TLSReports = curDest.TLSReports

	err := mox.DestinationSave(ctx, accountName, destName, newDest)
	xcheckf(ctx, err, "saving destination")
}
