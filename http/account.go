package http

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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

	accountSherpaHandler, err = sherpa.NewHandler("/account/api/", moxvar.Version, Account{}, &accountDoc, &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none"})
	if err != nil {
		xlog.Fatalx("sherpa handler", err)
	}
}

// Account exports web API functions for the account web interface. All its
// methods are exported under /account/api/. Function calls require valid HTTP
// Authentication credentials of a user.
type Account struct{}

func accountHandle(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	log := xlog.WithContext(ctx).Fields(mlog.Field("userauth", ""))
	var accountName string
	authResult := "error"
	defer func() {
		metrics.AuthenticationInc("httpaccount", "httpbasic", authResult)
	}()
	// todo: should probably add a cache here instead of looking up password in database all the time, just like in admin.go
	if auth := r.Header.Get("Authorization"); auth == "" || !strings.HasPrefix(auth, "Basic ") {
	} else if authBuf, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err != nil {
		log.Infox("parsing base64", err)
	} else if t := strings.SplitN(string(authBuf), ":", 2); len(t) != 2 {
		log.Info("bad user:pass form")
	} else if acc, err := store.OpenEmailAuth(t[0], t[1]); err != nil {
		if errors.Is(err, store.ErrUnknownCredentials) {
			authResult = "badcreds"
		}
		log.Infox("open account", err)
	} else {
		accountName = acc.Name
		authResult = "ok"
	}
	if accountName == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="mox account - login with email address and password"`)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "http 401 - unauthorized - mox account - login with email address and password")
		return
	}

	if r.Method == "GET" && r.URL.Path == "/account/" {
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
		return
	}
	accountSherpaHandler.ServeHTTP(w, r.WithContext(context.WithValue(ctx, authCtxKey, accountName)))
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
