// Package webmail implements a webmail client, serving html/js and providing an API for message actions and SSE endpoint for receiving real-time updates.
package webmail

// todo: should we be serving the messages/parts on a separate (sub)domain for user-content? to limit damage if the csp rules aren't enough.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"golang.org/x/net/html"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webauth"
	"github.com/mjl-/mox/webops"
)

var pkglog = mlog.New("webmail", nil)

type ctxKey string

// We pass the request to the sherpa handler so the TLS info can be used for
// the Received header in submitted messages. Most API calls need just the
// account name.
var requestInfoCtxKey ctxKey = "requestInfo"

type requestInfo struct {
	Log          mlog.Log
	LoginAddress string
	Account      *store.Account // Nil only for methods Login and LoginPrep.
	SessionToken store.SessionToken
	Response     http.ResponseWriter
	Request      *http.Request // For Proto and TLS connection state during message submit.
}

//go:embed webmail.html
var webmailHTML []byte

//go:embed webmail.js
var webmailJS []byte

//go:embed msg.html
var webmailmsgHTML []byte

//go:embed msg.js
var webmailmsgJS []byte

//go:embed text.html
var webmailtextHTML []byte

//go:embed text.js
var webmailtextJS []byte

var (
	// Similar between ../webmail/webmail.go:/metricSubmission and ../smtpserver/server.go:/metricSubmission and ../webapisrv/server.go:/metricSubmission
	metricSubmission = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webmail_submission_total",
			Help: "Webmail message submission results, known values (those ending with error are server errors): ok, badfrom, messagelimiterror, recipientlimiterror, queueerror, storesenterror, domaindisabled.",
		},
		[]string{
			"result",
		},
	)
	metricServerErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webmail_errors_total",
			Help: "Webmail server errors, known values: dkimsign, submit.",
		},
		[]string{
			"error",
		},
	)
	metricSSEConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "mox_webmail_sse_connections",
			Help: "Number of active webmail SSE connections.",
		},
	)
)

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

func xdbwrite(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx)) {
	err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(ctx, err, "transaction")
}

func xdbread(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx)) {
	err := acc.DB.Read(ctx, func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(ctx, err, "transaction")
}

var webmailFile = &mox.WebappFile{
	HTML:       webmailHTML,
	JS:         webmailJS,
	HTMLPath:   filepath.FromSlash("webmail/webmail.html"),
	JSPath:     filepath.FromSlash("webmail/webmail.js"),
	CustomStem: "webmail",
}

func customization() (css, js []byte, err error) {
	if css, err = os.ReadFile(mox.ConfigDirPath("webmail.css")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	if js, err = os.ReadFile(mox.ConfigDirPath("webmail.js")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	css = append([]byte("/* Custom CSS by admin from $configdir/webmail.css: */\n"), css...)
	js = append([]byte("// Custom JS by admin from $configdir/webmail.js:\n"), js...)
	js = append(js, '\n')
	return css, js, nil
}

// Serve HTML content, either from a file, or return the fallback data. If
// customize is set, css/js is inserted if configured. Caller should already have
// set the content-type. We use this to return a file from the local file system
// (during development), or embedded in the binary (when deployed).
func serveContentFallback(log mlog.Log, w http.ResponseWriter, r *http.Request, path string, fallback []byte, customize bool) {
	serve := func(mtime time.Time, rd io.ReadSeeker) {
		if customize {
			buf, err := io.ReadAll(rd)
			if err != nil {
				log.Errorx("reading content to customize", err)
				http.Error(w, "500 - internal server error - reading content to customize", http.StatusInternalServerError)
				return
			}
			customCSS, customJS, err := customization()
			if err != nil {
				log.Errorx("reading customizations", err)
				http.Error(w, "500 - internal server error - reading customizations", http.StatusInternalServerError)
				return
			}
			buf = bytes.Replace(buf, []byte("/* css placeholder */"), customCSS, 1)
			buf = bytes.Replace(buf, []byte("/* js placeholder */"), customJS, 1)
			rd = bytes.NewReader(buf)
		}
		http.ServeContent(w, r, "", mtime, rd)
	}

	f, err := os.Open(path)
	if err == nil {
		defer func() {
			err := f.Close()
			log.Check(err, "closing serve file")
		}()
		st, err := f.Stat()
		if err == nil {
			serve(st.ModTime(), f)
			return
		}
	}
	serve(mox.FallbackMtime(log), bytes.NewReader(fallback))
}

func init() {
	mox.NewWebmailHandler = func(maxMsgSize int64, basePath string, isForwarded bool, accountPath string) http.Handler {
		return http.HandlerFunc(Handler(maxMsgSize, basePath, isForwarded, accountPath))
	}
}

// Handler returns a handler for the webmail endpoints, customized for the max
// message size coming from the listener and cookiePath.
func Handler(maxMessageSize int64, cookiePath string, isForwarded bool, accountPath string) func(w http.ResponseWriter, r *http.Request) {
	sh, err := makeSherpaHandler(maxMessageSize, cookiePath, isForwarded)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "500 - internal server error - cannot handle requests", http.StatusInternalServerError)
			return
		}
		handle(sh, isForwarded, accountPath, w, r)
	}
}

func handle(apiHandler http.Handler, isForwarded bool, accountPath string, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := pkglog.WithContext(ctx).With(slog.String("userauth", ""))

	// Server-sent event connection, for all initial data (list of mailboxes), list of
	// messages, and all events afterwards. Authenticated through a single use token in
	// the query string, which it got from a Token API call.
	if r.URL.Path == "/events" {
		serveEvents(ctx, log, accountPath, w, r)
		return
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		err, ok := x.(*sherpa.Error)
		if !ok {
			log.WithContext(ctx).Error("handle panic", slog.Any("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Webmailhandle)
			panic(x)
		}
		if strings.HasPrefix(err.Code, "user:") {
			log.Debugx("webmail user error", err)
			http.Error(w, "400 - bad request - "+err.Message, http.StatusBadRequest)
		} else {
			log.Errorx("webmail server error", err)
			http.Error(w, "500 - internal server error - "+err.Message, http.StatusInternalServerError)
		}
	}()

	switch r.URL.Path {
	case "/":
		switch r.Method {
		case "GET", "HEAD":
			h := w.Header()
			h.Set("X-Frame-Options", "deny")
			h.Set("Referrer-Policy", "same-origin")
			webmailFile.Serve(ctx, log, w, r)
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		}
		return

	case "/licenses.txt":
		switch r.Method {
		case "GET", "HEAD":
			h := w.Header()
			h.Set("Content-Type", "text/plain; charset=utf-8")
			mox.LicensesWrite(w)
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		}
		return

	case "/msg.js", "/text.js":
		switch r.Method {
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
			return
		case "GET", "HEAD":
		}

		path := filepath.Join("webmail", r.URL.Path[1:])
		var fallback = webmailmsgJS
		if r.URL.Path == "/text.js" {
			fallback = webmailtextJS
		}

		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		serveContentFallback(log, w, r, path, fallback, false)
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
		requireCSRF := isAPI || isExport
		accName, sessionToken, loginAddress, ok = webauth.Check(ctx, log, webauth.Accounts, "webmail", isForwarded, w, r, isAPI, requireCSRF, isExport)
		if !ok {
			// Response has been written already.
			return
		}
	}

	if isAPI {
		var acc *store.Account
		if accName != "" {
			log = log.With(slog.String("account", accName))
			var err error
			acc, err = store.OpenAccount(log, accName, true)
			if err != nil {
				log.Errorx("open account", err)
				http.Error(w, "500 - internal server error - error opening account", http.StatusInternalServerError)
				return
			}
			defer func() {
				err := acc.Close()
				log.Check(err, "closing account")
			}()
		}
		reqInfo := requestInfo{log, loginAddress, acc, sessionToken, w, r}
		ctx = context.WithValue(ctx, requestInfoCtxKey, reqInfo)
		apiHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	// We are now expecting the following URLs:
	// .../export
	// .../msg/<msgid>/{attachments.zip,parsedmessage.js,raw}
	// .../msg/<msgid>/{,msg}{text,html,htmlexternal}
	// .../msg/<msgid>/{view,viewtext,download}/<partid>

	if r.URL.Path == "/export" {
		webops.Export(log, accName, w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/msg/") {
		http.NotFound(w, r)
		return
	}

	t := strings.Split(r.URL.Path[len("/msg/"):], "/")
	if len(t) < 2 {
		http.NotFound(w, r)
		return
	}

	id, err := strconv.ParseInt(t[0], 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return
	}

	// Many of the requests need either a message or a parsed part. Make it easy to
	// fetch/prepare and cleanup. We only do all the work when the request seems legit
	// (valid HTTP route and method).
	xprepare := func() (acc *store.Account, moreHeaders []string, m store.Message, msgr *store.MsgReader, p message.Part, cleanup func(), ok bool) {
		if r.Method != "GET" {
			http.Error(w, "405 - method not allowed - post required", http.StatusMethodNotAllowed)
			return
		}

		defer func() {
			if ok {
				return
			}
			if msgr != nil {
				err := msgr.Close()
				log.Check(err, "closing message reader")
				msgr = nil
			}
			if acc != nil {
				err := acc.Close()
				log.Check(err, "closing account")
				acc = nil
			}
		}()

		var err error

		acc, err = store.OpenAccount(log, accName, false)
		xcheckf(ctx, err, "open account")

		m = store.Message{ID: id}
		err = acc.DB.Read(ctx, func(tx *bstore.Tx) error {
			if err := tx.Get(&m); err != nil {
				return err
			} else if m.Expunged {
				return fmt.Errorf("message was removed")
			}
			s := store.Settings{ID: 1}
			if err := tx.Get(&s); err != nil {
				return fmt.Errorf("get settings for more headers: %v", err)
			}
			moreHeaders = s.ShowHeaders
			return nil
		})
		if err == bstore.ErrAbsent || err == nil && m.Expunged {
			http.NotFound(w, r)
			return
		}
		xcheckf(ctx, err, "get message")

		msgr = acc.MessageReader(m)

		p, err = m.LoadPart(msgr)
		xcheckf(ctx, err, "load parsed message")

		cleanup = func() {
			err := msgr.Close()
			log.Check(err, "closing message reader")
			err = acc.Close()
			log.Check(err, "closing account")
		}
		ok = true
		return
	}

	h := w.Header()

	// We set a Content-Security-Policy header that is as strict as possible, depending
	// on the type of message/part/html/js. We have to be careful because we are
	// returning data that is coming in from external places. E.g. HTML could contain
	// javascripts that we don't want to execute, especially not on our domain. We load
	// resources in an iframe. The CSP policy starts out  with default-src 'none' to
	// disallow loading anything, then start allowing what is safe, such as inlined
	// datauri images and inline styles. Data can only be loaded when the request is
	// coming from the same origin (so other sites cannot include resources
	// (messages/parts)).
	//
	// We want to load resources in sandbox-mode, causing the page to be loaded as from
	// a different origin. If sameOrigin is set, we have a looser CSP policy:
	// allow-same-origin is set so resources are loaded as coming from this same
	// origin. This is needed for the msg* endpoints that render a message, where we
	// load the message body in a separate iframe again (with stricter CSP again),
	// which we need to access for its inner height. If allowSelfScript is also set
	// (for "msgtext"), the CSP leaves out the sandbox entirely.
	//
	// If allowExternal is set, we allow loading image, media (audio/video), styles and
	// fronts from external URLs as well as inline URI's. By default we don't allow any
	// loading of content, except inlined images (we do that ourselves for images
	// embedded in the email), and we allow inline styles (which are safely constrained
	// to an iframe).
	//
	// If allowSelfScript is set, inline scripts and scripts from our origin are
	// allowed. Used to display a message including header. The header is rendered with
	// javascript, the content is rendered in a separate iframe with a CSP that doesn't
	// have allowSelfScript.
	headers := func(sameOrigin, allowExternal, allowSelfScript, allowSelfImg bool) {
		// allow-popups is needed to make opening links in new tabs work.
		sb := "sandbox allow-popups allow-popups-to-escape-sandbox; "
		if sameOrigin && allowSelfScript {
			// Sandbox with both allow-same-origin and allow-script would not provide security,
			// and would give warning in console about that.
			sb = ""
		} else if sameOrigin {
			sb = "sandbox allow-popups allow-popups-to-escape-sandbox allow-same-origin; "
		}
		script := ""
		if allowSelfScript {
			script = "; script-src 'unsafe-inline' 'self'; frame-src 'self'; connect-src 'self'"
		}
		var csp string
		if allowExternal {
			csp = sb + "frame-ancestors 'self'; default-src 'none'; img-src data: http: https: 'unsafe-inline'; style-src 'unsafe-inline' data: http: https:; font-src data: http: https: 'unsafe-inline'; media-src 'unsafe-inline' data: http: https:" + script
		} else if allowSelfImg {
			csp = sb + "frame-ancestors 'self'; default-src 'none'; img-src data: 'self'; style-src 'unsafe-inline'" + script
		} else {
			csp = sb + "frame-ancestors 'self'; default-src 'none'; img-src data:; style-src 'unsafe-inline'" + script
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "sameorigin") // Duplicate with CSP, but better too much than too little.
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
	}

	switch {
	case len(t) == 2 && t[1] == "attachments.zip":
		acc, _, m, msgr, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()
		state := msgState{acc: acc, m: m, msgr: msgr, part: &p}
		// note: state is cleared by cleanup

		mi, err := messageItem(log, m, &state, nil)
		xcheckf(ctx, err, "parsing message")

		headers(false, false, false, false)
		h.Set("Content-Type", "application/zip")
		h.Set("Cache-Control", "no-store, max-age=0")
		var subjectSlug string
		if p.Envelope != nil {
			s := p.Envelope.Subject
			s = strings.ToLower(s)
			s = regexp.MustCompile("[^a-z0-9_.-]").ReplaceAllString(s, "-")
			s = regexp.MustCompile("--*").ReplaceAllString(s, "-")
			s = strings.TrimLeft(s, "-")
			s = strings.TrimRight(s, "-")
			if s != "" {
				s = "-" + s
			}
			subjectSlug = s
		}
		filename := fmt.Sprintf("email-%d-attachments-%s%s.zip", m.ID, m.Received.Format("20060102-150405"), subjectSlug)
		cd := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
		h.Set("Content-Disposition", cd)

		zw := zip.NewWriter(w)
		names := map[string]bool{}
		for _, a := range mi.Attachments {
			ap := a.Part
			_, name, err := ap.DispositionFilename()
			if err != nil && errors.Is(err, message.ErrParamEncoding) {
				log.Debugx("parsing disposition header for filename", err)
			} else {
				xcheckf(ctx, err, "reading disposition header")
			}
			if name != "" {
				name = filepath.Base(name)
			}
			mt := strings.ToLower(ap.MediaType + "/" + ap.MediaSubType)
			if name == "" || names[name] {
				ext := filepath.Ext(name)
				if ext == "" {
					// Handle just a few basic types.
					extensions := map[string]string{
						"text/plain":      ".txt",
						"text/html":       ".html",
						"image/jpeg":      ".jpg",
						"image/png":       ".png",
						"image/gif":       ".gif",
						"application/zip": ".zip",
					}
					ext = extensions[mt]
					if ext == "" {
						ext = ".bin"
					}
				}
				var stem string
				if name != "" && strings.HasSuffix(name, ext) {
					stem = strings.TrimSuffix(name, ext)
				} else {
					stem = "attachment"
					for _, index := range a.Path {
						stem += fmt.Sprintf("-%d", index)
					}
				}
				name = stem + ext
				seq := 0
				for names[name] {
					seq++
					name = stem + fmt.Sprintf("-%d", seq) + ext
				}
			}
			names[name] = true

			fh := zip.FileHeader{
				Name:     name,
				Modified: m.Received,
			}
			nodeflate := map[string]bool{
				"application/x-bzip2":          true,
				"application/zip":              true,
				"application/x-zip-compressed": true,
				"application/gzip":             true,
				"application/x-gzip":           true,
				"application/vnd.rar":          true,
				"application/x-rar-compressed": true,
				"application/x-7z-compressed":  true,
			}
			// Sniff content-type as well for compressed data.
			buf := make([]byte, 512)
			n, _ := io.ReadFull(ap.Reader(), buf)
			var sniffmt string
			if n > 0 {
				sniffmt = strings.ToLower(http.DetectContentType(buf[:n]))
			}
			deflate := ap.MediaType != "VIDEO" && ap.MediaType != "AUDIO" && (ap.MediaType != "IMAGE" || ap.MediaSubType == "BMP") && !nodeflate[mt] && !nodeflate[sniffmt]
			if deflate {
				fh.Method = zip.Deflate
			}
			// We cannot return errors anymore: we have already sent an application/zip header.
			if zf, err := zw.CreateHeader(&fh); err != nil {
				log.Check(err, "adding to zip file")
				return
			} else if _, err := io.Copy(zf, ap.Reader()); err != nil {
				log.Check(err, "writing to zip file")
				return
			}
		}
		err = zw.Close()
		log.Check(err, "final write to zip file")

	// Raw display or download of a message, as text/plain.
	case len(t) == 2 && (t[1] == "raw" || t[1] == "rawdl"):
		_, _, m, msgr, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()

		headers(false, false, false, false)

		// We intentially use text/plain. We certainly don't want to return a format that
		// browsers or users would think of executing. We do set the charset if available
		// on the outer part. If present, we assume it may be relevant for other parts. If
		// not, there is not much we could do better...
		ct := "text/plain"
		params := map[string]string{}

		if t[1] == "rawdl" {
			ct = "message/rfc822"
			if smtputf8, err := p.NeedsSMTPUTF8(); err != nil {
				log.Errorx("checking for smtputf8 for content-type", err, slog.Int64("msgid", m.ID))
				http.Error(w, "500 - server error - checking message for content-type: "+err.Error(), http.StatusInternalServerError)
				return
			} else if smtputf8 {
				ct = "message/global"
				params["charset"] = "utf-8"
			}
		} else if charset := p.ContentTypeParams["charset"]; charset != "" {
			params["charset"] = charset
		}
		h.Set("Content-Type", mime.FormatMediaType(ct, params))
		if t[1] == "rawdl" {
			filename := fmt.Sprintf("email-%d-%s.eml", m.ID, m.Received.Format("20060102-150405"))
			cd := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
			h.Set("Content-Disposition", cd)
		}
		h.Set("Cache-Control", "no-store, max-age=0")

		_, err := io.Copy(w, &moxio.AtReader{R: msgr})
		log.Check(err, "writing raw")

	case len(t) == 2 && (t[1] == "msgtext" || t[1] == "msghtml" || t[1] == "msghtmlexternal"):
		// msg.html has a javascript tag with message data, and javascript to render the
		// message header like the regular webmail.html and to load the message body in a
		// separate iframe with a separate request with stronger CSP.
		acc, _, m, msgr, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()

		state := msgState{acc: acc, m: m, msgr: msgr, part: &p}
		// note: state is cleared by cleanup

		pm, err := parsedMessage(log, &m, &state, true, true, true)
		xcheckf(ctx, err, "getting parsed message")
		if t[1] == "msgtext" && len(pm.Texts) == 0 || t[1] != "msgtext" && !pm.HasHTML {
			http.Error(w, "400 - bad request - no such part", http.StatusBadRequest)
			return
		}

		sameorigin := true
		loadExternal := t[1] == "msghtmlexternal"
		allowSelfScript := true
		headers(sameorigin, loadExternal, allowSelfScript, false)
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store, max-age=0")

		path := filepath.FromSlash("webmail/msg.html")
		fallback := webmailmsgHTML
		serveContentFallback(log, w, r, path, fallback, true)

	case len(t) == 2 && t[1] == "parsedmessage.js":
		// Used by msg.html, for the msg* endpoints, for the data needed to show all data
		// except the message body.
		// This is js with data inside instead so we can load it synchronously, which we do
		// to get a "loaded" event after the page was actually loaded.

		acc, moreHeaders, m, msgr, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()
		state := msgState{acc: acc, m: m, msgr: msgr, part: &p}
		// note: state is cleared by cleanup

		pm, err := parsedMessage(log, &m, &state, true, true, true)
		xcheckf(ctx, err, "parsing parsedmessage")
		pmjson, err := json.Marshal(pm)
		xcheckf(ctx, err, "marshal parsedmessage")

		m.MsgPrefix = nil
		m.ParsedBuf = nil
		hl := messageItemMoreHeaders(moreHeaders, pm)
		mi := MessageItem{m, pm.envelope, pm.attachments, pm.isSigned, pm.isEncrypted, false, hl}
		mijson, err := json.Marshal(mi)
		xcheckf(ctx, err, "marshal messageitem")

		headers(false, false, false, false)
		h.Set("Content-Type", "application/javascript; charset=utf-8")
		h.Set("Cache-Control", "no-store, max-age=0")

		_, err = fmt.Fprintf(w, "window.messageItem = %s;\nwindow.parsedMessage = %s;\n", mijson, pmjson)
		log.Check(err, "writing parsedmessage.js")

	case len(t) == 2 && t[1] == "text":
		// Returns text.html whichs loads the message data with a javascript tag and
		// renders just the text content with the same code as webmail.html. Used by the
		// iframe in the msgtext endpoint. Not used by the regular webmail viewer, it
		// renders the text itself, with the same shared js code.
		acc, _, m, msgr, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()

		state := msgState{acc: acc, m: m, msgr: msgr, part: &p}
		// note: state is cleared by cleanup

		pm, err := parsedMessage(log, &m, &state, true, true, true)
		xcheckf(ctx, err, "parsing parsedmessage")

		if len(pm.Texts) == 0 {
			http.Error(w, "400 - bad request - no text part in message", http.StatusBadRequest)
			return
		}

		// Needed for inner document height for outer iframe height in separate message view.
		sameorigin := true
		allowSelfScript := true
		allowSelfImg := true
		headers(sameorigin, false, allowSelfScript, allowSelfImg)
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store, max-age=0")

		// We typically return the embedded file, but during development it's handy to load
		// from disk.
		path := filepath.FromSlash("webmail/text.html")
		fallback := webmailtextHTML
		serveContentFallback(log, w, r, path, fallback, true)

	case len(t) == 2 && (t[1] == "html" || t[1] == "htmlexternal"):
		// Returns the first HTML part, with "cid:" URIs replaced with an inlined datauri
		// if the referenced Content-ID attachment can be found.
		_, _, _, _, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()

		setHeaders := func() {
			// Needed for inner document height for outer iframe height in separate message
			// view. We only need that when displaying as a separate message on the msghtml*
			// endpoints. When displaying in the regular webmail, we don't need to know the
			// inner height so we load it as different origin, which should be safer.
			sameorigin := r.URL.Query().Get("sameorigin") == "true"
			allowExternal := strings.HasSuffix(t[1], "external")
			headers(sameorigin, allowExternal, false, false)

			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("Cache-Control", "no-store, max-age=0")
		}

		// todo: skip certain html parts? e.g. with content-disposition: attachment?
		var done bool
		var usePart func(p *message.Part, parents []*message.Part)
		usePart = func(p *message.Part, parents []*message.Part) {
			if done {
				return
			}
			mt := p.MediaType + "/" + p.MediaSubType
			switch mt {
			case "TEXT/HTML":
				done = true
				err := inlineSanitizeHTML(log, setHeaders, w, p, parents)
				if err != nil {
					http.Error(w, "400 - bad request - "+err.Error(), http.StatusBadRequest)
				}
				return
			}
			parents = append(parents, p)
			for _, sp := range p.Parts {
				usePart(&sp, parents)
			}
		}
		usePart(&p, nil)

		if !done {
			http.Error(w, "400 - bad request - no html part in message", http.StatusBadRequest)
		}

	case len(t) == 3 && (t[1] == "view" || t[1] == "viewtext" || t[1] == "download"):
		// View any part, as referenced in the last element path. "0" is the whole message,
		// 0.0 is the first subpart, etc. "view" returns it with the content-type from the
		// message (could be dangerous, but we set strict CSP headers), "viewtext" returns
		// data with a text/plain content-type so the browser will attempt to display it,
		// and "download" adds a content-disposition header causing the browser the
		// download the file.
		_, _, _, _, p, cleanup, ok := xprepare()
		if !ok {
			return
		}
		defer cleanup()

		paths := strings.Split(t[2], ".")
		if len(paths) == 0 || paths[0] != "0" {
			http.NotFound(w, r)
			return
		}
		ap := p
		for _, e := range paths[1:] {
			index, err := strconv.ParseInt(e, 10, 32)
			if err != nil || index < 0 || int(index) >= len(ap.Parts) {
				http.NotFound(w, r)
				return
			}
			ap = ap.Parts[int(index)]
		}

		headers(false, false, false, false)
		var ct string
		if t[1] == "viewtext" {
			ct = "text/plain"
		} else {
			ct = strings.ToLower(ap.MediaType + "/" + ap.MediaSubType)
		}
		h.Set("Content-Type", ct)
		h.Set("Cache-Control", "no-store, max-age=0")
		if t[1] == "download" {
			_, name, err := ap.DispositionFilename()
			if err != nil && errors.Is(err, message.ErrParamEncoding) {
				log.Debugx("parsing disposition/filename", err)
			} else {
				xcheckf(ctx, err, "reading disposition/filename")
			}
			if name == "" {
				name = "attachment.bin"
			}
			cd := mime.FormatMediaType("attachment", map[string]string{"filename": name})
			h.Set("Content-Disposition", cd)
		}

		_, err := io.Copy(w, ap.Reader())
		log.Check(err, "copying attachment")
	default:
		http.NotFound(w, r)
	}
}

// inlineSanitizeHTML writes the part as HTML, with "cid:" URIs for html "src"
// attributes inlined and with potentially dangerous tags removed (javascript). The
// sanitizing is just a first layer of defense, CSP headers block execution of
// scripts. If the HTML becomes too large, an error is returned. Before writing
// HTML, setHeaders is called to write the required headers for content-type and
// CSP. On error, setHeader is not called, no output is written and the caller
// should write an error response.
func inlineSanitizeHTML(log mlog.Log, setHeaders func(), w io.Writer, p *message.Part, parents []*message.Part) error {
	node, err := html.Parse(p.ReaderUTF8OrBinary())
	if err != nil {
		return fmt.Errorf("parsing html: %v", err)
	}

	// We track size, if it becomes too much, we abort and still copy as regular html.
	var totalSize int64
	if err := inlineNode(p, parents, node, &totalSize); err != nil {
		return fmt.Errorf("inline cid uris in html nodes: %w", err)
	}
	sanitizeNode(node)
	setHeaders()
	err = html.Render(w, node)
	log.Check(err, "writing html")
	return nil
}

// findCID returns the part with the Content-ID matching cid, which includes
// "<>", starting at the part's siblings, up the tree, and later from the
// top-part down the tree.
func findCID(p *message.Part, parents []*message.Part, cid string) *message.Part {
	for i := len(parents) - 1; i >= 0; i-- {
		for j, pp := range parents[i].Parts {
			if pp.ContentID != nil && strings.EqualFold(*pp.ContentID, cid) {
				return &parents[i].Parts[j]
			}
		}
	}

	if len(parents) > 0 {
		return findCIDAll(parents[0], cid)
	}
	return nil
}

func findCIDAll(p *message.Part, cid string) *message.Part {
	if p.ContentID != nil && strings.EqualFold(*p.ContentID, cid) {
		return p
	}
	for i := range p.Parts {
		pp := findCIDAll(&p.Parts[i], cid)
		if pp != nil {
			return pp
		}
	}
	return nil
}

// We inline cid: URIs into data: URIs. If a cid is missing in the
// multipart/related, we ignore the error and continue with other HTML nodes. It
// will probably just result in a "broken image". We limit the max size we
// generate. We only replace "src" attributes that start with "cid:". A cid URI
// could theoretically occur in many more places, like link href, and css url().
// That's probably not common though. Let's wait for someone to need it.
func inlineNode(p *message.Part, parents []*message.Part, node *html.Node, totalSize *int64) error {
	for i, a := range node.Attr {
		if a.Key != "src" || !caselessPrefix(a.Val, "cid:") || a.Namespace != "" {
			continue
		}
		cid := "<" + a.Val[4:] + ">"
		ap := findCID(p, parents, cid)
		if ap == nil {
			// Missing cid, can happen with email, no need to stop returning data.
			continue
		}
		*totalSize += ap.DecodedSize
		if *totalSize >= 10*1024*1024 {
			return fmt.Errorf("html too large")
		}
		var sb strings.Builder
		if _, err := fmt.Fprintf(&sb, "data:%s;base64,", strings.ToLower(ap.MediaType+"/"+ap.MediaSubType)); err != nil {
			return fmt.Errorf("writing datauri: %v", err)
		}
		w := base64.NewEncoder(base64.StdEncoding, &sb)
		if _, err := io.Copy(w, ap.Reader()); err != nil {
			return fmt.Errorf("writing base64 datauri: %v", err)
		}
		node.Attr[i].Val = sb.String()
	}
	for node = node.FirstChild; node != nil; node = node.NextSibling {
		if err := inlineNode(p, parents, node, totalSize); err != nil {
			return err
		}
	}
	return nil
}

func caselessPrefix(k, pre string) bool {
	return len(k) >= len(pre) && strings.EqualFold(k[:len(pre)], pre)
}

var targetable = map[string]bool{
	"a":    true,
	"area": true,
	"form": true,
	"base": true,
}

// sanitizeNode removes script elements, on* attributes, javascript: href
// attributes, adds target="_blank" to all links and to a base tag.
func sanitizeNode(node *html.Node) {
	i := 0
	var haveTarget, haveRel bool
	for i < len(node.Attr) {
		a := node.Attr[i]
		// Remove dangerous attributes.
		if strings.HasPrefix(a.Key, "on") || a.Key == "href" && caselessPrefix(a.Val, "javascript:") || a.Key == "src" && caselessPrefix(a.Val, "data:text/html") {
			copy(node.Attr[i:], node.Attr[i+1:])
			node.Attr = node.Attr[:len(node.Attr)-1]
			continue
		}
		if a.Key == "target" {
			node.Attr[i].Val = "_blank"
			haveTarget = true
		}
		if a.Key == "rel" && targetable[node.Data] {
			node.Attr[i].Val = "noopener noreferrer"
			haveRel = true
		}
		i++
	}
	// Ensure target attribute is set for elements that can have it.
	if !haveTarget && node.Type == html.ElementNode && targetable[node.Data] {
		node.Attr = append(node.Attr, html.Attribute{Key: "target", Val: "_blank"})
		haveTarget = true
	}
	if haveTarget && !haveRel {
		node.Attr = append(node.Attr, html.Attribute{Key: "rel", Val: "noopener noreferrer"})
	}

	parent := node
	node = node.FirstChild
	var haveBase bool
	for node != nil {
		// Set next now, we may remove cur, which clears its NextSibling.
		cur := node
		node = node.NextSibling

		// Remove script elements.
		if cur.Type == html.ElementNode && cur.Data == "script" {
			parent.RemoveChild(cur)
			continue
		}
		sanitizeNode(cur)
	}
	if parent.Type == html.ElementNode && parent.Data == "head" && !haveBase {
		n := html.Node{Type: html.ElementNode, Data: "base", Attr: []html.Attribute{{Key: "target", Val: "_blank"}, {Key: "rel", Val: "noopener noreferrer"}}}
		parent.AppendChild(&n)
	}
}
