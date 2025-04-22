// Package webapisrv implements the server-side of the webapi.
package webapisrv

// In a separate package from webapi, so webapi.Client can be used and imported
// without including all mox internals. Documentation for the functions is in
// ../webapi/client.go.

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/webapi"
	"github.com/mjl-/mox/webauth"
	"github.com/mjl-/mox/webops"
)

var pkglog = mlog.New("webapi", nil)

var (
	// Similar between ../webmail/webmail.go:/metricSubmission and ../smtpserver/server.go:/metricSubmission and ../webapisrv/server.go:/metricSubmission
	metricSubmission = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webapi_submission_total",
			Help: "Webapi message submission results, known values (those ending with error are server errors): ok, badfrom, messagelimiterror, recipientlimiterror, queueerror, storesenterror, domaindisabled.",
		},
		[]string{
			"result",
		},
	)
	metricServerErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webapi_errors_total",
			Help: "Webapi server errors, known values: dkimsign, submit.",
		},
		[]string{
			"error",
		},
	)
	metricResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_webapi_results_total",
			Help: "HTTP webapi results by method and result.",
		},
		[]string{"method", "result"}, // result: "badauth", "ok", or error code
	)
	metricDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_webapi_duration_seconds",
			Help:    "HTTP webhook call duration.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 20, 30},
		},
		[]string{"method"},
	)
)

// We pass the request to the handler so the TLS info can be used for
// the Received header in submitted messages. Most API calls need just the
// account name.
type ctxKey string

var requestInfoCtxKey ctxKey = "requestInfo"

type requestInfo struct {
	Log          mlog.Log
	LoginAddress string
	Account      *store.Account
	Response     http.ResponseWriter // For setting headers for non-JSON responses.
	Request      *http.Request       // For Proto and TLS connection state during message submit.
}

// todo: show a curl invocation on the method pages

var docsMethodTemplate = htmltemplate.Must(htmltemplate.New("method").Parse(`<!doctype html>
	<head>
		<meta charset="utf-8" />
		<meta name="robots" content="noindex,nofollow" />
		<title>Method {{ .Method }} - WebAPI - Mox</title>
		<style>
body, html { padding: 1em; font-size: 16px; }
* { font-size: inherit; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
h1, h2, h3, h4 { margin-bottom: 1ex; }
h1 { font-size: 1.2rem; }
h2 { font-size: 1.1rem; }
h3, h4 { font-size: 1rem; }
ul { padding-left: 1rem; }
p { margin-bottom: 1em; max-width: 50em; }
[title] { text-decoration: underline; text-decoration-style: dotted; }
fieldset { border: 0; }
textarea { width: 100%; max-width: 50em; }
		</style>
	</head>
	<body>
		<h1><a href="../">WebAPI</a> - Method {{ .Method }}</h1>
		<form id="webapicall" method="POST">
			<fieldset id="webapifieldset">
				<h2>Request JSON</h2>
				<div><textarea id="webapirequest" name="request" required rows="20">{{ .Request }}</textarea></div>
				<br/>
				<div>
					<button type="reset">Reset</button>
					<button type="submit">Call</button>
				</div>
				<br/>
{{ if .ReturnsBytes }}
				<p>Method has a non-JSON response.</p>
{{ else }}
				<h2>Response JSON</h2>
				<div><textarea id="webapiresponse" rows="20">{{ .Response }}</textarea></div>
{{ end }}
			</fieldset>
		</form>
		<script>
window.addEventListener('load', () => {
	window.webapicall.addEventListener('submit', async (e) => {
		const stop = () => {
			e.stopPropagation()
			e.preventDefault()
		}

		let req
		try {
			req = JSON.parse(window.webapirequest.value)
		} catch (err) {
			window.alert('Error parsing request: ' + err.message)
			stop()
			return
		}
		if (!req) {
			window.alert('Empty request')
			stop()
			return
		}

		if ({{ .ReturnsBytes }}) {
			// Just POST to this URL.
			return
		}

		stop()
		// Do call ourselves, get response and put it in the response textarea.
		window.webapifieldset.disabled = true
		let data = new window.FormData()
		data.append("request", window.webapirequest.value)
		try {
			const response = await fetch("{{ .Method }}", {body: data, method: "POST"})
			const text = await response.text()
			try {
				window.webapiresponse.value = JSON.stringify(JSON.parse(text), undefined, '\t')
			} catch (err) {
				window.webapiresponse.value = text
			}
		} catch (err) {
			window.alert('Error: ' + err.message)
		} finally {
			window.webapifieldset.disabled = false
		}
	})
})
		</script>
	</body>
</html>
`))

var docsIndex []byte

func init() {
	var methods []string
	mt := reflect.TypeFor[webapi.Methods]()
	n := mt.NumMethod()
	for i := range n {
		methods = append(methods, mt.Method(i).Name)
	}
	docsIndexTmpl := htmltemplate.Must(htmltemplate.New("index").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<meta name="robots" content="noindex,nofollow" />
		<title>Webapi - Mox</title>
		<style>
body, html { padding: 1em; font-size: 16px; }
* { font-size: inherit; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
h1, h2, h3, h4 { margin-bottom: 1ex; }
h1 { font-size: 1.2rem; }
h2 { font-size: 1.1rem; }
h3, h4 { font-size: 1rem; }
ul { padding-left: 1rem; }
p { margin-bottom: 1em; max-width: 50em; }
[title] { text-decoration: underline; text-decoration-style: dotted; }
fieldset { border: 0; }
		</style>
	</head>
	<body>
		<h1>Webapi and webhooks</h1>
		<p>The mox webapi is a simple HTTP/JSON-based API for sending messages and processing incoming messages.</p>
		<p>Configure webhooks in mox to receive notifications about outgoing delivery event, and/or incoming deliveries of messages.</p>
		<p>Documentation and examples:</p>
		<p><a href="{{ .WebapiDocsURL }}">{{ .WebapiDocsURL }}</a></p>
		<h2>Methods</h2>
		<p>The methods below are available in this version of mox. Follow a link for an example request/response JSON, and a button to make an API call.</p>
		<ul>
{{ range $i, $method := .Methods }}
			<li><a href="{{ $method }}">{{ $method }}</a></li>
{{ end }}
		</ul>
	</body>
</html>
`))
	webapiDocsURL := "https://pkg.go.dev/github.com/mjl-/mox@" + moxvar.VersionBare + "/webapi/"
	webhookDocsURL := "https://pkg.go.dev/github.com/mjl-/mox@" + moxvar.VersionBare + "/webhook/"
	indexArgs := struct {
		WebapiDocsURL  string
		WebhookDocsURL string
		Methods        []string
	}{webapiDocsURL, webhookDocsURL, methods}
	var b bytes.Buffer
	err := docsIndexTmpl.Execute(&b, indexArgs)
	if err != nil {
		panic("executing api docs index template: " + err.Error())
	}
	docsIndex = b.Bytes()

	mox.NewWebapiHandler = func(maxMsgSize int64, basePath string, isForwarded bool) http.Handler {
		return NewServer(maxMsgSize, basePath, isForwarded)
	}
}

// NewServer returns a new http.Handler for a webapi server.
func NewServer(maxMsgSize int64, path string, isForwarded bool) http.Handler {
	return server{maxMsgSize, path, isForwarded}
}

// server implements the webapi methods.
type server struct {
	maxMsgSize  int64  // Of outgoing messages.
	path        string // Path webapi is configured under, typically /webapi/, with methods at /webapi/v0/<method>.
	isForwarded bool   // Whether incoming requests are reverse-proxied. Used for getting remote IPs for rate limiting.
}

var _ webapi.Methods = server{}

// ServeHTTP implements http.Handler.
func (s server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := pkglog.WithContext(r.Context()) // Take cid from webserver.

	// Send requests to /webapi/ to /webapi/v0/.
	if r.URL.Path == "/" {
		if r.Method != "GET" {
			http.Error(w, "405 - method not allow", http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, s.path+"v0/", http.StatusSeeOther)
		return
	}
	// Serve short introduction and list to methods at /webapi/v0/.
	if r.URL.Path == "/v0/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(docsIndex)
		return
	}

	// Anything else must be a method endpoint.
	if !strings.HasPrefix(r.URL.Path, "/v0/") {
		http.NotFound(w, r)
		return
	}
	fn := r.URL.Path[len("/v0/"):]
	log = log.With(slog.String("method", fn))
	rfn := reflect.ValueOf(s).MethodByName(fn)
	var zero reflect.Value
	if rfn == zero || rfn.Type().NumIn() != 2 || rfn.Type().NumOut() != 2 {
		log.Debug("unknown webapi method")
		http.NotFound(w, r)
		return
	}

	// GET on method returns an example request JSON, a button to call the method,
	// which either fills a textarea with the response (in case of JSON) or posts to
	// the URL letting the browser handle the response (e.g. raw message or part).
	if r.Method == "GET" {
		formatJSON := func(v any) (string, error) {
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetIndent("", "\t")
			enc.SetEscapeHTML(false)
			err := enc.Encode(v)
			return string(b.String()), err
		}

		req, err := formatJSON(mox.FillExample(nil, reflect.New(rfn.Type().In(1))).Interface())
		if err != nil {
			log.Errorx("formatting request as json", err)
			http.Error(w, "500 - internal server error - marshal request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// todo: could check for io.ReadCloser, but we don't return other interfaces than that one.
		returnsBytes := rfn.Type().Out(0).Kind() == reflect.Interface
		var resp string
		if !returnsBytes {
			resp, err = formatJSON(mox.FillExample(nil, reflect.New(rfn.Type().Out(0))).Interface())
			if err != nil {
				log.Errorx("formatting response as json", err)
				http.Error(w, "500 - internal server error - marshal response: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		args := struct {
			Method       string
			Request      string
			Response     string
			ReturnsBytes bool
		}{fn, req, resp, returnsBytes}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = docsMethodTemplate.Execute(w, args)
		log.Check(err, "executing webapi method template")
		return
	} else if r.Method != "POST" {
		http.Error(w, "405 - method not allowed - use get or post", http.StatusMethodNotAllowed)
		return
	}

	// Account is available during call, but we close it before we start writing a
	// response, to prevent slow readers from holding a reference for a long time.
	var acc *store.Account
	closeAccount := func() {
		if acc != nil {
			err := acc.Close()
			log.Check(err, "closing account")
			acc = nil
		}
	}
	defer closeAccount()

	email, password, aok := r.BasicAuth()
	if !aok {
		metricResults.WithLabelValues(fn, "badauth").Inc()
		log.Debug("missing http basic authentication credentials")
		w.Header().Set("WWW-Authenticate", "Basic realm=webapi")
		http.Error(w, "401 - unauthorized - use http basic auth with email address as username", http.StatusUnauthorized)
		return
	}
	log = log.With(slog.String("username", email))

	t0 := time.Now()

	// If remote IP/network resulted in too many authentication failures, refuse to serve.
	remoteIP := webauth.RemoteIP(log, s.isForwarded, r)
	if remoteIP == nil {
		metricResults.WithLabelValues(fn, "internal").Inc()
		log.Debug("cannot find remote ip for rate limiter")
		http.Error(w, "500 - internal server error - cannot find remote ip", http.StatusInternalServerError)
		return
	}
	if !mox.LimiterFailedAuth.CanAdd(remoteIP, t0, 1) {
		metrics.AuthenticationRatelimitedInc("webapi")
		log.Debug("refusing connection due to many auth failures", slog.Any("remoteip", remoteIP))
		http.Error(w, "429 - too many auth attempts", http.StatusTooManyRequests)
		return
	}

	writeError := func(err webapi.Error) {
		closeAccount()
		metricResults.WithLabelValues(fn, err.Code).Inc()

		if err.Code == "server" {
			log.Errorx("webapi call result", err, slog.String("resultcode", err.Code))
		} else {
			log.Infox("webapi call result", err, slog.String("resultcode", err.Code))
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		werr := enc.Encode(err)
		log.Check(werr, "writing error response")
	}

	// Called for all successful JSON responses, not non-JSON responses.
	writeResponse := func(resp any) {
		closeAccount()
		metricResults.WithLabelValues(fn, "ok").Inc()
		log.Debug("webapi call result", slog.String("resultcode", "ok"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		werr := enc.Encode(resp)
		log.Check(werr, "writing error response")
	}

	la := loginAttempt(remoteIP.String(), r, "webapi", "httpbasic")
	la.LoginAddress = email
	defer func() {
		store.LoginAttemptAdd(context.Background(), log, la)
		metricDuration.WithLabelValues(fn).Observe(float64(time.Since(t0)) / float64(time.Second))
	}()

	var err error
	acc, la.AccountName, err = store.OpenEmailAuth(log, email, password, true)
	if err != nil {
		mox.LimiterFailedAuth.Add(remoteIP, t0, 1)
		if errors.Is(err, mox.ErrDomainNotFound) || errors.Is(err, mox.ErrAddressNotFound) || errors.Is(err, store.ErrUnknownCredentials) || errors.Is(err, store.ErrLoginDisabled) {
			log.Debug("bad http basic authentication credentials")
			metricResults.WithLabelValues(fn, "badauth").Inc()
			la.Result = store.AuthBadCredentials
			msg := "use http basic auth with email address as username"
			if errors.Is(err, store.ErrLoginDisabled) {
				la.Result = store.AuthLoginDisabled
				msg = "login is disabled for this account"
			}
			w.Header().Set("WWW-Authenticate", "Basic realm=webapi")
			http.Error(w, "401 - unauthorized - "+msg, http.StatusUnauthorized)
			return
		}
		writeError(webapi.Error{Code: "server", Message: "error verifying credentials"})
		return
	}
	la.AccountName = acc.Name
	la.Result = store.AuthSuccess
	mox.LimiterFailedAuth.Reset(remoteIP, t0)

	ct := r.Header.Get("Content-Type")
	ct, _, err = mime.ParseMediaType(ct)
	if err != nil {
		writeError(webapi.Error{Code: "protocol", Message: "unknown content-type " + r.Header.Get("Content-Type")})
		return
	}
	if ct == "multipart/form-data" {
		err = r.ParseMultipartForm(200 * 1024)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		writeError(webapi.Error{Code: "protocol", Message: "parsing form: " + err.Error()})
		return
	}

	reqstr := r.PostFormValue("request")
	if reqstr == "" {
		writeError(webapi.Error{Code: "protocol", Message: "missing/empty request"})
		return
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, eok := x.(webapi.Error); eok {
			writeError(err)
			return
		}
		log.Error("unhandled panic in webapi call", slog.Any("x", x), slog.String("resultcode", "server"))
		metrics.PanicInc(metrics.Webapi)
		debug.PrintStack()
		writeError(webapi.Error{Code: "server", Message: "unhandled error"})
	}()
	req := reflect.New(rfn.Type().In(1))
	dec := json.NewDecoder(strings.NewReader(reqstr))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req.Interface()); err != nil {
		writeError(webapi.Error{Code: "protocol", Message: fmt.Sprintf("parsing request: %s", err)})
		return
	}

	reqInfo := requestInfo{log, email, acc, w, r}
	nctx := context.WithValue(r.Context(), requestInfoCtxKey, reqInfo)
	resp := rfn.Call([]reflect.Value{reflect.ValueOf(nctx), req.Elem()})
	if !resp[1].IsZero() {
		var e webapi.Error
		err := resp[1].Interface().(error)
		if x, eok := err.(webapi.Error); eok {
			e = x
		} else {
			e = webapi.Error{Code: "error", Message: err.Error()}
		}
		writeError(e)
		return
	}
	rc, ok := resp[0].Interface().(io.ReadCloser)
	if !ok {
		rv, _ := mox.FillNil(resp[0])
		writeResponse(rv.Interface())
		return
	}
	closeAccount()
	log.Debug("webapi call result", slog.String("resultcode", "ok"))
	metricResults.WithLabelValues(fn, "ok").Inc()
	defer func() {
		err := rc.Close()
		log.Check(err, "closing readcloser")
	}()
	_, err = io.Copy(w, rc)
	log.Check(err, "writing response to client")
}

// loginAttempt initializes a store.LoginAttempt, for adding to the store after
// filling in the results and other details.
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

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		msg := fmt.Sprintf(format, args...)
		panic(webapi.Error{Code: "server", Message: fmt.Sprintf("%s: %s", msg, err)})
	}
}

func xcheckuserf(err error, format string, args ...any) {
	if err != nil {
		msg := fmt.Sprintf(format, args...)
		panic(webapi.Error{Code: "user", Message: fmt.Sprintf("%s: %s", msg, err)})
	}
}

func xdbwrite(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx)) {
	err := acc.DB.Write(ctx, func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(err, "transaction")
}

func xdbread(ctx context.Context, acc *store.Account, fn func(tx *bstore.Tx)) {
	err := acc.DB.Read(ctx, func(tx *bstore.Tx) error {
		fn(tx)
		return nil
	})
	xcheckf(err, "transaction")
}

func xcheckcontrol(s string) {
	for _, c := range s {
		if c < 0x20 {
			xcheckuserf(errors.New("control characters not allowed"), "checking header values")
		}
	}
}

func xparseAddress(addr string) smtp.Address {
	a, err := smtp.ParseAddress(addr)
	if err != nil {
		panic(webapi.Error{Code: "badAddress", Message: fmt.Sprintf("parsing address %q: %s", addr, err)})
	}
	return a
}

func xparseAddresses(l []webapi.NameAddress) ([]message.NameAddress, []smtp.Path) {
	r := make([]message.NameAddress, len(l))
	paths := make([]smtp.Path, len(l))
	for i, a := range l {
		xcheckcontrol(a.Name)
		addr := xparseAddress(a.Address)
		r[i] = message.NameAddress{DisplayName: a.Name, Address: addr}
		paths[i] = addr.Path()
	}
	return r, paths
}

func xrandomID(n int) string {
	return base64.RawURLEncoding.EncodeToString(xrandom(n))
}

func xrandom(n int) []byte {
	buf := make([]byte, n)
	x, err := cryptorand.Read(buf)
	if err != nil {
		panic("read random")
	} else if x != n {
		panic("short random read")
	}
	return buf
}

func (s server) Send(ctx context.Context, req webapi.SendRequest) (resp webapi.SendResult, err error) {
	// Similar between ../smtpserver/server.go:/submit\( and ../webmail/api.go:/MessageSubmit\( and ../webapisrv/server.go:/Send\(

	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log
	acc := reqInfo.Account

	m := req.Message

	accConf, _ := acc.Conf()

	if m.Text == "" && m.HTML == "" {
		return resp, webapi.Error{Code: "missingBody", Message: "at least text or html body required"}
	}

	if len(m.From) == 0 {
		m.From = []webapi.NameAddress{{Name: accConf.FullName, Address: reqInfo.LoginAddress}}
	} else if len(m.From) > 1 {
		return resp, webapi.Error{Code: "multipleFrom", Message: "multiple from-addresses not allowed"}
	}
	froms, fromPaths := xparseAddresses(m.From)
	from, fromPath := froms[0], fromPaths[0]
	to, toPaths := xparseAddresses(m.To)
	cc, ccPaths := xparseAddresses(m.CC)
	bcc, bccPaths := xparseAddresses(m.BCC)

	recipients := append(append(toPaths, ccPaths...), bccPaths...)
	addresses := append(append(m.To, m.CC...), m.BCC...)

	// Check if from address is allowed for account.
	if ok, disabled := mox.AllowMsgFrom(acc.Name, from.Address); disabled {
		metricSubmission.WithLabelValues("domaindisabled").Inc()
		return resp, webapi.Error{Code: "domainDisabled", Message: "domain of from-address is temporarily disabled"}
	} else if !ok {
		metricSubmission.WithLabelValues("badfrom").Inc()
		return resp, webapi.Error{Code: "badFrom", Message: "from-address not configured for account"}
	}

	if len(recipients) == 0 {
		return resp, webapi.Error{Code: "noRecipients", Message: "no recipients"}
	}

	// Check outgoing message rate limit.
	xdbread(ctx, acc, func(tx *bstore.Tx) {
		msglimit, rcptlimit, err := acc.SendLimitReached(tx, recipients)
		if msglimit >= 0 {
			metricSubmission.WithLabelValues("messagelimiterror").Inc()
			panic(webapi.Error{Code: "messageLimitReached", Message: "outgoing message rate limit reached"})
		} else if rcptlimit >= 0 {
			metricSubmission.WithLabelValues("recipientlimiterror").Inc()
			panic(webapi.Error{Code: "recipientLimitReached", Message: "outgoing new recipient rate limit reached"})
		}
		xcheckf(err, "checking send limit")
	})

	// If we have a non-ascii localpart, we will be sending with smtputf8. We'll go
	// full utf-8 then.
	intl := func(l []smtp.Path) bool {
		for _, p := range l {
			if p.Localpart.IsInternational() {
				return true
			}
		}
		return false
	}
	smtputf8 := intl([]smtp.Path{fromPath}) || intl(toPaths) || intl(ccPaths) || intl(bccPaths)

	replyTos, replyToPaths := xparseAddresses(m.ReplyTo)
	for _, rt := range replyToPaths {
		if rt.Localpart.IsInternational() {
			smtputf8 = true
		}
	}

	// Create file to compose message into.
	dataFile, err := store.CreateMessageTemp(log, "webapi-submit")
	xcheckf(err, "creating temporary file for message")
	defer store.CloseRemoveTempFile(log, dataFile, "message to submit")

	// If writing to the message file fails, we abort immediately.
	xc := message.NewComposer(dataFile, s.maxMsgSize, smtputf8)
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrMessageSize) {
			panic(webapi.Error{Code: "messageTooLarge", Message: "message too large"})
		} else if ok && errors.Is(err, message.ErrCompose) {
			xcheckf(err, "making message")
		}
		panic(x)
	}()

	// Each queued message gets a Received header.
	// We cannot use VIA, because there is no registered method. We would like to use
	// it to add the ascii domain name in case of smtputf8 and IDNA host name.
	// We don't add the IP address of the submitter. Exposing likely not desirable.
	recvFrom := message.HeaderCommentDomain(mox.Conf.Static.HostnameDomain, smtputf8)
	recvBy := mox.Conf.Static.HostnameDomain.XName(smtputf8)
	recvID := mox.ReceivedID(mox.CidFromCtx(ctx))
	recvHdrFor := func(rcptTo string) string {
		recvHdr := &message.HeaderWriter{}
		// For additional Received-header clauses, see:
		// https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml#table-mail-parameters-8
		// Note: we don't have "via" or "with", there is no registered for webmail.
		recvHdr.Add(" ", "Received:", "from", recvFrom, "by", recvBy, "id", recvID) // ../rfc/5321:3158
		if reqInfo.Request.TLS != nil {
			recvHdr.Add(" ", mox.TLSReceivedComment(log, *reqInfo.Request.TLS)...)
		}
		recvHdr.Add(" ", "for", "<"+rcptTo+">;", time.Now().Format(message.RFC5322Z))
		return recvHdr.String()
	}

	// Outer message headers.
	xc.HeaderAddrs("From", []message.NameAddress{from})
	if len(replyTos) > 0 {
		xc.HeaderAddrs("Reply-To", replyTos)
	}
	xc.HeaderAddrs("To", to)
	xc.HeaderAddrs("Cc", cc)
	// We prepend Bcc headers to the message when adding to the Sent mailbox.
	if m.Subject != "" {
		xcheckcontrol(m.Subject)
		xc.Subject(m.Subject)
	}

	var date time.Time
	if m.Date != nil {
		date = *m.Date
	} else {
		date = time.Now()
	}
	xc.Header("Date", date.Format(message.RFC5322Z))

	if m.MessageID == "" {
		m.MessageID = fmt.Sprintf("<%s>", mox.MessageIDGen(smtputf8))
	} else if !strings.HasPrefix(m.MessageID, "<") || !strings.HasSuffix(m.MessageID, ">") {
		return resp, webapi.Error{Code: "malformedMessageID", Message: "missing <> in message-id"}
	}
	xcheckcontrol(m.MessageID)
	xc.Header("Message-Id", m.MessageID)

	if len(m.References) > 0 {
		for _, ref := range m.References {
			xcheckcontrol(ref)
			// We don't check for <>'s. If caller just puts in what they got, we don't want to
			// reject the message.
		}
		xc.Header("References", strings.Join(m.References, "\r\n\t"))
		xc.Header("In-Reply-To", m.References[len(m.References)-1])
	}
	xc.Header("MIME-Version", "1.0")

	var haveUserAgent bool
	for _, kv := range req.Headers {
		xcheckcontrol(kv[0])
		xcheckcontrol(kv[1])
		xc.Header(kv[0], kv[1])
		if strings.EqualFold(kv[0], "User-Agent") || strings.EqualFold(kv[0], "X-Mailer") {
			haveUserAgent = true
		}
	}
	if !haveUserAgent {
		xc.Header("User-Agent", "mox/"+moxvar.Version)
	}

	// Whether we have additional separately alternative/inline/attached file(s).
	mpf := reqInfo.Request.MultipartForm
	formAlternative := mpf != nil && len(mpf.File["alternativefile"]) > 0
	formInline := mpf != nil && len(mpf.File["inlinefile"]) > 0
	formAttachment := mpf != nil && len(mpf.File["attachedfile"]) > 0

	// MIME structure we'll build:
	// - multipart/mixed (in case of attached files)
	//   - multipart/related (in case of inline files, we assume they are relevant both text and html part if present)
	//     - multipart/alternative (in case we have both text and html bodies)
	//       - text/plain (optional)
	//       - text/html (optional)
	//       - alternative file, ...
	//     - inline file, ...
	//   - attached file, ...

	// We keep track of cur, which is where we add new parts to, whether the text or
	// html part, or the inline or attached files.
	var cur, mixed, related, alternative *multipart.Writer
	xcreateMultipart := func(subtype string) *multipart.Writer {
		mp := multipart.NewWriter(xc)
		if cur == nil {
			xc.Header("Content-Type", fmt.Sprintf(`multipart/%s; boundary="%s"`, subtype, mp.Boundary()))
			xc.Line()
		} else {
			_, err := cur.CreatePart(textproto.MIMEHeader{"Content-Type": []string{fmt.Sprintf(`multipart/%s; boundary="%s"`, subtype, mp.Boundary())}})
			xcheckf(err, "adding multipart")
		}
		return mp
	}
	xcreatePart := func(header textproto.MIMEHeader) io.Writer {
		if cur == nil {
			for k, vl := range header {
				for _, v := range vl {
					xc.Header(k, v)
				}
			}
			xc.Line()
			return xc
		}
		p, err := cur.CreatePart(header)
		xcheckf(err, "adding part")
		return p
	}
	// We create multiparts from outer structure to inner. Then for each we add its
	// inner parts and close the multipart.
	if len(req.AttachedFiles) > 0 || formAttachment {
		mixed = xcreateMultipart("mixed")
		cur = mixed
	}
	if len(req.InlineFiles) > 0 || formInline {
		related = xcreateMultipart("related")
		cur = related
	}
	if m.Text != "" && m.HTML != "" || len(req.AlternativeFiles) > 0 || formAlternative {
		alternative = xcreateMultipart("alternative")
		cur = alternative
	}
	if m.Text != "" {
		textBody, ct, cte := xc.TextPart("plain", m.Text)
		tp := xcreatePart(textproto.MIMEHeader{"Content-Type": []string{ct}, "Content-Transfer-Encoding": []string{cte}})
		_, err := tp.Write([]byte(textBody))
		xcheckf(err, "write text part")
	}
	if m.HTML != "" {
		htmlBody, ct, cte := xc.TextPart("html", m.HTML)
		tp := xcreatePart(textproto.MIMEHeader{"Content-Type": []string{ct}, "Content-Transfer-Encoding": []string{cte}})
		_, err := tp.Write([]byte(htmlBody))
		xcheckf(err, "write html part")
	}

	xaddFileBase64 := func(ct string, inline bool, filename string, cid string, base64Data string) {
		h := textproto.MIMEHeader{}
		disp := "attachment"
		if inline {
			disp = "inline"
		}
		cd := mime.FormatMediaType(disp, map[string]string{"filename": filename})

		h.Set("Content-Type", ct)
		h.Set("Content-Disposition", cd)
		if cid != "" {
			h.Set("Content-ID", cid)
		}
		h.Set("Content-Transfer-Encoding", "base64")
		p := xcreatePart(h)

		for len(base64Data) > 0 {
			line := base64Data
			n := min(len(line), 76) // ../rfc/2045:1372
			line, base64Data = base64Data[:n], base64Data[n:]
			_, err := p.Write([]byte(line))
			xcheckf(err, "writing attachment")
			_, err = p.Write([]byte("\r\n"))
			xcheckf(err, "writing attachment")
		}
	}
	xaddJSONFiles := func(l []webapi.File, inline bool) {
		for _, f := range l {
			if f.ContentType == "" {
				buf, _ := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(f.Data)), 512))
				f.ContentType = http.DetectContentType(buf)
				if f.ContentType == "application/octet-stream" {
					f.ContentType = ""
				}
			}

			// Ensure base64 is valid, then we'll write the original string.
			_, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(f.Data)))
			xcheckuserf(err, "parsing attachment as base64")

			xaddFileBase64(f.ContentType, inline, f.Name, f.ContentID, f.Data)
		}
	}
	xaddFile := func(fh *multipart.FileHeader, inline bool) {
		f, err := fh.Open()
		xcheckf(err, "open uploaded file")
		defer func() {
			err := f.Close()
			log.Check(err, "closing uploaded file")
		}()

		ct := fh.Header.Get("Content-Type")
		if ct == "" {
			buf, err := io.ReadAll(io.LimitReader(f, 512))
			if err == nil {
				ct = http.DetectContentType(buf)
			}
			_, err = f.Seek(0, 0)
			xcheckf(err, "rewind uploaded file after content-detection")
			if ct == "application/octet-stream" {
				ct = ""
			}
		}

		h := textproto.MIMEHeader{}
		disp := "attachment"
		if inline {
			disp = "inline"
		}
		cd := mime.FormatMediaType(disp, map[string]string{"filename": fh.Filename})

		if ct != "" {
			h.Set("Content-Type", ct)
		}
		h.Set("Content-Disposition", cd)
		cid := fh.Header.Get("Content-ID")
		if cid != "" {
			h.Set("Content-ID", cid)
		}
		h.Set("Content-Transfer-Encoding", "base64")
		p := xcreatePart(h)
		bw := moxio.Base64Writer(p)
		_, err = io.Copy(bw, f)
		xcheckf(err, "adding uploaded file")
		err = bw.Close()
		xcheckf(err, "flushing uploaded file")
	}

	cur = alternative
	xaddJSONFiles(req.AlternativeFiles, true)
	if mpf != nil {
		for _, fh := range mpf.File["alternativefile"] {
			xaddFile(fh, true)
		}
	}
	if alternative != nil {
		err := alternative.Close()
		xcheckf(err, "closing alternative part")
		alternative = nil
	}

	cur = related
	xaddJSONFiles(req.InlineFiles, true)
	if mpf != nil {
		for _, fh := range mpf.File["inlinefile"] {
			xaddFile(fh, true)
		}
	}
	if related != nil {
		err := related.Close()
		xcheckf(err, "closing related part")
		related = nil
	}
	cur = mixed
	xaddJSONFiles(req.AttachedFiles, false)
	if mpf != nil {
		for _, fh := range mpf.File["attachedfile"] {
			xaddFile(fh, false)
		}
	}
	if mixed != nil {
		err := mixed.Close()
		xcheckf(err, "closing mixed part")
		mixed = nil
	}
	cur = nil
	xc.Flush()

	// Add DKIM-Signature headers.
	var msgPrefix string
	fd := from.Address.Domain
	confDom, _ := mox.Conf.Domain(fd)
	if confDom.Disabled {
		xcheckuserf(mox.ErrDomainDisabled, "checking domain")
	}
	selectors := mox.DKIMSelectors(confDom.DKIM)
	if len(selectors) > 0 {
		dkimHeaders, err := dkim.Sign(ctx, log.Logger, from.Address.Localpart, fd, selectors, smtputf8, dataFile)
		if err != nil {
			metricServerErrors.WithLabelValues("dkimsign").Inc()
		}
		xcheckf(err, "sign dkim")

		msgPrefix = dkimHeaders
	}

	loginAddr, err := smtp.ParseAddress(reqInfo.LoginAddress)
	xcheckf(err, "parsing login address")
	useFromID := slices.Contains(accConf.ParsedFromIDLoginAddresses, loginAddr)
	var localpartBase string
	if useFromID {
		localpartBase = strings.SplitN(string(fromPath.Localpart), confDom.LocalpartCatchallSeparatorsEffective[0], 2)[0]
	}
	fromIDs := make([]string, len(recipients))
	qml := make([]queue.Msg, len(recipients))
	now := time.Now()
	for i, rcpt := range recipients {
		fp := fromPath
		if useFromID {
			fromIDs[i] = xrandomID(16)
			fp.Localpart = smtp.Localpart(localpartBase + confDom.LocalpartCatchallSeparatorsEffective[0] + fromIDs[i])
		}

		// Don't use per-recipient unique message prefix when multiple recipients are
		// present, we want to keep the message identical.
		var recvRcpt string
		if len(recipients) == 1 {
			recvRcpt = rcpt.XString(smtputf8)
		}
		rcptMsgPrefix := recvHdrFor(recvRcpt) + msgPrefix
		msgSize := int64(len(rcptMsgPrefix)) + xc.Size
		qm := queue.MakeMsg(fp, rcpt, xc.Has8bit, xc.SMTPUTF8, msgSize, m.MessageID, []byte(rcptMsgPrefix), req.RequireTLS, now, m.Subject)
		qm.FromID = fromIDs[i]
		qm.Extra = req.Extra
		if req.FutureRelease != nil {
			ival := time.Until(*req.FutureRelease)
			if ival > queue.FutureReleaseIntervalMax {
				xcheckuserf(fmt.Errorf("date/time can not be further than %v in the future", queue.FutureReleaseIntervalMax), "scheduling delivery")
			}
			qm.NextAttempt = *req.FutureRelease
			qm.FutureReleaseRequest = "until;" + req.FutureRelease.Format(time.RFC3339)
			// todo: possibly add a header to the message stored in the Sent mailbox to indicate it was scheduled for later delivery.
		}
		qml[i] = qm
	}
	err = queue.Add(ctx, log, acc.Name, dataFile, qml...)
	if err != nil {
		metricSubmission.WithLabelValues("queueerror").Inc()
	}
	xcheckf(err, "adding messages to the delivery queue")
	metricSubmission.WithLabelValues("ok").Inc()

	// Message has been added to the queue. Ensure we finish the work.
	ctx = context.WithoutCancel(ctx)

	if req.SaveSent {
		// Append message to Sent mailbox and mark original messages as answered/forwarded.
		acc.WithRLock(func() {
			var changes []store.Change

			var sentID int64
			metricked := false
			defer func() {
				if sentID != 0 {
					p := acc.MessagePath(sentID)
					err := os.Remove(p)
					log.Check(err, "removing sent message file after error", slog.String("path", p))
				}

				if x := recover(); x != nil {
					if !metricked {
						metricServerErrors.WithLabelValues("submit").Inc()
					}
					panic(x)
				}
			}()
			xdbwrite(ctx, reqInfo.Account, func(tx *bstore.Tx) {
				sentmb, err := bstore.QueryTx[store.Mailbox](tx).FilterEqual("Expunged", false).FilterEqual("Sent", true).Get()
				if err == bstore.ErrAbsent {
					// There is no mailbox designated as Sent mailbox, so we're done.
					return
				}
				xcheckf(err, "message submitted to queue, adding to Sent mailbox")

				modseq, err := acc.NextModSeq(tx)
				xcheckf(err, "next modseq")

				// If there were bcc headers, prepend those to the stored message only, before the
				// DKIM signature. The DKIM-signature oversigns the bcc header, so this stored message
				// won't validate with DKIM anymore, which is fine.
				if len(bcc) > 0 {
					var sb strings.Builder
					xbcc := message.NewComposer(&sb, 100*1024, smtputf8)
					xbcc.HeaderAddrs("Bcc", bcc)
					xbcc.Flush()
					msgPrefix = sb.String() + msgPrefix
				}

				sentm := store.Message{
					CreateSeq:     modseq,
					ModSeq:        modseq,
					MailboxID:     sentmb.ID,
					MailboxOrigID: sentmb.ID,
					Flags:         store.Flags{Notjunk: true, Seen: true},
					Size:          int64(len(msgPrefix)) + xc.Size,
					MsgPrefix:     []byte(msgPrefix),
				}

				err = acc.MessageAdd(log, tx, &sentmb, &sentm, dataFile, store.AddOpts{})
				if err != nil && errors.Is(err, store.ErrOverQuota) {
					panic(webapi.Error{Code: "sentOverQuota", Message: fmt.Sprintf("message was sent, but not stored in sent mailbox: %v", err)})
				} else if err != nil {
					metricSubmission.WithLabelValues("storesenterror").Inc()
					metricked = true
				}
				xcheckf(err, "message submitted to queue, appending message to Sent mailbox")
				sentID = sentm.ID

				err = tx.Update(&sentmb)
				xcheckf(err, "updating mailbox")

				changes = append(changes, sentm.ChangeAddUID(sentmb), sentmb.ChangeCounts())
			})
			sentID = 0 // Commit.

			store.BroadcastChanges(acc, changes)
		})
	}

	submissions := make([]webapi.Submission, len(qml))
	for i, qm := range qml {
		submissions[i] = webapi.Submission{
			Address:    addresses[i].Address,
			QueueMsgID: qm.ID,
			FromID:     fromIDs[i],
		}
	}
	resp = webapi.SendResult{
		MessageID:   m.MessageID,
		Submissions: submissions,
	}
	return resp, nil
}

func (s server) SuppressionList(ctx context.Context, req webapi.SuppressionListRequest) (resp webapi.SuppressionListResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	resp.Suppressions, err = queue.SuppressionList(ctx, reqInfo.Account.Name)
	return
}

func (s server) SuppressionAdd(ctx context.Context, req webapi.SuppressionAddRequest) (resp webapi.SuppressionAddResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	addr := xparseAddress(req.EmailAddress)
	sup := webapi.Suppression{
		Account: reqInfo.Account.Name,
		Manual:  req.Manual,
		Reason:  req.Reason,
	}
	err = queue.SuppressionAdd(ctx, addr.Path(), &sup)
	return resp, err
}

func (s server) SuppressionRemove(ctx context.Context, req webapi.SuppressionRemoveRequest) (resp webapi.SuppressionRemoveResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	addr := xparseAddress(req.EmailAddress)
	err = queue.SuppressionRemove(ctx, reqInfo.Account.Name, addr.Path())
	return resp, err
}

func (s server) SuppressionPresent(ctx context.Context, req webapi.SuppressionPresentRequest) (resp webapi.SuppressionPresentResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	addr := xparseAddress(req.EmailAddress)
	xcheckuserf(err, "parsing address %q", req.EmailAddress)
	sup, err := queue.SuppressionLookup(ctx, reqInfo.Account.Name, addr.Path())
	if sup != nil {
		resp.Present = true
	}
	return resp, err
}

func xwebapiAddresses(l []message.Address) (r []webapi.NameAddress) {
	r = make([]webapi.NameAddress, len(l))
	for i, ma := range l {
		dom, err := dns.ParseDomain(ma.Host)
		xcheckf(err, "parsing host %q for address", ma.Host)
		lp, err := smtp.ParseLocalpart(ma.User)
		xcheckf(err, "parsing localpart %q for address", ma.User)
		path := smtp.Path{Localpart: lp, IPDomain: dns.IPDomain{Domain: dom}}
		r[i] = webapi.NameAddress{Name: ma.Name, Address: path.XString(true)}
	}
	return r
}

// caller should hold account lock.
func xmessageGet(ctx context.Context, acc *store.Account, msgID int64) (store.Message, store.Mailbox) {
	m := store.Message{ID: msgID}
	var mb store.Mailbox
	err := acc.DB.Read(ctx, func(tx *bstore.Tx) error {
		if err := tx.Get(&m); err == bstore.ErrAbsent || err == nil && m.Expunged {
			panic(webapi.Error{Code: "messageNotFound", Message: "message not found"})
		}
		var err error
		mb, err = store.MailboxID(tx, m.MailboxID)
		if err != nil {
			return fmt.Errorf("get mailbox: %v", err)
		}
		return nil
	})
	xcheckf(err, "get message")
	return m, mb
}

func (s server) MessageGet(ctx context.Context, req webapi.MessageGetRequest) (resp webapi.MessageGetResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log
	acc := reqInfo.Account

	var m store.Message
	var mb store.Mailbox
	var msgr *store.MsgReader
	acc.WithRLock(func() {
		m, mb = xmessageGet(ctx, acc, req.MsgID)
		msgr = acc.MessageReader(m)
	})
	defer func() {
		if err != nil {
			err := msgr.Close()
			log.Check(err, "cleaning up message reader")
		}
	}()

	p, err := m.LoadPart(msgr)
	xcheckf(err, "load parsed message")

	var env message.Envelope
	if p.Envelope != nil {
		env = *p.Envelope
	}
	text, html, _, err := webops.ReadableParts(p, 1*1024*1024)
	if err != nil {
		log.Debugx("looking for text and html content in message", err)
	}
	date := &env.Date
	if date.IsZero() {
		date = nil
	}

	// Parse References message header.
	h, err := p.Header()
	if err != nil {
		log.Debugx("parsing headers for References", err)
	}
	var refs []string
	for _, s := range h.Values("References") {
		s = strings.ReplaceAll(s, "\t", " ")
		for _, w := range strings.Split(s, " ") {
			if w != "" {
				refs = append(refs, w)
			}
		}
	}
	if env.InReplyTo != "" && !slices.Contains(refs, env.InReplyTo) {
		// References are ordered, most recent first. In-Reply-To is less powerful/older.
		// So if both are present, give References preference, prepending the In-Reply-To
		// header.
		refs = append([]string{env.InReplyTo}, refs...)
	}

	msg := webapi.Message{
		From:       xwebapiAddresses(env.From),
		To:         xwebapiAddresses(env.To),
		CC:         xwebapiAddresses(env.CC),
		BCC:        xwebapiAddresses(env.BCC),
		ReplyTo:    xwebapiAddresses(env.ReplyTo),
		MessageID:  env.MessageID,
		References: refs,
		Date:       date,
		Subject:    env.Subject,
		Text:       strings.ReplaceAll(text, "\r\n", "\n"),
		HTML:       strings.ReplaceAll(html, "\r\n", "\n"),
	}

	var msgFrom string
	if d, err := dns.ParseDomain(m.MsgFromDomain); err == nil {
		msgFrom = smtp.NewAddress(m.MsgFromLocalpart, d).Pack(true)
	}
	var rcptTo string
	if m.RcptToDomain != "" {
		rcptTo = m.RcptToLocalpart.String() + "@" + m.RcptToDomain
	}
	meta := webapi.MessageMeta{
		Size:                m.Size,
		DSN:                 m.DSN,
		Flags:               append(m.Flags.Strings(), m.Keywords...),
		MailFrom:            m.MailFrom,
		MailFromValidated:   m.MailFromValidated,
		RcptTo:              rcptTo,
		MsgFrom:             msgFrom,
		MsgFromValidated:    m.MsgFromValidated,
		DKIMVerifiedDomains: m.DKIMDomains,
		RemoteIP:            m.RemoteIP,
		MailboxName:         mb.Name,
	}

	structure, err := queue.PartStructure(log, &p)
	xcheckf(err, "parsing structure")

	result := webapi.MessageGetResult{
		Message:   msg,
		Structure: structure,
		Meta:      meta,
	}
	return result, nil
}

func (s server) MessageRawGet(ctx context.Context, req webapi.MessageRawGetRequest) (resp io.ReadCloser, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	acc := reqInfo.Account

	var m store.Message
	var msgr *store.MsgReader
	acc.WithRLock(func() {
		m, _ = xmessageGet(ctx, acc, req.MsgID)
		msgr = acc.MessageReader(m)
	})

	reqInfo.Response.Header().Set("Content-Type", "text/plain")
	return msgr, nil
}

func (s server) MessagePartGet(ctx context.Context, req webapi.MessagePartGetRequest) (resp io.ReadCloser, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	log := reqInfo.Log
	acc := reqInfo.Account

	var m store.Message
	var msgr *store.MsgReader
	acc.WithRLock(func() {
		m, _ = xmessageGet(ctx, acc, req.MsgID)
		msgr = acc.MessageReader(m)
	})
	defer func() {
		if err != nil {
			err := msgr.Close()
			log.Check(err, "cleaning up message reader")
		}
	}()

	p, err := m.LoadPart(msgr)
	xcheckf(err, "load parsed message")

	for i, index := range req.PartPath {
		if index < 0 || index >= len(p.Parts) {
			return nil, webapi.Error{Code: "partNotFound", Message: fmt.Sprintf("part %d at index %d not found", index, i)}
		}
		p = p.Parts[index]
	}
	return struct {
		io.Reader
		io.Closer
	}{Reader: p.Reader(), Closer: msgr}, nil
}

var xops = webops.XOps{
	DBWrite: xdbwrite,
	Checkf: func(ctx context.Context, err error, format string, args ...any) {
		xcheckf(err, format, args...)
	},
	Checkuserf: func(ctx context.Context, err error, format string, args ...any) {
		if err != nil && errors.Is(err, webops.ErrMessageNotFound) {
			msg := fmt.Sprintf("%s: %s", fmt.Sprintf(format, args...), err)
			panic(webapi.Error{Code: "messageNotFound", Message: msg})
		}
		xcheckuserf(err, format, args...)
	},
}

func (s server) MessageDelete(ctx context.Context, req webapi.MessageDeleteRequest) (resp webapi.MessageDeleteResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xops.MessageDelete(ctx, reqInfo.Log, reqInfo.Account, []int64{req.MsgID})
	return
}

func (s server) MessageFlagsAdd(ctx context.Context, req webapi.MessageFlagsAddRequest) (resp webapi.MessageFlagsAddResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xops.MessageFlagsAdd(ctx, reqInfo.Log, reqInfo.Account, []int64{req.MsgID}, req.Flags)
	return
}

func (s server) MessageFlagsRemove(ctx context.Context, req webapi.MessageFlagsRemoveRequest) (resp webapi.MessageFlagsRemoveResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xops.MessageFlagsClear(ctx, reqInfo.Log, reqInfo.Account, []int64{req.MsgID}, req.Flags)
	return
}

func (s server) MessageMove(ctx context.Context, req webapi.MessageMoveRequest) (resp webapi.MessageMoveResult, err error) {
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)
	xops.MessageMove(ctx, reqInfo.Log, reqInfo.Account, []int64{req.MsgID}, req.DestMailboxName, 0)
	return
}
