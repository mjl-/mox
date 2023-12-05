package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"io/fs"
	golog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
)

func recvid(r *http.Request) string {
	cid := mox.CidFromCtx(r.Context())
	if cid <= 0 {
		return ""
	}
	return " (id " + mox.ReceivedID(cid) + ")"
}

// WebHandle serves an HTTP request by going through the list of WebHandlers,
// check if there is a domain+path match, and running the handler if so.
// WebHandle runs after the built-in handlers for mta-sts, autoconfig, etc.
// If no handler matched, false is returned.
// WebHandle sets w.Name to that of the matching handler.
func WebHandle(w *loggingWriter, r *http.Request, host dns.Domain) (handled bool) {
	redirects, handlers := mox.Conf.WebServer()

	for from, to := range redirects {
		if host != from {
			continue
		}
		u := r.URL
		u.Scheme = "https"
		u.Host = to.Name()
		w.Handler = "(domainredirect)"
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return true
	}

	for _, h := range handlers {
		if host != h.DNSDomain {
			continue
		}
		loc := h.Path.FindStringIndex(r.URL.Path)
		if loc == nil {
			continue
		}
		s := loc[0]
		e := loc[1]
		path := r.URL.Path[s:e]

		if r.TLS == nil && !h.DontRedirectPlainHTTP {
			u := *r.URL
			u.Scheme = "https"
			u.Host = h.DNSDomain.Name()
			w.Handler = h.Name
			w.Compress = h.Compress
			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			return true
		}

		// We don't want the loggingWriter to override the static handler's decisions to compress.
		w.Compress = h.Compress
		if h.WebStatic != nil && HandleStatic(h.WebStatic, h.Compress, w, r) {
			w.Handler = h.Name
			return true
		}
		if h.WebRedirect != nil && HandleRedirect(h.WebRedirect, w, r) {
			w.Handler = h.Name
			return true
		}
		if h.WebForward != nil && HandleForward(h.WebForward, w, r, path) {
			w.Handler = h.Name
			return true
		}
	}
	w.Compress = false
	return false
}

var lsTemplate = htmltemplate.Must(htmltemplate.New("ls").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>ls</title>
		<style>
body, html { padding: 1em; font-size: 16px; }
* { font-size: inherit; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
h1 { margin-bottom: 1ex; font-size: 1.2rem; }
table td, table th { padding: .2em .5em; }
table > tbody > tr:nth-child(odd) { background-color: #f8f8f8; }
[title] { text-decoration: underline; text-decoration-style: dotted; }
		</style>
	</head>
	<body>
		<h1>ls</h1>
		<table>
			<thead>
				<tr>
					<th>Size in MB</th>
					<th>Modified (UTC)</th>
					<th>Name</th>
				</tr>
			</thead>
			<tbody>
			{{ if not .Files }}
				<tr><td colspan="3">No files.</td></tr>
			{{ end }}
			{{ range .Files }}
				<tr>
					<td title="{{ .Size }} bytes" style="text-align: right">{{ .SizeReadable }}{{ if .SizePad }}<span style="visibility:hidden">.  </span>{{ end }}</td>
					<td>{{ .Modified }}</td>
					<td><a style="display: block" href="{{ .Name }}">{{ .Name }}</a></td>
				</tr>
			{{ end }}
			</tbody>
		</table>
	</body>
</html>
`))

// HandleStatic serves static files. If a directory is requested and the URL
// path doesn't end with a slash, a response with a redirect to the URL path with trailing
// slash is written. If a directory is requested and an index.html exists, that
// file is returned. Otherwise, for directories with ListFiles configured, a
// directory listing is returned.
func HandleStatic(h *config.WebStatic, compress bool, w http.ResponseWriter, r *http.Request) (handled bool) {
	log := func() mlog.Log {
		return pkglog.WithContext(r.Context())
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if h.ContinueNotFound {
			// Give another handler that is presumbly configured, for the same path, a chance.
			// E.g. an app that may generate this file for future requests to pick up.
			return false
		}
		http.Error(w, "405 - method not allowed", http.StatusMethodNotAllowed)
		return true
	}

	var fspath string
	if h.StripPrefix != "" {
		if !strings.HasPrefix(r.URL.Path, h.StripPrefix) {
			if h.ContinueNotFound {
				// We haven't handled this request, try a next WebHandler in the list.
				return false
			}
			http.NotFound(w, r)
			return true
		}
		fspath = filepath.Join(h.Root, strings.TrimPrefix(r.URL.Path, h.StripPrefix))
	} else {
		fspath = filepath.Join(h.Root, r.URL.Path)
	}
	// fspath will not have a trailing slash anymore, we'll correct for it
	// later when the path turns out to be file instead of a directory.

	serveFile := func(name string, fi fs.FileInfo, content *os.File) {
		// ServeContent only sets a content-type if not already present in the response headers.
		hdr := w.Header()
		for k, v := range h.ResponseHeaders {
			hdr.Add(k, v)
		}
		// We transparently compress here, but still use ServeContent, because it handles
		// conditional requests, range requests. It's a bit of a hack, but on first write
		// to staticgzcacheReplacer where we are compressing, we write the full compressed
		// file instead, and return an error to ServeContent so it stops. We still have all
		// the useful behaviour (status code and headers) from ServeContent.
		xw := w
		if compress && acceptsGzip(r) && compressibleContent(content) {
			xw = &staticgzcacheReplacer{w, r, content.Name(), content, fi.ModTime(), fi.Size(), 0, false}
		} else {
			w.(*loggingWriter).Compress = false
		}
		http.ServeContent(xw, r, name, fi.ModTime(), content)
	}

	f, err := os.Open(fspath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			if h.ContinueNotFound {
				// We haven't handled this request, try a next WebHandler in the list.
				return false
			}
			http.NotFound(w, r)
			return true
		} else if os.IsPermission(err) {
			// If we tried opening a directory, we may not have permission to read it, but
			// still access files inside it (execute bit), such as index.html. So try to serve it.
			index, err := os.Open(filepath.Join(fspath, "index.html"))
			if err == nil {
				defer index.Close()
				var ifi os.FileInfo
				ifi, err = index.Stat()
				if err != nil {
					log().Errorx("stat index.html in directory we cannot list", err, slog.Any("url", r.URL), slog.String("fspath", fspath))
					http.Error(w, "500 - internal server error"+recvid(r), http.StatusInternalServerError)
					return true
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				serveFile("index.html", ifi, index)
				return true
			}
			http.Error(w, "403 - permission denied", http.StatusForbidden)
			return true
		}
		log().Errorx("open file for static file serving", err, slog.Any("url", r.URL), slog.String("fspath", fspath))
		http.Error(w, "500 - internal server error"+recvid(r), http.StatusInternalServerError)
		return true
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log().Errorx("stat file for static file serving", err, slog.Any("url", r.URL), slog.String("fspath", fspath))
		http.Error(w, "500 - internal server error"+recvid(r), http.StatusInternalServerError)
		return true
	}
	// Redirect if the local path is a directory.
	if fi.IsDir() && !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusTemporaryRedirect)
		return true
	} else if !fi.IsDir() && strings.HasSuffix(r.URL.Path, "/") {
		if h.ContinueNotFound {
			return false
		}
		http.NotFound(w, r)
		return true
	}

	if fi.IsDir() {
		index, err := os.Open(filepath.Join(fspath, "index.html"))
		if err != nil && os.IsPermission(err) {
			http.Error(w, "403 - permission denied", http.StatusForbidden)
			return true
		} else if err != nil && os.IsNotExist(err) && !h.ListFiles {
			if h.ContinueNotFound {
				return false
			}
			http.Error(w, "403 - permission denied", http.StatusForbidden)
			return true
		} else if err == nil {
			defer index.Close()
			var ifi os.FileInfo
			ifi, err = index.Stat()
			if err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				serveFile("index.html", ifi, index)
				return true
			}
		}
		if !os.IsNotExist(err) {
			log().Errorx("stat for static file serving", err, slog.Any("url", r.URL), slog.String("fspath", fspath))
			http.Error(w, "500 - internal server error"+recvid(r), http.StatusInternalServerError)
			return true
		}

		type File struct {
			Name         string
			Size         int64
			SizeReadable string
			SizePad      bool // Whether the size needs padding because it has no decimal point.
			Modified     string
		}
		files := []File{}
		if r.URL.Path != "/" {
			files = append(files, File{"..", 0, "", false, ""})
		}
		for {
			l, err := f.Readdir(1000)
			for _, e := range l {
				mb := float64(e.Size()) / (1024 * 1024)
				var size string
				var sizepad bool
				if !e.IsDir() {
					if mb >= 10 {
						size = fmt.Sprintf("%d", int64(mb))
						sizepad = true
					} else {
						size = fmt.Sprintf("%.2f", mb)
					}
				}
				const dateTime = "2006-01-02 15:04:05" // time.DateTime, but only since go1.20.
				modified := e.ModTime().UTC().Format(dateTime)
				f := File{e.Name(), e.Size(), size, sizepad, modified}
				if e.IsDir() {
					f.Name += "/"
				}
				files = append(files, f)
			}
			if err == io.EOF {
				break
			} else if err != nil {
				log().Errorx("reading directory for file listing", err, slog.Any("url", r.URL), slog.String("fspath", fspath))
				http.Error(w, "500 - internal server error"+recvid(r), http.StatusInternalServerError)
				return true
			}
		}
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name < files[j].Name
		})
		hdr := w.Header()
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		for k, v := range h.ResponseHeaders {
			if !strings.EqualFold(k, "content-type") {
				hdr.Add(k, v)
			}
		}
		err = lsTemplate.Execute(w, map[string]any{"Files": files})
		if err != nil && !moxio.IsClosed(err) {
			log().Errorx("executing directory listing template", err)
		}
		return true
	}

	serveFile(fspath, fi, f)
	return true
}

// HandleRedirect writes a response with an HTTP redirect.
func HandleRedirect(h *config.WebRedirect, w http.ResponseWriter, r *http.Request) (handled bool) {
	var dstpath string
	if h.OrigPath == nil {
		// No path rewrite necessary.
		dstpath = r.URL.Path
	} else if !h.OrigPath.MatchString(r.URL.Path) {
		http.NotFound(w, r)
		return true
	} else {
		dstpath = h.OrigPath.ReplaceAllString(r.URL.Path, h.ReplacePath)
	}

	u := *r.URL
	u.Opaque = ""
	u.RawPath = ""
	u.OmitHost = false
	if h.URL != nil {
		u.Scheme = h.URL.Scheme
		u.Host = h.URL.Host
		u.ForceQuery = h.URL.ForceQuery
		u.RawQuery = h.URL.RawQuery
		u.Fragment = h.URL.Fragment
		if r.URL.RawQuery != "" {
			if u.RawQuery != "" {
				u.RawQuery += "&"
			}
			u.RawQuery += r.URL.RawQuery
		}
	}
	u.Path = dstpath
	code := http.StatusPermanentRedirect
	if h.StatusCode != 0 {
		code = h.StatusCode
	}

	// If we would be redirecting to the same scheme,host,path, we would get here again
	// causing a redirect loop. Instead, this causes this redirect to not match,
	// allowing to try the next WebHandler. This can be used to redirect all plain http
	// requests to https.
	reqscheme := "http"
	if r.TLS != nil {
		reqscheme = "https"
	}
	if reqscheme == u.Scheme && r.Host == u.Host && r.URL.Path == u.Path {
		return false
	}

	http.Redirect(w, r, u.String(), code)
	return true
}

// HandleForward handles a request by forwarding it to another webserver and
// passing the response on. I.e. a reverse proxy. It handles websocket
// connections by monitoring the websocket handshake and then just passing along the
// websocket frames.
func HandleForward(h *config.WebForward, w http.ResponseWriter, r *http.Request, path string) (handled bool) {
	log := func() mlog.Log {
		return pkglog.WithContext(r.Context())
	}

	xr := *r
	r = &xr
	if h.StripPath {
		u := *r.URL
		u.Path = r.URL.Path[len(path):]
		if !strings.HasPrefix(u.Path, "/") {
			u.Path = "/" + u.Path
		}
		u.RawPath = ""
		r.URL = &u
	}

	// Remove any forwarded headers passed in by client.
	hdr := http.Header{}
	for k, vl := range r.Header {
		if k == "Forwarded" || k == "X-Forwarded" || strings.HasPrefix(k, "X-Forwarded-") {
			continue
		}
		hdr[k] = vl
	}
	r.Header = hdr

	// Add our own X-Forwarded headers. ReverseProxy will add X-Forwarded-For.
	r.Header["X-Forwarded-Host"] = []string{r.Host}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	r.Header["X-Forwarded-Proto"] = []string{proto}
	// note: We are not using "ws" or "wss" for websocket. The request we are
	// forwarding is http(s), and we don't yet know if the backend even supports
	// websockets.

	// todo: add Forwarded header? is anyone using it?

	// If we see an Upgrade: websocket, we're going to assume the client needs
	// websocket and only attempt to talk websocket with the backend. If the backend
	// doesn't do websocket, we'll send back a "bad request" response. For other values
	// of Upgrade, we don't do anything special.
	// https://www.iana.org/assignments/http-upgrade-tokens/http-upgrade-tokens.xhtml
	// Upgrade: ../rfc/9110:2798
	// Upgrade headers are not for http/1.0, ../rfc/9110:2880
	// Websocket client "handshake" is described at ../rfc/6455:1134
	upgrade := r.Header.Get("Upgrade")
	if upgrade != "" && !(r.ProtoMajor == 1 && r.ProtoMinor == 0) {
		// Websockets have case-insensitive string "websocket".
		for _, s := range strings.Split(upgrade, ",") {
			if strings.EqualFold(textproto.TrimString(s), "websocket") {
				forwardWebsocket(h, w, r, path)
				return true
			}
		}
	}

	// ReverseProxy will append any remaining path to the configured target URL.
	proxy := httputil.NewSingleHostReverseProxy(h.TargetURL)
	proxy.FlushInterval = time.Duration(-1) // Flush after each write.
	proxy.ErrorLog = golog.New(mlog.LogWriter(mlog.New("net/http/httputil", nil).WithContext(r.Context()), mlog.LevelDebug, "reverseproxy error"), "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			log().Debugx("forwarding request to backend webserver", err, slog.Any("url", r.URL))
			return
		}
		log().Errorx("forwarding request to backend webserver", err, slog.Any("url", r.URL))
		if os.IsTimeout(err) {
			http.Error(w, "504 - gateway timeout"+recvid(r), http.StatusGatewayTimeout)
		} else {
			http.Error(w, "502 - bad gateway"+recvid(r), http.StatusBadGateway)
		}
	}
	whdr := w.Header()
	for k, v := range h.ResponseHeaders {
		whdr.Add(k, v)
	}
	proxy.ServeHTTP(w, r)
	return true
}

var errResponseNotWebsocket = errors.New("not a valid websocket response to request")
var errNotImplemented = errors.New("functionality not yet implemented")

// Request has an Upgrade: websocket header. Check more websocketiness about the
// request. If it looks good, we forward it to the backend. If the backend responds
// with a valid websocket response, indicating it is indeed a websocket server, we
// pass the response along and start copying data between the client and the
// backend. We don't look at the frames and payloads. The backend already needs to
// know enough websocket to handle the frames. It wouldn't necessarily hurt to
// monitor the frames too, and check if they are valid, but it's quite a bit of
// work for little benefit. Besides, the whole point of websockets is to exchange
// bytes without HTTP being in the way, so let's do that.
func forwardWebsocket(h *config.WebForward, w http.ResponseWriter, r *http.Request, path string) (handled bool) {
	log := func() mlog.Log {
		return pkglog.WithContext(r.Context())
	}

	lw := w.(*loggingWriter)
	lw.WebsocketRequest = true // For correct protocol in metrics.

	// We check the requested websocket version first. A future websocket version may
	// have different request requirements.
	// ../rfc/6455:1160
	wsversion := r.Header.Get("Sec-WebSocket-Version")
	if wsversion != "13" {
		// Indicate we only support version 13. Should get a client from the future to fall back to version 13.
		// ../rfc/6455:1435
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "400 - bad request - websockets only supported with version 13"+recvid(r), http.StatusBadRequest)
		lw.error(fmt.Errorf("Sec-WebSocket-Version %q not supported", wsversion))
		return true
	}

	// ../rfc/6455:1143
	if r.Method != "GET" {
		http.Error(w, "400 - bad request - websockets only allowed with method GET"+recvid(r), http.StatusBadRequest)
		lw.error(fmt.Errorf("websocket request only allowed with method GET"))
		return true
	}

	// ../rfc/6455:1153
	var connectionUpgrade bool
	for _, s := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(textproto.TrimString(s), "upgrade") {
			connectionUpgrade = true
			break
		}
	}
	if !connectionUpgrade {
		http.Error(w, "400 - bad request - connection header must be \"upgrade\""+recvid(r), http.StatusBadRequest)
		lw.error(fmt.Errorf(`connection header is %q, must be "upgrade"`, r.Header.Get("Connection")))
		return true
	}

	// ../rfc/6455:1156
	wskey := r.Header.Get("Sec-WebSocket-Key")
	key, err := base64.StdEncoding.DecodeString(wskey)
	if err != nil || len(key) != 16 {
		http.Error(w, "400 - bad request - websockets requires  Sec-WebSocket-Key with 16 bytes base64-encoded value"+recvid(r), http.StatusBadRequest)
		lw.error(fmt.Errorf("bad Sec-WebSocket-Key %q, must be 16 byte base64-encoded value", wskey))
		return true
	}

	// ../rfc/6455:1162
	// We don't look at the origin header. The backend needs to handle it, if it thinks
	// that helps...
	// We also don't look at Sec-WebSocket-Protocol and Sec-WebSocket-Extensions. The
	// backend can set them, but it doesn't influence our forwarding of the data.

	// If this is not a hijacker, there is not point in connecting to the backend.
	hj, ok := lw.W.(http.Hijacker)
	var cbr *bufio.ReadWriter
	if !ok {
		log().Info("cannot turn http connection into tcp connection (http.Hijacker)")
		http.Error(w, "501 - not implemented - cannot turn this connection into websocket"+recvid(r), http.StatusNotImplemented)
		lw.error(fmt.Errorf("connection not a http.Hijacker (%T)", lw.W))
		return
	}

	freq := *r
	freq.Proto = "HTTP/1.1"
	freq.ProtoMajor = 1
	freq.ProtoMinor = 1
	fresp, beconn, err := websocketTransact(r.Context(), h.TargetURL, &freq)
	if err != nil {
		if errors.Is(err, errResponseNotWebsocket) {
			http.Error(w, "400 - bad request - websocket not supported"+recvid(r), http.StatusBadRequest)
		} else if errors.Is(err, errNotImplemented) {
			http.Error(w, "501 - not implemented - "+err.Error()+recvid(r), http.StatusNotImplemented)
		} else if os.IsTimeout(err) {
			http.Error(w, "504 - gateway timeout"+recvid(r), http.StatusGatewayTimeout)
		} else {
			http.Error(w, "502 - bad gateway"+recvid(r), http.StatusBadGateway)
		}
		lw.error(err)
		return
	}
	defer func() {
		if beconn != nil {
			beconn.Close()
		}
	}()

	// Hijack the client connection so we can write the response ourselves, and start
	// copying the websocket frames.
	var cconn net.Conn
	cconn, cbr, err = hj.Hijack()
	if err != nil {
		log().Debugx("cannot turn http transaction into websocket connection", err)
		http.Error(w, "501 - not implemented - cannot turn this connection into websocket"+recvid(r), http.StatusNotImplemented)
		lw.error(err)
		return
	}
	defer func() {
		if cconn != nil {
			cconn.Close()
		}
	}()

	// Below this point, we can no longer write to the ResponseWriter.

	// Mark as websocket response, for logging.
	lw.WebsocketResponse = true
	lw.setStatusCode(fresp.StatusCode)

	for k, v := range h.ResponseHeaders {
		fresp.Header.Add(k, v)
	}

	// Write the response to the client, completing its websocket handshake.
	if err := fresp.Write(cconn); err != nil {
		lw.error(fmt.Errorf("writing websocket response to client: %w", err))
		return
	}

	errc := make(chan error, 1)

	// Copy from client to backend.
	go func() {
		buf, err := cbr.Peek(cbr.Reader.Buffered())
		if err != nil {
			errc <- err
			return
		}
		if len(buf) > 0 {
			n, err := beconn.Write(buf)
			if err != nil {
				errc <- err
				return
			}
			lw.SizeFromClient += int64(n)
		}
		n, err := io.Copy(beconn, cconn)
		lw.SizeFromClient += n
		errc <- err
	}()

	// Copy from backend to client.
	go func() {
		n, err := io.Copy(cconn, beconn)
		lw.SizeToClient = n
		errc <- err
	}()

	// Stop and close connection on first error from either size, typically a closed
	// connection whose closing was already announced with a websocket frame.
	lw.error(<-errc)
	// Close connections so other goroutine stops as well.
	cconn.Close()
	beconn.Close()
	// Wait for goroutine so it has updated the logWriter.Size*Client fields before we
	// continue with logging.
	<-errc
	cconn = nil
	return true
}

func websocketTransact(ctx context.Context, targetURL *url.URL, r *http.Request) (rresp *http.Response, rconn net.Conn, rerr error) {
	log := func() mlog.Log {
		return pkglog.WithContext(r.Context())
	}

	// Dial the backend, possibly doing TLS. We assume the net/http DefaultTransport is
	// unmodified.
	transport := http.DefaultTransport.(*http.Transport)

	// We haven't implemented using a proxy for websocket requests yet. If we need one,
	// return an error instead of trying to connect directly, which would be a
	// potential security issue.
	treq := *r
	treq.URL = targetURL
	if purl, err := transport.Proxy(&treq); err != nil {
		return nil, nil, fmt.Errorf("determining proxy for websocket backend connection: %w", err)
	} else if purl != nil {
		return nil, nil, fmt.Errorf("%w: proxy required for websocket connection to backend", errNotImplemented) // todo: implement?
	}

	host, port, err := net.SplitHostPort(targetURL.Host)
	if err != nil {
		host = targetURL.Host
		if targetURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	conn, err := transport.DialContext(r.Context(), "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	if targetURL.Scheme == "https" {
		tlsconn := tls.Client(conn, transport.TLSClientConfig)
		ctx, cancel := context.WithTimeout(r.Context(), transport.TLSHandshakeTimeout)
		defer cancel()
		if err := tlsconn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tlsconn
	}
	defer func() {
		if rerr != nil {
			conn.Close()
		}
	}()

	// todo: make timeout configurable?
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log().Check(err, "set deadline for websocket request to backend")
	}

	// Set clean connection headers.
	removeHopByHopHeaders(r.Header)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")

	// Write the websocket request to the backend.
	if err := r.Write(conn); err != nil {
		return nil, nil, fmt.Errorf("writing request to backend: %w", err)
	}

	// Read response from backend.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response from backend: %w", err)
	}
	defer func() {
		if rerr != nil {
			resp.Body.Close()
		}
	}()
	if err := conn.SetDeadline(time.Time{}); err != nil {
		log().Check(err, "clearing deadline on websocket connection to backend")
	}

	// Check that the response from the backend server indicates it is websocket. If
	// not, don't pass the backend response, but an error that websocket is not
	// appropriate.
	if err := checkWebsocketResponse(resp, r); err != nil {
		return resp, nil, err
	}

	// note: net/http.Response.Body documents that it implements io.Writer for a
	// status: 101 response. But that's not the case when the response has been read
	// with http.ReadResponse. We'll write to the connection directly.

	buf, err := br.Peek(br.Buffered())
	if err != nil {
		return resp, nil, fmt.Errorf("peek at buffered data written by backend: %w", err)
	}
	return resp, websocketConn{io.MultiReader(bytes.NewReader(buf), conn), conn}, nil
}

// A net.Conn but with reads coming from an io multireader (due to buffered reader
// needed for http.ReadResponse).
type websocketConn struct {
	r io.Reader
	net.Conn
}

func (c websocketConn) Read(buf []byte) (int, error) {
	return c.r.Read(buf)
}

// Check that an HTTP response (from a backend) is a valid websocket response, i.e.
// that it accepts the WebSocket "upgrade".
// ../rfc/6455:1299
func checkWebsocketResponse(resp *http.Response, req *http.Request) error {
	if resp.StatusCode != 101 {
		return fmt.Errorf("%w: response http status not 101 but %s", errResponseNotWebsocket, resp.Status)
	}
	if upgrade := resp.Header.Get("Upgrade"); !strings.EqualFold(upgrade, "websocket") {
		return fmt.Errorf(`%w: response http status is 101, but Upgrade header is %q, should be "websocket"`, errResponseNotWebsocket, upgrade)
	}
	if connection := resp.Header.Get("Connection"); !strings.EqualFold(connection, "upgrade") {
		return fmt.Errorf(`%w: response http status is 101, Upgrade is websocket, but Connection header is %q, should be "Upgrade"`, errResponseNotWebsocket, connection)
	}
	accept, err := base64.StdEncoding.DecodeString(resp.Header.Get("Sec-WebSocket-Accept"))
	if err != nil {
		return fmt.Errorf(`%w: response http status, Upgrade and Connection header are websocket, but Sec-WebSocket-Accept header is not valid base64: %v`, errResponseNotWebsocket, err)
	}
	exp := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if !bytes.Equal(accept, exp[:]) {
		return fmt.Errorf(`%w: response http status, Upgrade and Connection header are websocket, but backend Sec-WebSocket-Accept value does not match`, errResponseNotWebsocket)
	}
	// We don't have requirements for the other Sec-WebSocket headers. ../rfc/6455:1340
	return nil
}

// From Go 1.20.4 src/net/http/httputil/reverseproxy.go:
// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
// ../rfc/2616:5128
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// From Go 1.20.4 src/net/http/httputil/reverseproxy.go:
// removeHopByHopHeaders removes hop-by-hop headers.
func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	// ../rfc/7230:2817
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	// ../rfc/2616:5128
	for _, f := range hopHeaders {
		h.Del(f)
	}
}
