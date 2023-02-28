package http

import (
	"fmt"
	htmltemplate "html/template"
	"io"
	golog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
)

// todo: automatic gzip on responses, if client supports it, and if content looks compressible.

// WebHandle serves an HTTP request by going through the list of WebHandlers,
// check if there is a domain+path match, and running the handler if so.
// WebHandle runs after the built-in handlers for mta-sts, autoconfig, etc.
// If no handler matched, false is returned.
// WebHandle sets w.Name to that of the matching handler.
func WebHandle(w *loggingWriter, r *http.Request) (handled bool) {
	log := func() *mlog.Log {
		return xlog.WithContext(r.Context())
	}

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// Common, there often is not port.
		host = r.Host
	}
	dom, err := dns.ParseDomain(host)
	if err != nil {
		log().Debugx("parsing http request domain", err, mlog.Field("host", host))
		http.NotFound(w, r)
		return true
	}

	for _, h := range mox.Conf.WebHandlers() {
		if h.DNSDomain != dom {
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
			u.Host = host
			w.Handler = h.Name
			http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			return true
		}

		if h.WebStatic != nil && HandleStatic(h.WebStatic, w, r) {
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
func HandleStatic(h *config.WebStatic, w http.ResponseWriter, r *http.Request) (handled bool) {
	log := func() *mlog.Log {
		return xlog.WithContext(r.Context())
	}
	recvid := func() string {
		cid := mox.CidFromCtx(r.Context())
		if cid <= 0 {
			return ""
		}
		return " (requestid " + mox.ReceivedID(cid) + ")"
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

	f, err := os.Open(fspath)
	if err != nil {
		if os.IsNotExist(err) {
			if h.ContinueNotFound {
				// We haven't handled this request, try a next WebHandler in the list.
				return false
			}
			http.NotFound(w, r)
			return true
		} else if os.IsPermission(err) {
			http.Error(w, "403 - permission denied", http.StatusForbidden)
			return true
		}
		log().Errorx("open file for static file serving", err, mlog.Field("url", r.URL), mlog.Field("fspath", fspath))
		http.Error(w, "500 - internal server error"+recvid(), http.StatusInternalServerError)
		return true
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log().Errorx("stat file for static file serving", err, mlog.Field("url", r.URL), mlog.Field("fspath", fspath))
		http.Error(w, "500 - internal server error"+recvid(), http.StatusInternalServerError)
		return true
	}
	if fi.IsDir() && !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusTemporaryRedirect)
		return true
	}

	serveFile := func(name string, mtime time.Time, content *os.File) {
		// ServeContent only sets a content-type if not already present in the response headers.
		hdr := w.Header()
		for k, v := range h.ResponseHeaders {
			hdr.Add(k, v)
		}
		http.ServeContent(w, r, name, mtime, content)
	}

	if fi.IsDir() {
		index, err := os.Open(filepath.Join(fspath, "index.html"))
		if err != nil && os.IsPermission(err) || err != nil && os.IsNotExist(err) && !h.ListFiles {
			http.Error(w, "403 - permission denied", http.StatusForbidden)
			return true
		} else if err == nil {
			defer index.Close()
			var ifi os.FileInfo
			ifi, err = index.Stat()
			if err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				serveFile(filepath.Base(fspath), ifi.ModTime(), index)
				return true
			}
		}
		if !os.IsNotExist(err) {
			log().Errorx("stat for static file serving", err, mlog.Field("url", r.URL), mlog.Field("fspath", fspath))
			http.Error(w, "500 - internal server error"+recvid(), http.StatusInternalServerError)
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
				if mb >= 10 {
					size = fmt.Sprintf("%d", int64(mb))
					sizepad = true
				} else {
					size = fmt.Sprintf("%.2f", mb)
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
				log().Errorx("reading directory for file listing", err, mlog.Field("url", r.URL), mlog.Field("fspath", fspath))
				http.Error(w, "500 - internal server error"+recvid(), http.StatusInternalServerError)
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

	serveFile(fspath, fi.ModTime(), f)
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
	}
	if r.URL.RawQuery != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += r.URL.RawQuery
	}
	u.Path = dstpath
	code := http.StatusPermanentRedirect
	if h.StatusCode != 0 {
		code = h.StatusCode
	}
	http.Redirect(w, r, u.String(), code)
	return true
}

// HandleForward handles a request by forwarding it to another webserver and
// passing the response on. I.e. a reverse proxy.
func HandleForward(h *config.WebForward, w http.ResponseWriter, r *http.Request, path string) (handled bool) {
	log := func() *mlog.Log {
		return xlog.WithContext(r.Context())
	}
	recvid := func() string {
		cid := mox.CidFromCtx(r.Context())
		if cid <= 0 {
			return ""
		}
		return " (requestid " + mox.ReceivedID(cid) + ")"
	}

	xr := *r
	r = &xr
	if h.StripPath {
		u := *r.URL
		u.Path = r.URL.Path[len(path):]
		u.RawPath = ""
		r.URL = &u
	}

	// Remove any forwarded headers passed in by client.
	hdr := http.Header{}
	for k, vl := range r.Header {
		switch k {
		case "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
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
	// todo: add Forwarded header? is anyone using it?

	// ReverseProxy will append any remaining path to the configured target URL.
	proxy := httputil.NewSingleHostReverseProxy(h.TargetURL)
	proxy.FlushInterval = time.Duration(-1) // Flush after each write.
	proxy.ErrorLog = golog.New(mlog.ErrWriter(mlog.New("net/http/httputil").WithContext(r.Context()), mlog.LevelDebug, "reverseproxy error"), "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log().Errorx("forwarding request to backend webserver", err, mlog.Field("url", r.URL))
		http.Error(w, "502 - bad gateway"+recvid(), http.StatusBadGateway)
	}
	whdr := w.Header()
	for k, v := range h.ResponseHeaders {
		whdr.Add(k, v)
	}
	proxy.ServeHTTP(w, r)
	return true
}
