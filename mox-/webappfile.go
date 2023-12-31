package mox

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxvar"
)

// WebappFile serves a merged HTML and JS webapp as a single compressed, cacheable
// file. It merges the JS into the HTML at first load, caches a gzipped version
// that is generated on first need, and responds with a Last-Modified header.
type WebappFile struct {
	HTML, JS         []byte // Embedded html/js data.
	HTMLPath, JSPath string // Paths to load html/js from during development.

	sync.Mutex
	combined     []byte
	combinedGzip []byte
	mtime        time.Time // For Last-Modified and conditional request.
}

// FallbackMtime returns a time to use for the Last-Modified header in case we
// cannot find a file, e.g. when used in production.
func FallbackMtime(log mlog.Log) time.Time {
	p, err := os.Executable()
	log.Check(err, "finding executable for mtime")
	if err == nil {
		st, err := os.Stat(p)
		log.Check(err, "stat on executable for mtime")
		if err == nil {
			return st.ModTime()
		}
	}
	log.Info("cannot find executable for webappfile mtime, using current time")
	return time.Now()
}

func (a *WebappFile) serverError(log mlog.Log, w http.ResponseWriter, err error, action string) {
	log.Errorx("serve webappfile", err, slog.String("msg", action))
	http.Error(w, "500 - internal server error", http.StatusInternalServerError)
}

// Serve serves a combined file, with headers for caching and possibly gzipped.
func (a *WebappFile) Serve(ctx context.Context, log mlog.Log, w http.ResponseWriter, r *http.Request) {
	// We typically return the embedded file, but during development it's handy
	// to load from disk.
	fhtml, _ := os.Open(a.HTMLPath)
	if fhtml != nil {
		defer fhtml.Close()
	}
	fjs, _ := os.Open(a.JSPath)
	if fjs != nil {
		defer fjs.Close()
	}

	html := a.HTML
	js := a.JS

	var diskmtime time.Time
	var refreshdisk bool
	if fhtml != nil && fjs != nil {
		sth, err := fhtml.Stat()
		if err != nil {
			a.serverError(log, w, err, "stat html")
			return
		}
		stj, err := fjs.Stat()
		if err != nil {
			a.serverError(log, w, err, "stat js")
			return
		}

		maxmtime := sth.ModTime()
		if stj.ModTime().After(maxmtime) {
			maxmtime = stj.ModTime()
		}

		a.Lock()
		refreshdisk = maxmtime.After(a.mtime) || a.combined == nil
		a.Unlock()

		if refreshdisk {
			html, err = io.ReadAll(fhtml)
			if err != nil {
				a.serverError(log, w, err, "reading html")
				return
			}
			js, err = io.ReadAll(fjs)
			if err != nil {
				a.serverError(log, w, err, "reading js")
				return
			}
			diskmtime = maxmtime
		}
	}

	gz := AcceptsGzip(r)
	var out []byte
	var mtime time.Time
	var origSize int64

	func() {
		a.Lock()
		defer a.Unlock()

		if refreshdisk || a.combined == nil {
			script := []byte(`<script>/* placeholder */</script>`)
			index := bytes.Index(html, script)
			if index < 0 {
				a.serverError(log, w, errors.New("script not found"), "generating combined html")
				return
			}
			var b bytes.Buffer
			b.Write(html[:index])
			fmt.Fprintf(&b, "<script>\n// Javascript is generated from typescript, don't modify the javascript because changes will be lost.\nconst moxversion = \"%s\";\n", moxvar.Version)
			b.Write(js)
			b.WriteString("\t\t</script>")
			b.Write(html[index+len(script):])
			out = b.Bytes()
			a.combined = out
			if refreshdisk {
				a.mtime = diskmtime
			} else {
				a.mtime = FallbackMtime(log)
			}
			a.combinedGzip = nil
		} else {
			out = a.combined
		}
		if gz {
			if a.combinedGzip == nil {
				var b bytes.Buffer
				gzw, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
				if err == nil {
					_, err = gzw.Write(out)
				}
				if err == nil {
					err = gzw.Close()
				}
				if err != nil {
					a.serverError(log, w, err, "gzipping combined html")
					return
				}
				a.combinedGzip = b.Bytes()
			}
			origSize = int64(len(out))
			out = a.combinedGzip
		}
		mtime = a.mtime
	}()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(gzipInjector{w, gz, origSize}, r, "", mtime, bytes.NewReader(out))
}

// gzipInjector is a http.ResponseWriter that optionally injects a
// Content-Encoding: gzip header, only in case of status 200 OK. Used with
// http.ServeContent to serve gzipped content if the client supports it. We cannot
// just unconditionally add the content-encoding header, because we don't know
// enough if we will be sending data: http.ServeContent may be sending a "not
// modified" response, and possibly others.
type gzipInjector struct {
	http.ResponseWriter // Keep most methods.
	gz                  bool
	origSize            int64
}

// WriteHeader adds a Content-Encoding: gzip header before actually writing the
// headers and status.
func (w gzipInjector) WriteHeader(statusCode int) {
	if w.gz && statusCode == http.StatusOK {
		w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
		if lw, ok := w.ResponseWriter.(interface{ SetUncompressedSize(int64) }); ok {
			lw.SetUncompressedSize(w.origSize)
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// AcceptsGzip returns whether the client accepts gzipped responses.
func AcceptsGzip(r *http.Request) bool {
	s := r.Header.Get("Accept-Encoding")
	t := strings.Split(s, ",")
	for _, e := range t {
		e = strings.TrimSpace(e)
		tt := strings.Split(e, ";")
		if len(tt) > 1 && t[1] == "q=0" {
			continue
		}
		if tt[0] == "gzip" {
			return true
		}
	}
	return false
}
