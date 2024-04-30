package http

import (
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mjl-/mox/mlog"
)

// todo: consider caching gzipped responses from forward handlers too. we would need to read the responses (handle up to perhaps 2mb), hash the data (blake2b seems fast), check if we have the gzip content for that hash, cache it on second request. keep around entries for non-yet-cached hashes, with some limit and lru eviction policy. we have to recognize some content-types as not applicable and do direct streaming compression, e.g. for text/event-stream. and we need to detect when backend server could be slowly sending out data and abort the caching attempt. downside is always that we need to read the whole response before and hash it before we can send our response. it is best if the backend just responds with gzip itself though. compression needs more cpu than hashing (at least 10x), but it's only worth it with enough hits.

// Cache for gzipped static files.
var staticgzcache gzcache

type gzcache struct {
	dir string // Where all files are stored.

	// Max total size of combined files in cache. When adding a new entry, the least
	// recently used entries are evicted to stay below this size.
	maxSize int64

	sync.Mutex

	// Total on-disk size of compressed data. Not larger than maxSize. We can
	// temporarily have more bytes in use because while/after evicting, a writer may
	// still have the old removed file open.
	size int64

	// Indexed by effective path, based on handler.
	paths map[string]gzfile

	// Only with files we completed compressing, kept ordered by atime. We evict from
	// oldest. On use, we take entries out and put them at newest.
	oldest, newest *pathUse
}

type gzfile struct {
	// Whether compressing in progress. If a new request comes in while we are already
	// compressing, for simplicity of code we just compress again for that client.
	compressing bool

	mtime  int64    // If mtime changes, we remove entry from cache.
	atime  int64    // For LRU.
	gzsize int64    // Compressed size, used in Content-Length header.
	use    *pathUse // Only set after compressing finished.
}

type pathUse struct {
	prev, next *pathUse // Double-linked list.
	path       string
}

// Initialize staticgzcache from on-disk directory.
// The path and mtime are in the filename, the atime is in the file itself.
func loadStaticGzipCache(dir string, maxSize int64) {
	staticgzcache = gzcache{
		dir:     dir,
		maxSize: maxSize,
		paths:   map[string]gzfile{},
	}

	// todo future: should we split cached files in sub directories, so we don't end up with one huge directory?
	os.MkdirAll(dir, 0700)
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		pkglog.Errorx("listing static gzip cache files", err, slog.String("dir", dir))
	}
	for _, e := range entries {
		name := e.Name()
		var err error
		if !strings.HasSuffix(name, ".gz") {
			err = errors.New("missing .gz suffix")
		}
		var path, xpath, mtimestr string
		if err == nil {
			var ok bool
			xpath, mtimestr, ok = strings.Cut(strings.TrimRight(name, ".gz"), "+")
			if !ok {
				err = fmt.Errorf("missing + in filename")
			}
		}
		if err == nil {
			var pathbuf []byte
			pathbuf, err = base64.RawURLEncoding.DecodeString(xpath)
			if err == nil {
				path = string(pathbuf)
			}
		}
		var mtime int64
		if err == nil {
			mtime, err = strconv.ParseInt(mtimestr, 16, 64)
		}
		var fi fs.FileInfo
		if err == nil {
			fi, err = e.Info()
		}
		var atime int64
		if err == nil {
			atime, err = statAtime(fi.Sys())
		}
		if err != nil {
			pkglog.Infox("removing unusable/unrecognized file in static gzip cache dir", err)
			xerr := os.Remove(filepath.Join(dir, name))
			pkglog.Check(xerr, "removing unusable file in static gzip cache dir",
				slog.Any("error", err),
				slog.String("dir", dir),
				slog.String("filename", name))
			continue
		}
		staticgzcache.paths[path] = gzfile{
			mtime:  mtime,
			atime:  atime,
			gzsize: fi.Size(),
			use:    &pathUse{path: path},
		}
		staticgzcache.size += fi.Size()
	}

	pathatimes := make([]struct {
		path  string
		atime int64
	}, len(staticgzcache.paths))
	i := 0
	for k, gf := range staticgzcache.paths {
		pathatimes[i].path = k
		pathatimes[i].atime = gf.atime
		i++
	}
	sort.Slice(pathatimes, func(i, j int) bool {
		return pathatimes[i].atime < pathatimes[j].atime
	})
	for _, pa := range pathatimes {
		staticgzcache.push(staticgzcache.paths[pa.path].use)
	}

	// Ensure cache size is OK for current config.
	staticgzcache.evictFor(0)
}

// Evict entries so size bytes are available.
// Must be called with lock held.
func (c *gzcache) evictFor(size int64) {
	for c.size+size > c.maxSize && c.oldest != nil {
		c.evictPath(c.oldest.path)
	}
}

// remove path from cache.
// Must be called with lock held.
func (c *gzcache) evictPath(path string) {
	gf := c.paths[path]

	delete(c.paths, path)
	c.unlink(gf.use)
	c.size -= gf.gzsize
	err := os.Remove(staticCachePath(c.dir, path, gf.mtime))
	pkglog.Check(err, "removing cached gzipped static file", slog.String("path", path))
}

// Open cached file for path, requiring it has mtime. If there is no usable cached
// file, a nil file is returned and the caller should compress and add to the cache
// with startPath and finishPath. No usable cached file means the path isn't in the
// cache, or its mtime is different, or there is an entry but it is new and being
// compressed at the moment. If a usable cached file was found, it is opened and
// returned, along with its compressed/on-disk size.
func (c *gzcache) openPath(path string, mtime int64) (*os.File, int64) {
	c.Lock()
	defer c.Unlock()

	gf, ok := c.paths[path]
	if !ok || gf.compressing {
		return nil, 0
	}
	if gf.mtime != mtime {
		// File has changed, remove old entry. Caller will add to cache again.
		c.evictPath(path)
		return nil, 0
	}

	p := staticCachePath(c.dir, path, gf.mtime)
	f, err := os.Open(p)
	if err != nil {
		pkglog.Errorx("open static cached gzip file, removing from cache", err, slog.String("path", path))
		// Perhaps someone removed the file? Remove from cache, it will be recreated.
		c.evictPath(path)
		return nil, 0
	}

	gf.atime = time.Now().UnixNano()
	c.unlink(gf.use)
	c.push(gf.use)
	c.paths[path] = gf

	return f, gf.gzsize
}

// startPath attempts to add an entry to the cache for a new cached compressed
// file. If there is already an entry but it isn't done compressing yet, false is
// returned and the caller can still compress and respond but the entry cannot be
// added to the cache. If the entry is being added, the caller must call finishPath
// or abortPath.
func (c *gzcache) startPath(path string, mtime int64) bool {
	c.Lock()
	defer c.Unlock()

	if _, ok := c.paths[path]; ok {
		return false
	}
	// note: no "use" yet, we only set that when we finish, so we don't have to clean up on abort.
	c.paths[path] = gzfile{compressing: true, mtime: mtime}
	return true
}

// finishPath completes adding an entry to the cache, marking the entry as
// compressed, accounting for its size, and marking its atime.
func (c *gzcache) finishPath(path string, gzsize int64) {
	c.Lock()
	defer c.Unlock()

	c.evictFor(gzsize)

	gf := c.paths[path]
	gf.compressing = false
	gf.gzsize = gzsize
	gf.atime = time.Now().UnixNano()
	gf.use = &pathUse{path: path}
	c.paths[path] = gf
	c.size += gzsize
	c.push(gf.use)
}

// abortPath marks an entry as no longer being added to the cache.
func (c *gzcache) abortPath(path string) {
	c.Lock()
	defer c.Unlock()

	delete(c.paths, path)
	// note: gzfile.use isn't set yet.
}

// push inserts the "pathUse" to the head of the LRU doubly-linked list, unlinking
// it first if needed.
func (c *gzcache) push(u *pathUse) {
	c.unlink(u)
	u.prev = c.newest
	if c.newest != nil {
		c.newest.next = u
	}
	if c.oldest == nil {
		c.oldest = u
	}
	c.newest = u
}

// unlink removes the "pathUse" from the LRU doubly-linked list.
func (c *gzcache) unlink(u *pathUse) {
	if c.oldest == u {
		c.oldest = u.next
	}
	if c.newest == u {
		c.newest = u.prev
	}
	if u.prev != nil {
		u.prev.next = u.next
	}
	if u.next != nil {
		u.next.prev = u.prev
	}
	u.prev = nil
	u.next = nil
}

// Return path to the on-disk gzipped cached file.
func staticCachePath(dir, path string, mtime int64) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(path))
	return filepath.Join(dir, fmt.Sprintf("%s+%x.gz", p, mtime))
}

// staticgzcacheReplacer intercepts responses for cacheable static files,
// responding with the cached content if appropriate and failing further writes so
// the regular response writer stops.
type staticgzcacheReplacer struct {
	w            http.ResponseWriter
	r            *http.Request // For its context, or logging.
	uncomprPath  string
	uncomprFile  *os.File
	uncomprMtime time.Time
	uncomprSize  int64

	statusCode int

	// Set during WriteHeader to indicate a compressed file has been written, further
	// Writes result in an error to stop the writer of the uncompressed content.
	handled bool
}

func (w *staticgzcacheReplacer) logger() mlog.Log {
	return pkglog.WithContext(w.r.Context())
}

// Header returns the header of the underlying ResponseWriter.
func (w *staticgzcacheReplacer) Header() http.Header {
	return w.w.Header()
}

// WriteHeader checks whether the response is eligible for compressing. If not,
// WriteHeader on the underlying ResponseWriter is called. If so, headers for gzip
// content are set and the gzip content is written, either from disk or compressed
// and stored in the cache.
func (w *staticgzcacheReplacer) WriteHeader(statusCode int) {
	if w.statusCode != 0 {
		return
	}
	w.statusCode = statusCode
	if statusCode != http.StatusOK {
		w.w.WriteHeader(statusCode)
		return
	}

	gzf, gzsize := staticgzcache.openPath(w.uncomprPath, w.uncomprMtime.UnixNano())
	if gzf == nil {
		// Not in cache, or work in progress.
		started := staticgzcache.startPath(w.uncomprPath, w.uncomprMtime.UnixNano())
		if !started {
			// Another request is already compressing and storing this file.
			// todo: we should just wait for the other compression to finish, then use its result.
			w.w.(*loggingWriter).UncompressedSize = w.uncomprSize
			h := w.w.Header()
			h.Set("Content-Encoding", "gzip")
			h.Del("Content-Length") // We don't know this, we compress streamingly.
			gzw, _ := gzip.NewWriterLevel(w.w, gzip.BestSpeed)
			_, err := io.Copy(gzw, w.uncomprFile)
			if err == nil {
				err = gzw.Close()
			}
			w.handled = true
			if err != nil {
				w.w.(*loggingWriter).error(err)
			}
			return
		}

		// Compress and write to cache.
		p := staticCachePath(staticgzcache.dir, w.uncomprPath, w.uncomprMtime.UnixNano())
		ngzf, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			w.logger().Errorx("create new static gzip cache file", err, slog.String("requestpath", w.uncomprPath), slog.String("fspath", p))
			staticgzcache.abortPath(w.uncomprPath)
			return
		}
		defer func() {
			if ngzf != nil {
				staticgzcache.abortPath(w.uncomprPath)
				err := ngzf.Close()
				w.logger().Check(err, "closing failed static gzip cache file", slog.String("requestpath", w.uncomprPath), slog.String("fspath", p))
				err = os.Remove(p)
				w.logger().Check(err, "removing failed static gzip cache file", slog.String("requestpath", w.uncomprPath), slog.String("fspath", p))
			}
		}()

		gzw := gzip.NewWriter(ngzf)
		_, err = io.Copy(gzw, w.uncomprFile)
		if err == nil {
			err = gzw.Close()
		}
		if err == nil {
			err = ngzf.Sync()
		}
		if err == nil {
			gzsize, err = ngzf.Seek(0, 1)
		}
		if err == nil {
			_, err = ngzf.Seek(0, 0)
		}
		if err != nil {
			w.w.(*loggingWriter).error(err)
			return
		}
		staticgzcache.finishPath(w.uncomprPath, gzsize)
		gzf = ngzf
		ngzf = nil
	}
	defer func() {
		if gzf != nil {
			err := gzf.Close()
			if err != nil {
				w.logger().Errorx("closing static gzip cache file", err)
			}
		}
	}()

	// Signal to Write that we aleady (attempted to) write the responses.
	w.handled = true

	w.w.(*loggingWriter).UncompressedSize = w.uncomprSize
	h := w.w.Header()
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Length", fmt.Sprintf("%d", gzsize))
	w.w.WriteHeader(statusCode)
	if _, err := io.Copy(w.w, gzf); err != nil {
		w.w.(*loggingWriter).error(err)
	}
}

var errHandledCompressed = errors.New("response written with compression")

func (w *staticgzcacheReplacer) Write(buf []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.handled {
		// For 200 OK, we already wrote the response and just want the caller to stop processing.
		return 0, errHandledCompressed
	}
	return w.w.Write(buf)
}
