// Package mlog providers helpers on top of slog.Logger.
//
// Packages of mox that are fit or use by external code take an *slog.Logger as
// parameter for logging. Internally, and packages not intended for reuse,
// logging is done with mlog.Log. It providers convenience functions for:
// logging error values, tracing (protocol messages), uncoditional printing
// optionally exiting.
//
// An mlog provides a handler for an mlog.Log for formatting log lines. Lines are
// logged as "logfmt" lines for "mox serve". For command-line tools, the lines are
// printed with colon-separated level, message and error, followed by
// semicolon-separated attributes.
package mlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/exp/slog"
)

var noctx = context.Background()

// Logfmt enabled output in logfmt, instead of output more suitable for
// command-line tools. Must be set early in a program lifecycle.
var Logfmt bool

// LogStringer is used when formatting field values during logging. If a value
// implements it, LogString is called for the value to log.
type LogStringer interface {
	LogString() string
}

var lowestLevel atomic.Int32                     // For quick initial check.
var config atomic.Pointer[map[string]slog.Level] // For secondary complete check for match.

func init() {
	SetConfig(map[string]slog.Level{"": LevelInfo})
}

// SetConfig atomically sets the new log levels used by all Log instances.
func SetConfig(c map[string]slog.Level) {
	lowest := c[""]
	for _, l := range c {
		if l < lowest {
			lowest = l
		}
	}
	lowestLevel.Store(int32(lowest))
	config.Store(&c)
}

var (
	// When the configured log level is any of the Trace levels, all protocol messages
	// are printed. But protocol "data" (like an email message in the SMTP DATA
	// command) is replaced with "..." unless the configured level is LevelTracedata.
	// Likewise, protocol messages with authentication data (e.g. plaintext base64
	// passwords) are replaced with "***" unless the configured level is LevelTraceauth
	// or LevelTracedata.
	LevelTracedata = slog.LevelDebug - 8
	LevelTraceauth = slog.LevelDebug - 6
	LevelTrace     = slog.LevelDebug - 4
	LevelDebug     = slog.LevelDebug
	LevelInfo      = slog.LevelInfo
	LevelWarn      = slog.LevelWarn
	LevelError     = slog.LevelError
	LevelFatal     = slog.LevelError + 4 // Printed regardless of configured log level.
	LevelPrint     = slog.LevelError + 8 // Printed regardless of configured log level.
)

// Levelstrings map log levels to human-readable names.
var LevelStrings = map[slog.Level]string{
	LevelTracedata: "tracedata",
	LevelTraceauth: "traceauth",
	LevelTrace:     "trace",
	LevelDebug:     "debug",
	LevelInfo:      "info",
	LevelWarn:      "warn",
	LevelError:     "error",
	LevelFatal:     "fatal",
	LevelPrint:     "print",
}

// Levels map the human-readable log level to a level.
var Levels = map[string]slog.Level{
	"tracedata": LevelTracedata,
	"traceauth": LevelTraceauth,
	"trace":     LevelTrace,
	"debug":     LevelDebug,
	"info":      LevelInfo,
	"warn":      LevelWarn,
	"error":     LevelError,
	"fatal":     LevelFatal,
	"print":     LevelPrint,
}

// Log wraps an slog.Logger, providing convenience functions.
type Log struct {
	*slog.Logger
}

// New returns a Log that adds a "pkg" attribute. If logger is nil, a new
// Logger is created with a custom handler.
func New(pkg string, logger *slog.Logger) Log {
	if logger == nil {
		logger = slog.New(&handler{})
	}
	return Log{logger}.WithPkg(pkg)
}

// WithCid adds a attribute "cid".
// Also see WithContext.
func (l Log) WithCid(cid int64) Log {
	return l.With(slog.Int64("cid", cid))
}

type key string

// CidKey can be used with context.WithValue to store a "cid" in a context, for logging.
var CidKey key = "cid"

// WithContext adds cid from context, if present. Context are often passed to
// functions, especially between packages, to pass a "cid" for an operation. At the
// start of a function (especially if exported) a variable "log" is often
// instantiated from a package-level logger, with WithContext for its cid.
// Ideally, a Log could be passed instead, but contexts are more pervasive. For the same
// reason WithContext is more common than WithCid.
func (l Log) WithContext(ctx context.Context) Log {
	cidv := ctx.Value(CidKey)
	if cidv == nil {
		return l
	}
	cid := cidv.(int64)
	return l.WithCid(cid)
}

// With adds attributes to to each logged line.
func (l Log) With(attrs ...slog.Attr) Log {
	return Log{slog.New(l.Logger.Handler().WithAttrs(attrs))}
}

// WithPkg ensures pkg is added as attribute to logged lines. If the handler is
// an mlog handler, pkg is only added if not already the last added package.
func (l Log) WithPkg(pkg string) Log {
	h := l.Logger.Handler()
	if ph, ok := h.(*handler); ok {
		if len(ph.Pkgs) > 0 && ph.Pkgs[len(ph.Pkgs)-1] == pkg {
			return l
		}
		return Log{slog.New(ph.WithPkg(pkg))}
	}
	return Log{slog.New(h.WithAttrs([]slog.Attr{slog.String("pkg", pkg)}))}
}

// WithFunc sets fn to be called for additional attributes. Fn is only called
// when the line is logged.
// If the underlying handler is not an mlog.handler, this method has no effect.
// Caller must take care of preventing data races.
func (l Log) WithFunc(fn func() []slog.Attr) Log {
	h := l.Logger.Handler()
	if ph, ok := h.(*handler); ok {
		return Log{slog.New(ph.WithFunc(fn))}
	}
	// Ignored for other handlers, only used internally (smtpserver, imapserver).
	return l
}

// Check logs an error if err is not nil. Intended for logging errors that are good
// to know, but would not influence program flow.
func (l Log) Check(err error, msg string, attrs ...slog.Attr) {
	if err != nil {
		l.Errorx(msg, err, attrs...)
	}
}

func errAttr(err error) slog.Attr {
	return slog.Any("err", err)
}

// todo: consider taking a context parameter. it would require all code be refactored. we may want to do this if callers really depend on passing attrs through context. the mox code base does not do that. it makes all call sites more tedious, and requires passing around ctx everywhere, so consider carefully.

func (l Log) Debug(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelDebug, msg, attrs...)
}

func (l Log) Debugx(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelDebug, msg, attrs...)
}

func (l Log) Info(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelInfo, msg, attrs...)
}

func (l Log) Infox(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelInfo, msg, attrs...)
}

func (l Log) Warn(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelWarn, msg, attrs...)
}

func (l Log) Warnx(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelWarn, msg, attrs...)
}

func (l Log) Error(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelError, msg, attrs...)
}

func (l Log) Errorx(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelError, msg, attrs...)
}

func (l Log) Fatal(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelFatal, msg, attrs...)
	os.Exit(1)
}

func (l Log) Fatalx(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelFatal, msg, attrs...)
	os.Exit(1)
}

func (l Log) Print(msg string, attrs ...slog.Attr) {
	l.Logger.LogAttrs(noctx, LevelPrint, msg, attrs...)
}

func (l Log) Printx(msg string, err error, attrs ...slog.Attr) {
	if err != nil {
		attrs = append([]slog.Attr{errAttr(err)}, attrs...)
	}
	l.Logger.LogAttrs(noctx, LevelPrint, msg, attrs...)
}

// Trace logs at trace/traceauth/tracedata level.
// If the active log level is any of the trace levels, the data is logged.
// If level is for tracedata, but the active level doesn't trace data, data is replaced with "...".
// If level is for traceauth, but the active level doesn't trace auth, data is replaced with "***".
func (l Log) Trace(level slog.Level, prefix string, data []byte) {
	h := l.Handler()
	if !h.Enabled(noctx, level) {
		return
	}
	ph, ok := h.(*handler)
	if !ok {
		msg := prefix + string(data)
		r := slog.NewRecord(time.Now(), level, msg, 0)
		h.Handle(noctx, r)
		return
	}
	filterLevel, ok := ph.configMatch(level)
	if !ok {
		return
	}

	var msg string
	if hideData, hideAuth := traceLevel(filterLevel, level); hideData {
		msg = prefix + "..."
	} else if hideAuth {
		msg = prefix + "***"
	} else {
		msg = prefix + string(data)
	}
	r := slog.NewRecord(time.Time{}, level, msg, 0)
	ph.write(filterLevel, r)
}

func traceLevel(level, recordLevel slog.Level) (hideData, hideAuth bool) {
	hideData = recordLevel == LevelTracedata && level > LevelTracedata
	hideAuth = recordLevel == LevelTraceauth && level > LevelTraceauth
	return
}

type handler struct {
	Pkgs  []string
	Attrs []slog.Attr
	Group string             // Empty or with dot-separated names, ending with a dot.
	Fn    func() []slog.Attr // Only called when record is actually being logged.
}

func match(minLevel, level slog.Level) bool {
	return level >= LevelFatal || level >= minLevel || minLevel <= LevelTrace && level <= LevelTrace
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return match(slog.Level(lowestLevel.Load()), level)
}

func (h *handler) configMatch(level slog.Level) (slog.Level, bool) {
	c := *config.Load()
	for i := len(h.Pkgs) - 1; i >= 0; i-- {
		if l, ok := c[h.Pkgs[i]]; ok {
			return l, match(l, level)
		}
	}
	l := c[""]
	return l, match(l, level)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	l, ok := h.configMatch(r.Level)
	if !ok {
		return nil
	}
	if hideData, hideAuth := traceLevel(l, r.Level); hideData {
		r.Message = "..."
	} else if hideAuth {
		r.Message = "***"
	}
	return h.write(l, r)
}

// Reuse buffers to format log lines into.
var logBuffersStore [32][256]byte
var logBuffers = make(chan []byte, 200)

func init() {
	for i := range logBuffersStore {
		logBuffers <- logBuffersStore[i][:]
	}
}

// escape logfmt string if required, otherwise return original string.
func formatString(s string) string {
	for _, c := range s {
		if c <= ' ' || c == '"' || c == '\\' || c == '=' || c >= 0x7f {
			return fmt.Sprintf("%q", s)
		}
	}
	return s
}

func stringValue(iscid, nested bool, v any) string {
	// Handle some common types first.
	if v == nil {
		return ""
	}
	switch r := v.(type) {
	case string:
		return r
	case int:
		return strconv.Itoa(r)
	case int64:
		if iscid {
			return fmt.Sprintf("%x", v)
		}
		return strconv.FormatInt(r, 10)
	case bool:
		if r {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%v", v)
	case []byte:
		return base64.RawURLEncoding.EncodeToString(r)
	case []string:
		if nested && len(r) == 0 {
			// Drop field from logging.
			return ""
		}
		return "[" + strings.Join(r, ",") + "]"
	case error:
		return r.Error()
	case time.Time:
		return r.Format(time.RFC3339)
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr && rv.IsNil() {
		return ""
	}

	if r, ok := v.(LogStringer); ok {
		return r.LogString()
	}
	if r, ok := v.(fmt.Stringer); ok {
		return r.String()
	}

	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
		return stringValue(iscid, nested, rv.Interface())
	}
	if rv.Kind() == reflect.Slice {
		n := rv.Len()
		if nested && n == 0 {
			// Drop field.
			return ""
		}
		b := &strings.Builder{}
		b.WriteString("[")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(";")
			}
			b.WriteString(stringValue(false, true, rv.Index(i).Interface()))
		}
		b.WriteString("]")
		return b.String()
	} else if rv.Kind() != reflect.Struct {
		return fmt.Sprintf("%v", v)
	}
	n := rv.NumField()
	t := rv.Type()
	b := &strings.Builder{}
	first := true
	for i := 0; i < n; i++ {
		fv := rv.Field(i)
		if !t.Field(i).IsExported() {
			continue
		}
		if fv.Kind() == reflect.Struct || fv.Kind() == reflect.Ptr || fv.Kind() == reflect.Interface {
			// Don't recurse.
			continue
		}
		vs := stringValue(false, true, fv.Interface())
		if vs == "" {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		first = false
		k := strings.ToLower(t.Field(i).Name)
		b.WriteString(k + "=" + vs)
	}
	return b.String()
}

func writeAttr(w io.Writer, separator, group string, a slog.Attr) {
	switch a.Value.Kind() {
	case slog.KindGroup:
		if group != "" {
			group += "."
		}
		group += a.Key
		for _, a := range a.Value.Group() {
			writeAttr(w, separator, group, a)
		}
		return
	default:
		var vv any
		if a.Value.Kind() == slog.KindLogValuer {
			vv = a.Value.Resolve().Any()
		} else {
			vv = a.Value.Any()
		}
		s := stringValue(a.Key == "cid", false, vv)
		fmt.Fprint(w, separator, group, a.Key, "=", formatString(s))
	}
}

func (h *handler) write(l slog.Level, r slog.Record) error {
	// Reuse a buffer, or temporarily allocate a new one.
	var buf []byte
	select {
	case buf = <-logBuffers:
		defer func() {
			logBuffers <- buf
		}()
	default:
		buf = make([]byte, 128)
	}

	b := bytes.NewBuffer(buf[:0])
	eb := &errWriter{b, nil}

	if Logfmt {
		var wrotePkgs bool
		ensurePkgs := func() {
			if !wrotePkgs {
				wrotePkgs = true
				for _, pkg := range h.Pkgs {
					writeAttr(eb, " ", "", slog.String("pkg", pkg))
				}
			}
		}

		fmt.Fprint(eb, "l=", LevelStrings[r.Level], " m=")
		fmt.Fprintf(eb, "%q", r.Message)
		n := 0
		r.Attrs(func(a slog.Attr) bool {
			if n > 0 || a.Key != "err" || h.Group != "" {
				ensurePkgs()
			}
			writeAttr(eb, " ", h.Group, a)
			n++
			return true
		})
		ensurePkgs()
		for _, a := range h.Attrs {
			writeAttr(eb, " ", h.Group, a)
		}
		if h.Fn != nil {
			for _, a := range h.Fn() {
				writeAttr(eb, " ", h.Group, a)
			}
		}
		fmt.Fprint(eb, "\n")
	} else {
		var wrotePkgs bool
		ensurePkgs := func() {
			if !wrotePkgs {
				wrotePkgs = true
				for _, pkg := range h.Pkgs {
					writeAttr(eb, "; ", "", slog.String("pkg", pkg))
				}
			}
		}

		fmt.Fprint(eb, LevelStrings[r.Level], ": ", r.Message)
		n := 0
		r.Attrs(func(a slog.Attr) bool {
			if n == 0 && a.Key == "err" && h.Group == "" {
				fmt.Fprint(eb, ": ", a.Value.String())
				ensurePkgs()
			} else {
				ensurePkgs()
				writeAttr(eb, "; ", h.Group, a)
			}
			n++
			return true
		})
		ensurePkgs()
		for _, a := range h.Attrs {
			writeAttr(eb, "; ", h.Group, a)
		}
		if h.Fn != nil {
			for _, a := range h.Fn() {
				writeAttr(eb, "; ", h.Group, a)
				n++
			}
		}
		fmt.Fprint(eb, "\n")
	}
	if eb.Err != nil {
		return eb.Err
	}

	// todo: for mox serve, do writes in separate goroutine.
	_, err := os.Stderr.Write(b.Bytes())
	return err
}

type errWriter struct {
	Writer *bytes.Buffer
	Err    error
}

func (w *errWriter) Write(buf []byte) (int, error) {
	if w.Err != nil {
		return 0, w.Err
	}
	var n int
	n, w.Err = w.Writer.Write(buf)
	return n, w.Err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	if h.Attrs != nil {
		nh.Attrs = append([]slog.Attr{}, h.Attrs...)
	}
	nh.Attrs = append(nh.Attrs, attrs...)
	return &nh
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.Group += name + "."
	return &nh
}

func (h *handler) WithPkg(pkg string) *handler {
	nh := *h
	if nh.Pkgs != nil {
		nh.Pkgs = append([]string{}, nh.Pkgs...)
	}
	nh.Pkgs = append(nh.Pkgs, pkg)
	return &nh
}

func (h *handler) WithFunc(fn func() []slog.Attr) *handler {
	nh := *h
	nh.Fn = fn
	return &nh
}

type logWriter struct {
	log   Log
	level slog.Level
	msg   string
}

func (w logWriter) Write(buf []byte) (int, error) {
	err := strings.TrimSpace(string(buf))
	w.log.LogAttrs(noctx, w.level, w.msg, slog.String("err", err))
	return len(buf), nil
}

// LogWriter returns a writer that turns each write into a logging call on "log"
// with given "level" and "msg" and the written content as an error.
// Can be used for making a Go log.Logger for use in http.Server.ErrorLog.
func LogWriter(log Log, level slog.Level, msg string) io.Writer {
	return logWriter{log, level, msg}
}
