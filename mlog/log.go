// Package mlog provides logging with log levels and fields.
//
// Each log level has a function to log with and without error.
// Each such function takes a varargs list of fields (key value pairs) to log.
// Variable data should be in fields. Logging strings themselves should be
// constant, for easier log processing (e.g. building metrics based on log
// messages).
//
// The log levels can be configured per originating package, e.g. smtpclient,
// imapserver. The configuration is application-global, so each Log instance
// uses the same log levels.
//
// Print* should be used for lines that always should be printed, regardless of
// configured log levels. Useful for startup logging and subcommands.
//
// Fatal* stops the program. Its log text is always printed.
package mlog

// todo: log with source=path:linenumber? and/or stacktrace (perhaps optional)
// todo: should we turn errors logged with an context.Canceled from a level error into level info?
// todo: rethink format. perhaps simply using %#v is more useful for many types?

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
)

var Logfmt bool

type Level int

var LevelStrings = map[Level]string{
	LevelPrint:     "print",
	LevelFatal:     "fatal",
	LevelError:     "error",
	LevelInfo:      "info",
	LevelDebug:     "debug",
	LevelTrace:     "trace",
	LevelTraceauth: "traceauth",
	LevelTracedata: "tracedata",
}

var Levels = map[string]Level{
	"print":     LevelPrint,
	"fatal":     LevelFatal,
	"error":     LevelError,
	"info":      LevelInfo,
	"debug":     LevelDebug,
	"trace":     LevelTrace,
	"traceauth": LevelTraceauth,
	"tracedata": LevelTracedata,
}

const (
	LevelPrint     Level = 0 // Printed regardless of configured log level.
	LevelFatal     Level = 1 // Printed regardless of configured log level.
	LevelError     Level = 2
	LevelInfo      Level = 3
	LevelDebug     Level = 4
	LevelTrace     Level = 5
	LevelTraceauth Level = 6
	LevelTracedata Level = 7
)

// Holds a map[string]Level, mapping a package (field pkg in logs) to a log level.
// The empty string is the default/fallback log level.
var config atomic.Value

func init() {
	config.Store(map[string]Level{"": LevelError})
}

// SetConfig atomically sets the new log levels used by all Log instances.
func SetConfig(c map[string]Level) {
	config.Store(c)
}

// Pair is a field/value pair, for use in logged lines.
type Pair struct {
	key   string
	value any
}

// Field is a shorthand for making a Pair.
func Field(k string, v any) Pair {
	return Pair{k, v}
}

// Log is an instance potentially with its own field/value pair added to any
// logging output.
type Log struct {
	fields     []Pair
	moreFields func() []Pair
}

// New returns a new Log instance. Each log invocation adds field "pkg".
func New(pkg string) *Log {
	return &Log{
		fields: []Pair{{"pkg", pkg}},
	}
}

type key string

// CidKey can be used with context.WithValue to store a "cid" in a context, for logging.
var CidKey key = "cid"

// WithCid adds a field "cid".
// Also see WithContext.
func (l *Log) WithCid(cid int64) *Log {
	return l.Fields(Pair{"cid", cid})
}

// WithContext adds cid from context, if present. Context are often passed to
// functions, especially between packages, to pass a "cid" for an operation. At the
// start of a function (especially if exported) a variable "log" is often
// instantiated from a package-level variable "xlog", with WithContext for its cid.
// A *Log could be passed instead, but contexts are more pervasive. For the same
// reason WithContext is more common than WithCid.
func (l *Log) WithContext(ctx context.Context) *Log {
	cidv := ctx.Value(CidKey)
	if cidv == nil {
		return l
	}
	cid := cidv.(int64)
	return l.WithCid(cid)
}

// Field adds fields to the logger. Each logged line adds these fields.
func (l *Log) Fields(fields ...Pair) *Log {
	nl := *l
	nl.fields = append(fields, nl.fields...)
	return &nl
}

// MoreFields sets a function on the logger that is called just before logging,
// to retrieve additional fields to log.
func (l *Log) MoreFields(fn func() []Pair) *Log {
	nl := *l
	nl.moreFields = fn
	return &nl
}

func (l *Log) Trace(traceLevel Level, text string) bool {
	return l.logx(traceLevel, nil, text)
}

func (l *Log) Fatal(text string, fields ...Pair) { l.Fatalx(text, nil, fields...) }
func (l *Log) Fatalx(text string, err error, fields ...Pair) {
	l.plog(LevelFatal, err, text, fields...)
	os.Exit(1)
}

func (l *Log) Print(text string, fields ...Pair) bool {
	return l.logx(LevelPrint, nil, text, fields...)
}
func (l *Log) Printx(text string, err error, fields ...Pair) bool {
	return l.logx(LevelPrint, err, text, fields...)
}

func (l *Log) Debug(text string, fields ...Pair) bool {
	return l.logx(LevelDebug, nil, text, fields...)
}
func (l *Log) Debugx(text string, err error, fields ...Pair) bool {
	return l.logx(LevelDebug, err, text, fields...)
}

func (l *Log) Info(text string, fields ...Pair) bool { return l.logx(LevelInfo, nil, text, fields...) }
func (l *Log) Infox(text string, err error, fields ...Pair) bool {
	return l.logx(LevelInfo, err, text, fields...)
}

func (l *Log) Error(text string, fields ...Pair) bool {
	return l.logx(LevelError, nil, text, fields...)
}
func (l *Log) Errorx(text string, err error, fields ...Pair) bool {
	return l.logx(LevelError, err, text, fields...)
}

func (l *Log) logx(level Level, err error, text string, fields ...Pair) bool {
	if ok, high := l.match(level); ok {
		// Nothing.
	} else if high >= LevelTrace && level == LevelTraceauth {
		text = "***"
	} else if high >= LevelTrace && level == LevelTracedata {
		text = "..."
	} else {
		return false
	}
	if level > LevelTrace {
		level = LevelTrace
	}
	l.plog(level, err, text, fields...)
	return true
}

// escape logfmt string if required, otherwise return original string.
func logfmtValue(s string) string {
	for _, c := range s {
		if c == '"' || c == '\\' || c <= ' ' || c == '=' || c >= 0x7f {
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
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr && rv.IsNil() {
		return ""
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
		b.WriteString(k + "=" + logfmtValue(vs))
	}
	return b.String()
}

func (l *Log) plog(level Level, err error, text string, fields ...Pair) {
	fields = append(l.fields, fields...)
	if l.moreFields != nil {
		fields = append(fields, l.moreFields()...)
	}
	// We build up a buffer so we can do a single atomic write of the data. Otherwise partial log lines may interleaf.
	b := &bytes.Buffer{}
	if Logfmt {
		fmt.Fprintf(b, "l=%s m=%s", LevelStrings[level], logfmtValue(text))
		if err != nil {
			fmt.Fprintf(b, " err=%s", logfmtValue(err.Error()))
		}
		for i := 0; i < len(fields); i++ {
			kv := fields[i]
			fmt.Fprintf(b, " %s=%s", kv.key, logfmtValue(stringValue(kv.key == "cid", false, kv.value)))
		}
		b.WriteString("\n")
	} else {
		fmt.Fprintf(b, "%s: %s", LevelStrings[level], logfmtValue(text))
		if err != nil {
			fmt.Fprintf(b, ": %s", logfmtValue(err.Error()))
		}
		if len(fields) > 0 {
			fmt.Fprint(b, " (")
			for i := 0; i < len(fields); i++ {
				if i > 0 {
					fmt.Fprint(b, "; ")
				}
				kv := fields[i]
				fmt.Fprintf(b, "%s: %s", kv.key, logfmtValue(stringValue(kv.key == "cid", false, kv.value)))
			}
			fmt.Fprint(b, ")")
		}
		b.WriteString("\n")
	}
	os.Stderr.Write(b.Bytes())
}

func (l *Log) match(level Level) (bool, Level) {
	if level == LevelPrint || level == LevelFatal {
		return true, level
	}

	cl := config.Load().(map[string]Level)

	seen := false
	var high Level
	for _, kv := range l.fields {
		if kv.key != "pkg" {
			continue
		}
		pkg, ok := kv.value.(string)
		if !ok {
			continue
		}
		v, ok := cl[pkg]
		if v > high {
			high = v
		}
		if ok && v >= level {
			return true, high
		}
		seen = seen || ok
	}
	if seen {
		return false, high
	}
	v, ok := cl[""]
	if v > high {
		high = v
	}
	return ok && v >= level, v
}

type errWriter struct {
	log   *Log
	level Level
	msg   string
}

func (w *errWriter) Write(buf []byte) (int, error) {
	err := errors.New(strings.TrimSpace(string(buf)))
	w.log.logx(w.level, err, w.msg)
	return len(buf), nil
}

// ErrWriter returns a writer that turns each write into a logging call on "log"
// with given "level" and "msg" and the written content as an error.
// Can be used for making a Go log.Logger for use in http.Server.ErrorLog.
func ErrWriter(log *Log, level Level, msg string) io.Writer {
	return &errWriter{log, level, msg}
}
