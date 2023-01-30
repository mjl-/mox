package sherpa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/mjl-/sherpadoc"
)

// SherpaVersion is the version of the Sherpa protocol this package implements. Sherpa is at version 1.
const SherpaVersion = 1

// JSON holds all fields for a request to sherpa.json.
type JSON struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Functions        []string `json:"functions"`
	BaseURL          string   `json:"baseurl"`
	Version          string   `json:"version"`
	SherpaVersion    int      `json:"sherpaVersion"`
	SherpadocVersion int      `json:"sherpadocVersion"`
}

// HandlerOpts are options for creating a new handler.
type HandlerOpts struct {
	Collector           Collector // Holds functions for collecting metrics about function calls and other incoming HTTP requests. May be nil.
	LaxParameterParsing bool      // If enabled, incoming sherpa function calls will ignore unrecognized fields in struct parameters, instead of failing.
	AdjustFunctionNames string    // If empty, only the first character of function names are lower cased. For "lowerWord", the first string of capitals is lowercased, for "none", the function name is left as is.
}

// Raw signals a raw JSON response.
// If a handler panics with this type, the raw bytes are sent (with regular
// response headers).
// Can be used to skip the json encoding from the handler, eg for caching, or
// when you read a properly formatted JSON document from a file or database.
// By using panic to signal a raw JSON response, the return types stay intact
// for sherpadoc to generate documentation from.
type Raw []byte

// handler that responds to all Sherpa-related requests.
type handler struct {
	path       string
	functions  map[string]reflect.Value
	sherpaJSON *JSON
	opts       HandlerOpts
}

// Error returned by a function called through a sherpa API.
// Message is a human-readable error message.
// Code is optional, it can be used to handle errors programmatically.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

// InternalServerError is an error that propagates as an HTTP internal server error (HTTP status 500), instead of returning a regular HTTP status 200 OK with the error message in the response body.
// Useful for making Sherpa endpoints that can be monitored by simple HTTP monitoring tools.
type InternalServerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *InternalServerError) Error() string {
	return e.Message
}

func (e *InternalServerError) error() *Error {
	return &Error{"internalServerError", e.Message}
}

// Sherpa API response type
type response struct {
	Result interface{} `json:"result"`
	Error  *Error      `json:"error,omitempty"`
}

var htmlTemplate *template.Template

func init() {
	var err error
	htmlTemplate, err = template.New("html").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>{{.title}}</title>
		<style>
body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; line-height:1.4; font-size:16px; color: #333; }
a { color: #327CCB; }
.code { padding: 2px 4px; font-size: 90%; color: #c7254e; background-color: #f9f2f4; border-radius: 4px; }
		</style>
	</head>
	<body>
		<div style="margin:1em auto 1em; max-width:45em">
			<h1>{{.title}} <span style="font-weight:normal; font-size:0.7em">- version {{.version}}</span></h1>
			<p>
				This is the base URL for {{.title}}. The API has been loaded on this page, under variable <span class="code">{{.id}}</span>. So open your browser's developer console and start calling functions!
			</p>
			<p>
				You can also the <a href="{{.docURL}}">read documentation</a> for this API.</p>
			</p>
			<p style="text-align: center; font-size:smaller; margin-top:8ex;">
				<a href="https://github.com/mjl-/sherpa/">go sherpa code</a> |
				<a href="https://www.ueber.net/who/mjl/sherpa/">sherpa api's</a> |
				<a href="https://github.com/mjl-/sherpaweb/">sherpaweb code</a>
			</p>
		</div>
		<script src="{{.jsURL}}"></script>
	</body>
</html>`)
	if err != nil {
		panic(err)
	}
}

func getBaseURL(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + host
}

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	respond(w, status, v, false, "")
}

func respond(w http.ResponseWriter, status int, v interface{}, jsonp bool, callback string) {
	if jsonp {
		w.Header().Add("Content-Type", "text/javascript; charset=utf-8")
	} else {
		w.Header().Add("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	var err error
	if jsonp {
		_, err = fmt.Fprintf(w, "%s(\n\t", callback)
	}
	if raw, ok := v.(Raw); err == nil && ok {
		_, err = w.Write([]byte(`{"result":`))
		if err == nil {
			_, err = w.Write(raw)
		}
		if err == nil {
			_, err = w.Write([]byte("}"))
		}
	} else if err == nil && !ok {
		err = json.NewEncoder(w).Encode(v)
	}
	if err == nil && jsonp {
		_, err = fmt.Fprint(w, ");")
	}
	if err != nil && !isConnectionClosed(err) {
		log.Println("writing response:", err)
	}
}

// Call function fn with a json body read from r.
// Ctx is from the http.Request, and is canceled when the http connection goes away.
//
// on success, the returned interface contains:
// - nil, if fn has no return value
// - single value, if fn had a single return value
// - slice of values, if fn had multiple return values
// - Raw, for a preformatted JSON response (caught from panic).
//
// on error, we always return an Error with the Code field set.
func (h *handler) call(ctx context.Context, functionName string, fn reflect.Value, r io.Reader) (ret interface{}, ee error) {
	defer func() {
		e := recover()
		if e == nil {
			return
		}

		se, ok := e.(*Error)
		if ok {
			ee = se
			return
		}
		ierr, ok := e.(*InternalServerError)
		if ok {
			ee = ierr
			return
		}
		if raw, ok := e.(Raw); ok {
			ret = raw
			return
		}
		panic(e)
	}()

	lcheck := func(err error, code, message string) {
		if err != nil {
			panic(&Error{Code: code, Message: fmt.Sprintf("function %q: %s: %s", functionName, message, err)})
		}
	}

	var request struct {
		Params json.RawMessage `json:"params"`
	}

	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	err := dec.Decode(&request)
	lcheck(err, SherpaBadRequest, "invalid JSON request body")

	fnt := fn.Type()

	var params []interface{}
	err = json.Unmarshal(request.Params, &params)
	lcheck(err, SherpaBadRequest, "invalid JSON request body")

	needArgs := fnt.NumIn()
	needValues := needArgs
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	needsContext := needValues > 0 && fnt.In(0).Implements(ctxType)
	if needsContext {
		needArgs--
	}
	if fnt.IsVariadic() {
		if len(params) != needArgs-1 && len(params) != needArgs {
			err = fmt.Errorf("got %d, want %d or %d", len(params), needArgs-1, needArgs)
		}
	} else {
		if len(params) != needArgs {
			err = fmt.Errorf("got %d, want %d", len(params), needArgs)
		}
	}
	lcheck(err, SherpaBadParams, "bad number of parameters")

	values := make([]reflect.Value, needValues)
	o := 0
	if needsContext {
		values[0] = reflect.ValueOf(ctx)
		o = 1
	}
	args := make([]interface{}, needArgs)
	for i := range args {
		n := reflect.New(fnt.In(o + i))
		values[o+i] = n.Elem()
		args[i] = n.Interface()
	}

	dec = json.NewDecoder(bytes.NewReader(request.Params))
	if !h.opts.LaxParameterParsing {
		dec.DisallowUnknownFields()
	}
	err = dec.Decode(&args)
	lcheck(err, SherpaBadParams, "parsing parameters")

	errorType := reflect.TypeOf((*error)(nil)).Elem()
	checkError := fnt.NumOut() > 0 && fnt.Out(fnt.NumOut()-1).Implements(errorType)

	var results []reflect.Value
	if fnt.IsVariadic() {
		results = fn.CallSlice(values)
	} else {
		results = fn.Call(values)
	}
	if len(results) == 0 {
		return nil, nil
	}

	rr := make([]interface{}, len(results))
	for i, v := range results {
		rr[i] = v.Interface()
	}
	if !checkError {
		if len(rr) == 1 {
			return rr[0], nil
		}
		return rr, nil
	}
	rr, rerr := rr[:len(rr)-1], rr[len(rr)-1]
	var rv interface{} = rr
	switch len(rr) {
	case 0:
		rv = nil
	case 1:
		rv = rr[0]
	}
	if rerr == nil {
		return rv, nil
	}
	switch r := rerr.(type) {
	case *Error:
		return nil, r
	case *InternalServerError:
		return nil, r
	case error:
		return nil, &Error{Message: r.Error()}
	default:
		panic("checkError while type is not error")
	}
}

func adjustFunctionNameCapitals(s string, opts HandlerOpts) string {
	switch opts.AdjustFunctionNames {
	case "":
		return strings.ToLower(s[:1]) + s[1:]
	case "none":
		return s
	case "lowerWord":
		r := ""
		for i, c := range s {
			lc := unicode.ToLower(c)
			if lc == c {
				r += s[i:]
				break
			}
			r += string(lc)
		}
		return r
	default:
		panic(fmt.Sprintf("bad value for AdjustFunctionNames: %q", opts.AdjustFunctionNames))
	}
}

func gatherFunctions(functions map[string]reflect.Value, t reflect.Type, v reflect.Value, opts HandlerOpts) error {
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("sherpa sections must be a struct (not a ptr)")
	}
	for i := 0; i < t.NumMethod(); i++ {
		name := adjustFunctionNameCapitals(t.Method(i).Name, opts)
		m := v.Method(i)
		if _, ok := functions[name]; ok {
			return fmt.Errorf("duplicate function %s", name)
		}
		functions[name] = m
	}
	for i := 0; i < t.NumField(); i++ {
		err := gatherFunctions(functions, t.Field(i).Type, v.Field(i), opts)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewHandler returns a new http.Handler that serves all Sherpa API-related requests.
//
// Path is the path this API is available at.
//
// Version should be a semantic version.
//
// API should by a struct. It represents the root section. All methods of a
// section are exported as sherpa functions. All fields must be other sections
// (structs) whose methods are also exported. recursively. Method names must
// start with an uppercase character to be exported, but their exported names
// start with a lowercase character by default (but see HandlerOpts.AdjustFunctionNames).
//
// Doc is documentation for the top-level sherpa section, as generated by sherpadoc.
//
// Opts allows further configuration of the handler.
//
// Methods on the exported sections are exported as Sherpa functions.
// If the first parameter of a method is a context.Context, the context from the HTTP request is passed.
// This lets you abort work if the HTTP request underlying the function call disappears.
//
// Parameters and return values for exported functions are automatically converted from/to JSON.
// If the last element of a return value (if any) is an error,
// that error field is taken to indicate whether the call succeeded.
// Exported functions can also panic with an *Error or *InternalServerError to indicate a failed function call.
// Returning an error with a Code starting with "server" indicates an implementation error, which will be logged through the collector.
//
// Variadic functions can be called, but in the call (from the client), the variadic parameters must be passed in as an array.
//
// This handler strips "path" from the request.
func NewHandler(path string, version string, api interface{}, doc *sherpadoc.Section, opts *HandlerOpts) (http.Handler, error) {
	var xopts HandlerOpts
	if opts != nil {
		xopts = *opts
	}
	if xopts.Collector == nil {
		// We always want to have a collector, so we don't have to check for nil all the time when calling.
		xopts.Collector = ignoreCollector{}
	}

	doc.Version = version
	doc.SherpaVersion = SherpaVersion
	functions := map[string]reflect.Value{
		"_docs": reflect.ValueOf(func() *sherpadoc.Section {
			return doc
		}),
	}
	err := gatherFunctions(functions, reflect.TypeOf(api), reflect.ValueOf(api), xopts)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(functions))
	for name := range functions {
		names = append(names, name)
	}

	elems := strings.Split(strings.Trim(path, "/"), "/")
	id := elems[len(elems)-1]
	sherpaJSON := &JSON{
		ID:               id,
		Title:            doc.Name,
		Functions:        names,
		BaseURL:          "", // filled in during request
		Version:          version,
		SherpaVersion:    SherpaVersion,
		SherpadocVersion: doc.SherpadocVersion,
	}
	h := http.StripPrefix(path, &handler{
		path:       path,
		functions:  functions,
		sherpaJSON: sherpaJSON,
		opts:       xopts,
	})
	return h, nil
}

func badMethod(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// return whether callback js snippet is valid.
// this is a coarse test.  we disallow some valid js identifiers, like "\u03c0",
// and we allow many invalid ones, such as js keywords, "0intro" and identifiers starting/ending with ".", or having multiple dots.
func validCallback(cb string) bool {
	if cb == "" {
		return false
	}
	for _, c := range cb {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// Serve a HTTP request for this Sherpa API.
// ServeHTTP expects the request path is stripped from the path it was mounted at with the http package.
//
// The following endpoints are handled:
//   - sherpa.json, describing this API.
//   - sherpa.js, a small stand-alone client JavaScript library that makes it trivial to start using this API from a browser.
//   - functionName, for function invocations on this API.
//
// HTTP response will have CORS-headers set, and support the OPTIONS HTTP method.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	hdr := w.Header()
	hdr.Set("Access-Control-Allow-Origin", "*")
	hdr.Set("Access-Control-Allow-Methods", "GET, POST")
	hdr.Set("Access-Control-Allow-Headers", "Content-Type")

	collector := h.opts.Collector

	switch {
	case r.URL.Path == "":
		baseURL := getBaseURL(r) + h.path
		docURL := "https://www.sherpadoc.org/#" + baseURL
		err := htmlTemplate.Execute(w, map[string]interface{}{
			"id":      h.sherpaJSON.ID,
			"title":   h.sherpaJSON.Title,
			"version": h.sherpaJSON.Version,
			"docURL":  docURL,
			"jsURL":   baseURL + "sherpa.js",
		})
		if err != nil {
			log.Println(err)
		}

	case r.URL.Path == "sherpa.json":
		switch r.Method {
		case "OPTIONS":
			w.WriteHeader(204)
		case "GET":
			collector.JSON()
			hdr.Set("Content-Type", "application/json; charset=utf-8")
			hdr.Set("Cache-Control", "no-cache")
			sherpaJSON := &*h.sherpaJSON
			sherpaJSON.BaseURL = getBaseURL(r) + h.path
			err := json.NewEncoder(w).Encode(sherpaJSON)
			if err != nil {
				log.Println("writing sherpa.json response:", err)
			}
		default:
			badMethod(w)
		}

	case r.URL.Path == "sherpa.js":
		if r.Method != "GET" {
			badMethod(w)
			return
		}
		collector.JavaScript()
		hdr.Set("Content-Type", "text/javascript; charset=utf-8")
		hdr.Set("Cache-Control", "no-cache")
		sherpaJSON := &*h.sherpaJSON
		sherpaJSON.BaseURL = getBaseURL(r) + h.path
		buf, err := json.Marshal(sherpaJSON)
		js := strings.Replace(sherpaJS, "{{.sherpaJSON}}", string(buf), -1)
		_, err = w.Write([]byte(js))
		if err != nil {
			log.Println("writing sherpa.js response:", err)
		}

	default:
		name := r.URL.Path
		fn, ok := h.functions[name]
		switch r.Method {
		case "OPTIONS":
			w.WriteHeader(204)

		case "POST":
			hdr.Set("Cache-Control", "no-store")

			if !ok {
				collector.BadFunction()
				respondJSON(w, 404, &response{Error: &Error{Code: SherpaBadFunction, Message: fmt.Sprintf("function %q does not exist", name)}})
				return
			}

			ct := r.Header.Get("Content-Type")
			if ct == "" {
				collector.ProtocolError()
				respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf("missing content-type")}})
				return
			}
			mt, mtparams, err := mime.ParseMediaType(ct)
			if err != nil {
				collector.ProtocolError()
				respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf("invalid content-type %q", ct)}})
				return
			}
			if mt != "application/json" {
				collector.ProtocolError()
				respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf(`unrecognized content-type %q, expecting "application/json"`, mt)}})
				return
			}
			charset, ok := mtparams["charset"]
			if ok && strings.ToLower(charset) != "utf-8" {
				collector.ProtocolError()
				respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf(`unexpected charset %q, expecting "utf-8"`, charset)}})
				return
			}

			t0 := time.Now()
			r, xerr := h.call(r.Context(), name, fn, r.Body)
			durationSec := float64(time.Now().Sub(t0)) / float64(time.Second)
			if xerr != nil {
				switch err := xerr.(type) {
				case *InternalServerError:
					collector.FunctionCall(name, durationSec, err.Code)
					respondJSON(w, 500, &response{Error: err.error()})
				case *Error:
					collector.FunctionCall(name, durationSec, err.Code)
					respondJSON(w, 200, &response{Error: err})
				default:
					collector.FunctionCall(name, durationSec, "server:panic")
					panic(err)
				}
			} else {
				var v interface{}
				if raw, ok := r.(Raw); ok {
					v = raw
				} else {
					v = &response{Result: r}
				}
				collector.FunctionCall(name, durationSec, "")
				respondJSON(w, 200, v)
			}

		case "GET":
			hdr.Set("Cache-Control", "no-store")

			jsonp := false
			if !ok {
				collector.BadFunction()
				respondJSON(w, 404, &response{Error: &Error{Code: SherpaBadFunction, Message: fmt.Sprintf("function %q does not exist", name)}})
				return
			}

			err := r.ParseForm()
			if err != nil {
				collector.ProtocolError()
				respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf("could not parse query string")}})
				return
			}

			callback := r.Form.Get("callback")
			_, ok := r.Form["callback"]
			if ok {
				if !validCallback(callback) {
					collector.ProtocolError()
					respondJSON(w, 200, &response{Error: &Error{Code: SherpaBadRequest, Message: fmt.Sprintf(`invalid callback name %q`, callback)}})
					return
				}
				jsonp = true
			}

			// We allow an empty list to be missing to make it cleaner & easier to call health check functions (no ugly urls).
			body := r.Form.Get("body")
			_, ok = r.Form["body"]
			if !ok {
				body = `{"params": []}`
			}

			t0 := time.Now()
			r, xerr := h.call(r.Context(), name, fn, strings.NewReader(body))
			durationSec := float64(time.Now().Sub(t0)) / float64(time.Second)
			if xerr != nil {
				switch err := xerr.(type) {
				case *InternalServerError:
					collector.FunctionCall(name, durationSec, err.Code)
					respond(w, 500, &response{Error: err.error()}, jsonp, callback)
				case *Error:
					collector.FunctionCall(name, durationSec, err.Code)
					respond(w, 200, &response{Error: err}, jsonp, callback)
				default:
					collector.FunctionCall(name, durationSec, "server:panic")
					panic(err)
				}
			} else {
				var v interface{}
				if raw, ok := r.(Raw); ok {
					v = raw
				} else {
					v = &response{Result: r}
				}
				collector.FunctionCall(name, durationSec, "")
				respond(w, 200, v, jsonp, callback)
			}

		default:
			badMethod(w)
		}
	}
}
