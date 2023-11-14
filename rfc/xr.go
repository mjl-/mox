//go:build xr

package main

// xr reads source files and rfc files and generates html versions, a code and
// rfc index file, and an overal index file to view code and rfc side by side.

import (
	"bytes"
	"flag"
	"fmt"
	htmltemplate "html/template"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
)

var destdir string

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		log.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func xwritefile(path string, buf []byte) {
	p := filepath.Join(destdir, path)
	os.MkdirAll(filepath.Dir(p), 0755)
	err := os.WriteFile(p, buf, 0644)
	xcheckf(err, "writing file", p)
}

func main() {
	log.SetFlags(0)

	var release bool
	flag.BoolVar(&release, "release", false, "generate cross-references for a release, highlighting the release version as active page")
	flag.Usage = func() {
		log.Println("usage: go run xr.go destdir revision latestrelease ../*.go ../*/*.go")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 3 {
		flag.Usage()
	}

	destdir = args[0]
	revision := args[1]
	latestRelease := args[2]
	srcfiles := args[3:]

	// Generate code.html index.
	srcdirs := map[string][]string{}
	for _, arg := range srcfiles {
		arg = strings.TrimPrefix(arg, "../")
		dir := filepath.Dir(arg)
		file := filepath.Base(arg)
		srcdirs[dir] = append(srcdirs[dir], file)
	}
	for _, files := range srcdirs {
		sort.Strings(files)
	}
	dirs := maps.Keys(srcdirs)
	sort.Strings(dirs)
	var codeBuf bytes.Buffer
	err := codeTemplate.Execute(&codeBuf, map[string]any{
		"Dirs": srcdirs,
	})
	xcheckf(err, "generating code.html")
	xwritefile("code.html", codeBuf.Bytes())

	// Generate code html files.
	re := regexp.MustCompile(`(\.\./)?rfc/[0-9]{3,5}(-[^ :]*)?(:[0-9]+)?`)
	for dir, files := range srcdirs {
		for _, file := range files {
			src := filepath.Join("..", dir, file)
			dst := filepath.Join(dir, file+".html")
			buf, err := os.ReadFile(src)
			xcheckf(err, "reading file %s", src)

			var b bytes.Buffer
			fmt.Fprint(&b, `<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<style>
html { scroll-padding-top: 35%; }
body { font-family: 'ubuntu mono', monospace; }
.ln { position: absolute; display: none; background-color: #eee; padding-right: .5em; }
.l { white-space: pre-wrap; }
.l:hover .ln { display: inline; }
.l:target { background-color: gold; }
		</style>
	</head>
	<body>
`)

			for i, line := range strings.Split(string(buf), "\n") {
				n := i + 1
				_, err := fmt.Fprintf(&b, `<div id="L%d" class="l"><a href="#L%d" class="ln">%d</a>`, n, n, n)
				xcheckf(err, "writing source line")

				if line == "" {
					b.WriteString("\n")
				} else {
					for line != "" {
						loc := re.FindStringIndex(line)
						if loc == nil {
							b.WriteString(htmltemplate.HTMLEscapeString(line))
							break
						}
						s, e := loc[0], loc[1]
						b.WriteString(htmltemplate.HTMLEscapeString(line[:s]))
						match := line[s:e]
						line = line[e:]
						t := strings.Split(match, ":")
						linenumber := 1
						if len(t) == 2 {
							v, err := strconv.ParseInt(t[1], 10, 31)
							xcheckf(err, "parsing linenumber %q", t[1])
							linenumber = int(v)
						}
						fmt.Fprintf(&b, `<a href="%s.html#L%d" target="rfc">%s</a>`, t[0], linenumber, htmltemplate.HTMLEscapeString(match))
					}
				}
				fmt.Fprint(&b, "</div>\n")
			}

			fmt.Fprint(&b, `<script>
for (const a of document.querySelectorAll('a')) {
	a.addEventListener('click', function(e) {
		location.hash = '#'+e.target.closest('.l').id
	})
}
</script>
	</body>
</html>
`)

			xwritefile(dst, b.Bytes())
		}
	}

	// Generate rfc index.
	rfctext, err := os.ReadFile("index.txt")
	xcheckf(err, "reading rfc index.txt")
	type rfc struct {
		File  string
		Title string
	}
	topics := map[string][]rfc{}
	var topic string
	for _, line := range strings.Split(string(rfctext), "\n") {
		if strings.HasPrefix(line, "# ") {
			topic = line[2:]
			continue
		}
		t := strings.Split(line, "\t")
		if len(t) != 2 {
			continue
		}
		topics[topic] = append(topics[topic], rfc{strings.TrimSpace(t[0]), t[1]})
	}
	for _, l := range topics {
		sort.Slice(l, func(i, j int) bool {
			return l[i].File < l[j].File
		})
	}
	var rfcBuf bytes.Buffer
	err = rfcTemplate.Execute(&rfcBuf, map[string]any{
		"Topics": topics,
	})
	xcheckf(err, "generating rfc.html")
	xwritefile("rfc.html", rfcBuf.Bytes())

	// Process each rfc file into html.
	for _, rfcs := range topics {
		for _, rfc := range rfcs {
			dst := filepath.Join("rfc", rfc.File+".html")

			buf, err := os.ReadFile(rfc.File)
			xcheckf(err, "reading rfc %s", rfc.File)

			var b bytes.Buffer
			fmt.Fprint(&b, `<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<style>
html { scroll-padding-top: 35%; }
body { font-family: 'ubuntu mono', monospace; }
.ln { position: absolute; display: none; background-color: #eee; padding-right: .5em; }
.l { white-space: pre-wrap; }
.l:hover .ln { display: inline; }
.l:target { background-color: gold; }
		</style>
	</head>
	<body>
`)

			isRef := func(s string) bool {
				return s[0] >= '0' && s[0] <= '9' || strings.HasPrefix(s, "../")
			}

			parseRef := func(s string) (string, int, bool) {
				t := strings.Split(s, ":")
				linenumber := 1
				if len(t) == 2 {
					v, err := strconv.ParseInt(t[1], 10, 31)
					xcheckf(err, "parsing linenumber")
					linenumber = int(v)
				}
				isCode := strings.HasPrefix(t[0], "../")
				return t[0], linenumber, isCode
			}

			for i, line := range strings.Split(string(buf), "\n") {
				if line == "" {
					line = "\n"
				} else if len(line) < 80 || strings.Contains(rfc.File, "-") && i > 0 {
					line = htmltemplate.HTMLEscapeString(line)
				} else {
					t := strings.Split(line[80:], " ")
					line = htmltemplate.HTMLEscapeString(line[:80])
					for i, s := range t {
						if i > 0 {
							line += " "
						}
						if s == "" || !isRef(s) {
							line += htmltemplate.HTMLEscapeString(s)
							continue
						}
						file, linenumber, isCode := parseRef(s)
						target := ""
						if isCode {
							target = ` target="code"`
						}
						line += fmt.Sprintf(` <a href="%s.html#L%d"%s>%s:%d</a>`, file, linenumber, target, file, linenumber)
					}
				}
				n := i + 1
				_, err := fmt.Fprintf(&b, `<div id="L%d" class="l"><a href="#L%d" class="ln">%d</a>%s</div>%s`, n, n, n, line, "\n")
				xcheckf(err, "writing rfc line")
			}

			fmt.Fprint(&b, `
<script>
for (const a of document.querySelectorAll('a')) {
	a.addEventListener('click', function(e) {
		console.log('click', e.target.closest('.l').id)
		location.hash = '#'+e.target.closest('.l').id
	})
}
</script>
	</body>
</html>
`)

			xwritefile(dst, b.Bytes())
		}
	}

	// Generate overal file.
	index := indexHTML
	if release {
		index = strings.ReplaceAll(index, "RELEASEWEIGHT", "bold")
		index = strings.ReplaceAll(index, "REVISIONWEIGHT", "normal")
	} else {
		index = strings.ReplaceAll(index, "RELEASEWEIGHT", "normal")
		index = strings.ReplaceAll(index, "REVISIONWEIGHT", "bold")
	}
	index = strings.ReplaceAll(index, "REVISION", revision)
	index = strings.ReplaceAll(index, "RELEASE", latestRelease)
	xwritefile("index.html", []byte(index))
}

var indexHTML = `<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>mox cross-referenced code and RFCs</title>
		<style>
body { margin: 0; padding: 0; font-family: 'ubuntu', 'lato', sans-serif; }
[title] { text-decoration: underline; text-decoration-style: dotted; }
		</style>
	</head>
	<body>
		<div style="display: flex; flex-direction: column; height: 100vh">
			<div style="padding: .5em"><a href="../../">mox</a>, <span title="The mox code contains references to RFCs, often with specific line numbers. RFCs are generated that point back to the source code. This page shows code and RFCs side by side, with cross-references hyperlinked.">cross-referenced code and RFCs</span>: <a href="../RELEASE/" style="font-weight: RELEASEWEIGHT" title="released version">RELEASE</a> <a href="../dev/" style="font-weight: REVISIONWEIGHT" title="branch main">dev</a> (<a href="https://github.com/mjl-/mox/commit/REVISION" title="Source code commit for this revision.">commit REVISION</a>)</div>
			<div style="flex-grow: 1; display: flex; align-items: stretch">
				<div style="flex-grow: 1; margin: 1ex; position: relative; display: flex; flex-direction: column">
					<div style="margin-bottom: .5ex"><span id="codefile" style="font-weight: bold">...</span>, <a href="code.html" target="code">index</a></div>
					<iframe id="codeiframe" name="code" style="border: 1px solid #aaa; width: 100%; height: 100%; background-color: #eee; border-radius: .25em"></iframe>
				</div>
				<div style="flex-grow: 1; margin: 1ex; position: relative; display: flex; flex-direction: column">
					<div style="margin-bottom: .5ex"><span id="rfcfile" style="font-weight: bold">...</span>, <a href="rfc.html" target="rfc">index</a></div>
					<iframe id="rfciframe" name="rfc" style="border: 1px solid #aaa; width: 100%; height: 100%; background-color: #eee; border-radius: .25em"></iframe>
				</div>
			</div>
		</div>
		<script>
const basepath = location.pathname
function trimDotHTML(s) {
	if (s.endsWith('.html')) {
		return s.substring(s, s.length-'.html'.length)
	}
	return s
}
let changinghash = false
function hashline(s) {
	return s ? ':'+s.substring('#L'.length) : ''
}
function updateHash() {
	const code = trimDotHTML(codeiframe.contentWindow.location.pathname.substring(basepath.length))+hashline(codeiframe.contentWindow.location.hash)
	const rfc = trimDotHTML(rfciframe.contentWindow.location.pathname.substring(basepath.length))+hashline(rfciframe.contentWindow.location.hash)
	codefile.innerText = code
	rfcfile.innerText = rfc
	console.log('updating window hash')
	changinghash = true
	location.hash = '#' + code + ',' + rfc
	window.setTimeout(() => {
		changinghash = false
		console.log('done updating updating window hash')
	}, 0)
}
codeiframe.addEventListener('load', function(e) {
	console.log('codeiframe load', e, codeiframe.src)
	if (!rfciframe.src) {
		return
	}
	updateHash()
	codeiframe.contentWindow.addEventListener('hashchange', function(e) {
		console.log('hash of codeiframe changed', codeiframe.contentWindow.location.hash)
		updateHash()
	})
})
rfciframe.addEventListener('load', function(e) {
	console.log('rfciframe load', e, rfciframe.src)
	if (!rfciframe.src) {
		return
	}
	updateHash()
	rfciframe.contentWindow.addEventListener('hashchange', function(e) {
		console.log('hash of rfciframe changed', rfciframe.contentWindow.location.hash)
		updateHash()
	})
})
window.addEventListener('hashchange', function() {
	console.log('window hashchange', location.hash)
	if (changinghash) {
		console.log('not updating iframes src')
		return
	}
	console.log('updating iframes src')
	updateIframes()
})
function hashlink2src(s) {
	const t = s.split(':')
	if (t.length > 2 || t[0].startsWith('/') || t[0].includes('..')) {
		return ''
	}
	let h = t[0]+'.html'
	if (t.length === 2) {
		h += '#L'+t[1]
	}
	h = './'+h
	console.log('hashlink', s, h)
	return h
}
function updateIframes() {
	const h = location.hash.length > 1 ? location.hash.substring(1) : 'code,rfc'
	const t = h.split(',')
	const codesrc = hashlink2src(t[0])
	const rfcsrc = hashlink2src(t[1])
	codeiframe.src = codesrc
	rfciframe.src = rfcsrc
	if (codesrc) {
		codefile.innerText = t[0]
	}
	if (rfcsrc) {
		rfcfile.innerText = t[1]
	}
}
window.addEventListener('load', function() {
	console.log('document load')
	updateIframes()
})
		</script>
	</body>
</html>
`

var codeTemplate = htmltemplate.Must(htmltemplate.New("code").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>code index</title>
		<style>
* { font-size: inherit; font-family: 'ubuntu mono', monospace; margin: 0; padding: 0; box-sizing: border-box; }
		</style>
	</head>
	<body>
		<table>
			<tr><th>Package</th><th>Files</th></tr>
{{- range $dir, $files := .Dirs }}
			<tr>
				<td>{{ $dir }}/</td>
				<td>
				{{- range $files }}
					<a href="{{ $dir }}/{{ . }}.html">{{ . }}</a>
				{{- end }}
				</td>
			</tr>
{{- end }}
		</table>
	</body>
</html>
`))

var rfcTemplate = htmltemplate.Must(htmltemplate.New("rfc").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<style>
* { font-size: inherit; font-family: 'ubuntu mono', monospace; margin: 0; padding: 0; }
		</style>
	</head>
	<body>
		<table>
			<tr><th>Topic</th><th>RFC</th></tr>
{{- range $topic, $rfcs := .Topics }}
			<tr>
				<td>{{ $topic }}</td>
				<td>
				{{- range $rfcs }}
					<a href="rfc/{{ .File }}.html" title="{{ .Title }}">{{ .File }}</a>
				{{- end }}
				</td>
			</tr>
{{- end }}
		</table>
	</body>
</html>
`))
