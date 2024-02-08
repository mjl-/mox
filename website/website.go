//go:build website

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html"
	htmltemplate "html/template"
	"io"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/russross/blackfriday/v2"
)

func xcheck(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	var commithash = os.Getenv("commithash")
	var commitdate = os.Getenv("commitdate")

	var pageRoot, pageProtocols bool
	var pageTitle string
	flag.BoolVar(&pageRoot, "root", false, "is top-level index page, instead of in a sub directory")
	flag.BoolVar(&pageProtocols, "protocols", false, "is protocols page")
	flag.StringVar(&pageTitle, "title", "", "html title of page, set to value of link name with a suffix")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	linkname := args[0]

	if pageTitle == "" && linkname != "" {
		pageTitle = linkname + " - Mox"
	}

	// Often the website markdown file.
	input, err := io.ReadAll(os.Stdin)
	xcheck(err, "read")

	// For rendering the main content of the page.
	r := &renderer{
		linkname == "Config reference",
		"",
		*blackfriday.NewHTMLRenderer(blackfriday.HTMLRendererParameters{HeadingIDPrefix: "hdr-"}),
	}
	opts := []blackfriday.Option{
		blackfriday.WithExtensions(blackfriday.CommonExtensions | blackfriday.AutoHeadingIDs),
		blackfriday.WithRenderer(r),
	}

	// Make table of contents of a page, based on h2-links, or "## ..." in markdown.
	makeTOC := func() ([]byte, []byte) {
		var title string

		// Get the h2's, split them over the columns.
		type toclink struct {
			Title string
			ID    string
		}
		var links []toclink

		node := blackfriday.New(opts...).Parse(input)
		if node == nil {
			return nil, nil
		}
		for c := node.FirstChild; c != nil; c = c.Next {
			if c.Type != blackfriday.Heading {
				continue
			}
			if c.Level == 1 {
				title = string(c.FirstChild.Literal)
			} else if c.Level == 2 {
				link := toclink{string(c.FirstChild.Literal), c.HeadingID}
				links = append(links, link)
			}
		}

		// We split links over 2 columns if we have quite a few, to keep the page somewhat compact.
		ncol := 1
		if len(links) > 6 {
			ncol = 2
		}

		n := len(links) / ncol
		rem := len(links) - ncol*n
		counts := make([]int, ncol)
		for i := 0; i < ncol; i++ {
			counts[i] = n
			if rem > i {
				counts[i]++
			}
		}
		toc := `<div class="toc">`
		toc += "\n"
		o := 0
		for _, n := range counts {
			toc += "<ul>\n"
			for _, link := range links[o : o+n] {
				toc += fmt.Sprintf(`<li><a href="#%s">%s</a></li>`, html.EscapeString("hdr-"+link.ID), html.EscapeString(link.Title))
				toc += "\n"
			}
			toc += "</ul>\n"
			o += n
		}
		toc += "</div>\n"
		var titlebuf []byte
		if title != "" {
			titlebuf = []byte(fmt.Sprintf(`<h1 id="%s">%s</h1>`, html.EscapeString("hdr-"+blackfriday.SanitizedAnchorName(title)), html.EscapeString(title)))
		}
		return titlebuf, []byte(toc)
	}

	var output []byte
	if pageRoot {
		// Split content into two parts for main page. First two lines are special, for
		// header.
		inputstr := string(input)
		lines := strings.SplitN(inputstr, "\n", 3)
		if len(lines) < 2 {
			log.Fatalf("missing header")
		}
		inputstr = inputstr[len(lines[0])+1+len(lines[1])+1:]
		lines[0] = strings.TrimPrefix(lines[0], "#")
		lines[1] = strings.TrimPrefix(lines[1], "##")
		sep := "## Quickstart demo"
		inleft, inright, found := strings.Cut(inputstr, sep)
		if !found {
			log.Fatalf("did not find separator %q", sep)
		}
		outleft := blackfriday.Run([]byte(inleft), opts...)
		outright := blackfriday.Run([]byte(sep+inright), opts...)
		output = []byte(fmt.Sprintf(`
<div class="rootheader h1">
	<h1>%s</h1>
	<h2>%s</h2>
</div>
<div class="two"><div>%s</div><div>%s</div></div>`, html.EscapeString(lines[0]), html.EscapeString(lines[1]), outleft, outright))
	} else if pageProtocols {
		// ../rfc/index.txt is the standard input. We'll read each topic and the RFCs.
		topics := parseTopics(input)

		// First part of content is in markdown file.
		summary, err := os.ReadFile("protocols/summary.md")
		xcheck(err, "reading protocol summary")

		output = blackfriday.Run(summary, opts...)

		var out bytes.Buffer
		_, err = out.Write(output)
		xcheck(err, "write")

		err = protocolTemplate.Execute(&out, map[string]any{"Topics": topics})
		xcheck(err, "render protocol support")

		output = out.Bytes()
	} else {
		// Other pages.
		xinput := input
		if bytes.HasPrefix(xinput, []byte("# ")) {
			xinput = bytes.SplitN(xinput, []byte("\n"), 2)[1]
		}
		output = blackfriday.Run(xinput, opts...)
		titlebuf, toc := makeTOC()
		output = append(toc, output...)
		output = append(titlebuf, output...)
	}

	// HTML preamble.
	before = strings.Replace(before, "<title>...</title>", "<title>"+html.EscapeString(pageTitle)+"</title>", 1)
	before = strings.Replace(before, ">"+linkname+"<", ` style="font-weight: bold">`+linkname+"<", 1)
	if !pageRoot {
		before = strings.ReplaceAll(before, `"./`, `"../`)
	}
	_, err = os.Stdout.Write([]byte(before))
	xcheck(err, "write")

	// Page content.
	_, err = os.Stdout.Write(output)
	xcheck(err, "write")

	// Bottom, HTML closing.
	after = strings.Replace(after, "[commit]", fmt.Sprintf("%s, commit %s", commitdate, commithash), 1)
	_, err = os.Stdout.Write([]byte(after))
	xcheck(err, "write")
}

// Implementation status of standards/protocols.
type Status string

const (
	Implemented    Status = "Yes"
	Partial        Status = "Partial"
	Roadmap        Status = "Roadmap"
	NotImplemented Status = "No"
	Unknown        Status = "?"
)

// RFC and its implementation status.
type RFC struct {
	Number      int
	Title       string
	Status      Status
	StatusClass string
	Obsolete    bool
}

// Topic is a group of RFC's, typically by protocol, e.g. SMTP.
type Topic struct {
	Title string
	ID    string
	RFCs  []RFC
}

// parse topics and RFCs from ../rfc/index.txt.
// headings are topics, and hold the RFCs that follow them.
func parseTopics(input []byte) []Topic {
	var l []Topic
	var t *Topic

	b := bufio.NewReader(bytes.NewReader(input))
	for {
		line, err := b.ReadString('\n')
		if line != "" {
			if strings.HasPrefix(line, "# ") {
				// Skip topics without RFCs to show on the website.
				if t != nil && len(t.RFCs) == 0 {
					l = l[:len(l)-1]
				}
				title := strings.TrimPrefix(line, "# ")
				id := blackfriday.SanitizedAnchorName(title)
				l = append(l, Topic{Title: title, ID: id})
				t = &l[len(l)-1] // RFCs will be added to t.
				continue
			}

			// Tokens: RFC number, implementation status, is obsolete, title.
			tokens := strings.Split(line, "\t")
			if len(tokens) != 4 {
				continue
			}

			ignore := strings.HasPrefix(tokens[1], "-")
			if ignore {
				continue
			}
			status := Status(strings.TrimPrefix(tokens[1], "-"))
			var statusClass string
			switch status {
			case Implemented:
				statusClass = "implemented"
			case Partial:
				statusClass = "partial"
			case Roadmap:
				statusClass = "roadmap"
			case NotImplemented:
				statusClass = "notimplemented"
			case Unknown:
				statusClass = "unknown"
			default:
				log.Fatalf("unknown implementation status %q, line %q", status, line)
			}

			number, err := strconv.ParseInt(tokens[0], 10, 32)
			xcheck(err, "parsing rfc number")
			flags := strings.Split(tokens[2], ",")
			title := tokens[3]

			rfc := RFC{
				int(number),
				title,
				status,
				statusClass,
				slices.Contains(flags, "Obs"),
			}
			t.RFCs = append(t.RFCs, rfc)
		}
		if err == io.EOF {
			break
		}
		xcheck(err, "read line")
	}
	// Skip topics without RFCs to show on the website.
	if t != nil && len(t.RFCs) == 0 {
		l = l[:len(l)-1]
	}
	return l
}

// renderer is used for all HTML pages, for showing links to h2's on hover, and for
// specially rendering the config files with links for each config field.
type renderer struct {
	codeBlockConfigFile      bool   // Whether to interpret codeblocks as config files.
	h2                       string // Current title, for config line IDs.
	blackfriday.HTMLRenderer        // Embedded for RenderFooter and RenderHeader.
}

func (r *renderer) RenderNode(w io.Writer, node *blackfriday.Node, entering bool) blackfriday.WalkStatus {
	if node.Type == blackfriday.Heading && node.Level == 2 {
		r.h2 = string(node.FirstChild.Literal)

		id := "hdr-" + blackfriday.SanitizedAnchorName(string(node.FirstChild.Literal))
		if entering {
			_, err := fmt.Fprintf(w, `<h2 id="%s">`, id)
			xcheck(err, "write")
		} else {
			_, err := fmt.Fprintf(w, ` <a href="#%s">#</a></h2>`, id)
			xcheck(err, "write")
		}
		return blackfriday.GoToNext
	}
	if r.codeBlockConfigFile && node.Type == blackfriday.CodeBlock {
		if !entering {
			log.Fatalf("not entering")
		}

		_, err := fmt.Fprintln(w, `<div class="config">`)
		xcheck(err, "write")
		r.writeConfig(w, node.Literal)
		_, err = fmt.Fprintln(w, "</div>")
		xcheck(err, "write")
		return blackfriday.GoToNext
	}
	return r.HTMLRenderer.RenderNode(w, node, entering)
}

func (r *renderer) writeConfig(w io.Writer, data []byte) {
	var fields []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		var attrs, link string

		s := string(line)
		text := strings.TrimLeft(s, "\t")
		if strings.HasPrefix(text, "#") {
			attrs = ` class="comment"`
		} else if text != "" {
			// Add id attribute and link to it, based on the nested config fields that lead here.
			ntab := len(s) - len(text)
			nfields := ntab + 1
			if len(fields) >= nfields {
				fields = fields[:nfields]
			} else if nfields > len(fields)+1 {
				xcheck(errors.New("indent jumped"), "write codeblock")
			} else {
				fields = append(fields, "")
			}

			var word string
			if text == "-" {
				word = "dash"
			} else {
				word = strings.Split(text, ":")[0]
			}
			fields[nfields-1] = word

			id := fmt.Sprintf("cfg-%s-%s", blackfriday.SanitizedAnchorName(r.h2), strings.Join(fields, "-"))
			attrs = fmt.Sprintf(` id="%s"`, id)
			link = fmt.Sprintf(` <a href="#%s">#</a>`, id)
		}
		if s == "" {
			line = []byte("\n") // Prevent empty, zero-height line.
		}
		_, err := fmt.Fprintf(w, "<div%s>%s%s</div>\n", attrs, html.EscapeString(string(line)), link)
		xcheck(err, "write codeblock")
	}
}

var before = `<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<title>...</title>
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<link rel="icon" href="noNeedlessFaviconRequestsPlease:" />
		<style>
* { font-size: 18px; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-padding-top: 4ex; }
.textblock { max-width: 50em; margin: 0 auto; }
p { max-width: 50em; margin-bottom: 2ex; }
ul, ol { max-width: 50em; margin-bottom: 2ex; }
pre, code, .config, .config * { font-family: "ubuntu mono", monospace; }
pre, .config { margin-bottom: 2ex; padding: 1em; background-color: #f8f8f8; border-radius: .25em; }
pre { white-space: pre-wrap; }
code { background-color: #eee; }
pre code { background-color: inherit; }
h1 { font-size: 1.8em; }
h2 { font-size: 1.25em; margin-bottom: 1ex; }
h2 > a { opacity: 0; }
h2:hover > a { opacity: 1; }
h3 { font-size: 1.1em; margin-bottom: 1ex; }
.feature {display: inline-block; width: 30%; margin: 1em; }
dl { margin: 1em 0; }
dt { font-weight: bold; margin-bottom: .5ex; }
dd { max-width: 50em; padding-left: 2em; margin-bottom: 1em; }
table { margin-bottom: 2ex; }

video { display: block; max-width: 100%; box-shadow: 0 0 20px 0 #ddd; margin: 0 auto; }
.img1 { width: 1050px; max-width: 100%; box-shadow: 0 0 20px 0 #bbb; }
.img2 { width: 1500px; max-width: 100%; box-shadow: 0 0 20px 0 #bbb; }

.implemented { background: linear-gradient(90deg, #bbf05c 0%, #d0ff7d 100%); padding: 0 .25em; display: inline-block; }
.partial { background: linear-gradient(90deg, #f2f915 0%, #fbff74 100%); padding: 0 .25em; display: inline-block; }
.roadmap { background: linear-gradient(90deg, #ffbf6c 0%, #ffd49c 100%); padding: 0 .25em; display: inline-block; }
.notimplemented { background: linear-gradient(90deg, #ffa2fe 0%, #ffbffe 100%); padding: 0 .25em; display: inline-block; }
.unknown { background: linear-gradient(90deg, #ccc 0%, #e2e2e2 100%); padding: 0 .25em; display: inline-block; }

.config > * { white-space: pre-wrap; }
.config .comment { color: #777; }
.config > div > a { opacity: 0; }
.config > div:hover > a { opacity: 1; }
.config > div:target { background-color: gold; }

.rfcs .topic a { opacity: 0; }
.rfcs .topic:hover a { opacity: 1; }

.rootheader { background: linear-gradient(90deg, #ff9d9d 0%, #ffbd9d 100%); display: inline-block; padding: .25ex 3em .25ex 1em; border-radius: .2em; margin-bottom: 2ex; }
h1, .h1 { margin-bottom: 1ex; }
h2 { background: linear-gradient(90deg, #6dd5fd 0%, #77e8e3 100%); display: inline-block; padding: 0 .5em 0 .25em; margin-top: 2ex; font-weight: normal; }
.rootheader h1, .rootheader h2 { background: none; display: block; padding: 0; margin-top: 0; font-weight: bold; margin-bottom: 0; }
.meta { padding: 1em; display: flex; justify-content: space-between; margin: -1em; }
.meta > div > * { font-size: .9em; opacity: .5; }
.meta > nth-child(2) { text-align: right; opacity: .35 }

.navbody { display: flex; }
.nav { padding: 1em; text-align: right; background-color: #f4f4f4; }
.nav li { white-space: pre; }
.main { padding: 1em; }
.main ul, .main ol { padding-left: 1em; }
.two { display: flex; gap: 2em; }
.two > div { flex-basis: 50%; max-width: 50em; }
.toc { display: flex; gap: 2em; margin-bottom: 3ex; }
.toc ul { margin-bottom: 0; }

@media (min-width:1025px) {
	.nav { box-shadow: inset 0 0 10px rgba(0, 0, 0, 0.075); min-height: 100vh; }
	.main { padding-left: 2em; }
}
@media (max-width:1024px) {
	.navbody { display: block; }
	.main { box-shadow: 0 0 10px rgba(0, 0, 0, 0.075); }
	.nav { text-align: left; }
	.nav ul { display: inline; }
	.nav li { display: inline; }
	.nav .linkpad { display: none; }
	.extlinks { display: none; }
	.two { display: block; }
	.two > div { max-width: auto; }
	.toc { display: block; }
}
		</style>
	</head>
	<body>
		<div class="navbody">
			<nav class="nav">
				<ul style="list-style: none">
					<li><a href="./">Mox</a></li>
					<li><a href="./features/">Features</a></li>
					<li><a href="./screenshots/">Screenshots</a></li>
					<li><a href="./install/">Install</a></li>
					<li><a href="./faq/">FAQ</a></li>
					<li><a href="./config/">Config reference</a></li>
					<li><a href="./commands/">Command reference</a></li>
					<li class="linkpad" style="visibility: hidden; font-weight: bold; height: 0"><a href="./commands/">Command reference</a></li>
					<li><a href="./protocols/">Protocols</a></li>
				</ul>
				<div class="extlinks">
					<br/>
					External links:
					<ul style="list-style: none">
						<li><a href="https://github.com/mjl-/mox">Sources at github</a></li>
					</ul>
				</div>
			</nav>

			<div class="main">
`

var after = `
				<br/>
				<br/>
				<div class="meta">
					<div><a href="https://github.com/mjl-/mox/issues/new?title=website:+">feedback?</a></div>
					<div><span>[commit]</span></div>
				</div>
			</div>
		</div>
	</body>
</html>
`

// Template for protocol page, minus the first section which is read from
// protocols/summary.md.
var protocolTemplate = htmltemplate.Must(htmltemplate.New("protocolsupport").Parse(`
<table>
	<tr>
		<td><span class="implemented">Yes</span></td>
		<td>All/most of the functionality of the RFC has been implemented.</td>
	</tr>
	<tr>
		<td><span class="partial">Partial</span></td>
		<td>Some of the functionality from the RFC has been implemented.</td>
	</tr>
	<tr>
		<td><span class="roadmap">Roadmap</span></td>
		<td>Implementing functionality from the RFC is on the roadmap.</td>
	</tr>
	<tr>
		<td><span class="notimplemented">No</span></td>
		<td>Functionality from the RFC has not been implemented, is not currently on the roadmap, but may be in the future.</td>
	</tr>
	<tr>
		<td><span class="unknown">?</span></td>
		<td>Status undecided, unknown or not applicable.</td>
	</tr>
</table>

<table class="rfcs">
	<tr>
		<th>RFC #</th>
		<th>Status</th>
		<th style="text-align: left">Title</th>
	</tr>
{{ range .Topics }}
	<tr>
		<td colspan="3" style="font-weight: bold; padding: 3ex 0 1ex 0" id="topic-{{ .ID }}" class="topic">{{ .Title }} <a href="#topic-{{ .ID }}">#</a></td>
	</tr>
	{{ range .RFCs }}
	<tr{{ if .Obsolete }} style="opacity: .3"{{ end }}>
		<td style="text-align: right"><a href="../xr/dev/#code,rfc/{{ .Number }}">{{ .Number }}</a></td>
		<td style="text-align: center"><span class="{{ .StatusClass }}">{{ .Status }}</span></td>
		<td>{{ if .Obsolete }}Obsolete: {{ end }}{{ .Title }}</td>
	</tr>
	{{ end }}
{{ end }}
</table>
`))
