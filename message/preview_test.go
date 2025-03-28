package message

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"

	"github.com/mjl-/mox/mlog"
)

func TestPreviewText(t *testing.T) {
	check := func(body, expLine string) {
		t.Helper()

		line, err := previewText(strings.NewReader(body))
		tcompare(t, err, nil)
		if line != expLine {
			t.Fatalf("got %q, expected %q, for body %q", line, expLine, body)
		}
	}

	check("", "")
	check("single line", "single line\n")
	check("single line\n", "single line\n")
	check("> quoted\n", "[...]\n")
	check("> quoted\nresponse\n", "[...]\nresponse\n")
	check("> quoted\n[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check("[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check("[…]\nresponse after author snip\n", "[…]\nresponse after author snip\n")
	check(">> quoted0\n> quoted1\n>quoted2\n[...]\nresponse after author snip\n", "[...]\nresponse after author snip\n")
	check(">quoted\n\n>quoted\ncoalesce line-separated quotes\n", "[...]\ncoalesce line-separated quotes\n")
	check("On <date> <user> wrote:\n> hi\nresponse", "[...]\nresponse\n")
	check("On <longdate>\n<user> wrote:\n> hi\nresponse", "[...]\nresponse\n")
	check("> quote\nresponse\n--\nsignature\n", "[...]\nresponse\n")
	check("> quote\nline1\nline2\nline3\n", "[...]\nline1\nline2\nline3\n")
}

func tcompose(t *testing.T, typeContents ...string) *bytes.Reader {
	var b bytes.Buffer

	xc := NewComposer(&b, 100*1024, true)
	xc.Header("MIME-Version", "1.0")

	var cur, alt *multipart.Writer

	xcreateMultipart := func(subtype string) *multipart.Writer {
		mp := multipart.NewWriter(xc)
		if cur == nil {
			xc.Header("Content-Type", fmt.Sprintf(`multipart/%s; boundary="%s"`, subtype, mp.Boundary()))
			xc.Line()
		} else {
			_, err := cur.CreatePart(textproto.MIMEHeader{"Content-Type": []string{fmt.Sprintf(`multipart/%s; boundary="%s"`, subtype, mp.Boundary())}})
			tcheck(t, err, "adding multipart")
		}
		cur = mp
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
		tcheck(t, err, "adding part")
		return p
	}

	if len(typeContents)/2 > 1 {
		alt = xcreateMultipart("alternative")
	}
	for i := 0; i < len(typeContents); i += 2 {
		body, ct, cte := xc.TextPart(typeContents[i], typeContents[i+1])
		tp := xcreatePart(textproto.MIMEHeader{"Content-Type": []string{ct}, "Content-Transfer-Encoding": []string{cte}})
		_, err := tp.Write([]byte(body))
		tcheck(t, err, "write part")
	}
	if alt != nil {
		err := alt.Close()
		tcheck(t, err, "close multipart")
	}
	xc.Flush()

	buf := b.Bytes()
	return bytes.NewReader(buf)
}

func TestPreviewHTML(t *testing.T) {
	check := func(r *bytes.Reader, exp string) {
		t.Helper()

		p, err := Parse(slog.Default(), false, r)
		tcheck(t, err, "parse")
		err = p.Walk(slog.Default(), nil)
		tcheck(t, err, "walk")
		log := mlog.New("message", nil)
		s, err := p.Preview(log)
		tcheck(t, err, "preview")
		tcompare(t, s, exp)
	}

	// We use the first part for the preview.
	m := tcompose(t, "plain", "the text", "html", "<html><body>the html</body></html>")
	check(m, "the text\n")

	// HTML before text.
	m = tcompose(t, "html", "<body>the html</body>", "plain", "the text")
	check(m, "the html\n")

	// Only text.
	m = tcompose(t, "plain", "the text")
	check(m, "the text\n")

	// Only html.
	m = tcompose(t, "html", "<body>the html</body>")
	check(m, "the html\n")

	// No preview
	m = tcompose(t, "other", "other text")
	check(m, "")

	// HTML with quoted text.
	m = tcompose(t, "html", "<html><div>On ... someone wrote:</div><blockquote>something worth replying</blockquote><div>agreed</div></body>")
	check(m, "[...]\nagreed\n")

	// HTML with ignored elements, inline elements and tables.
	const moreHTML = `<!doctype html>
<html>
	<head>
		<title>title</title>
		<style>head style</style>
		<script>head script</script>
	</head>
<body>
<script>body script</script>
<style>body style</style>
<div>line1</div>
<div>line2</div>
<div><a href="about:blank">link1   </a> text <span>word</span><span>word2</span>.</div>
<table><tr><td>col1</td><th>col2</th></tr><tr><td>row2</td></tr></table>
</body></html>
`
	m = tcompose(t, "html", moreHTML)
	check(m, `line1
line2
link1 text wordword2.
col1 col2
row2
`)
}
