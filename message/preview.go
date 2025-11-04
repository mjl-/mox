package message

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

// Preview returns a message preview, based on the first text/plain or text/html
// part of the message that has textual content. Preview returns at most 256
// characters (possibly more bytes). Callers may want to truncate and trim trailing
// whitespace before using the preview.
//
// Preview logs at debug level for invalid messages. An error is only returned for
// serious errors, like i/o errors.
func (p Part) Preview(log mlog.Log) (string, error) {
	// ../rfc/8970:190

	// Don't use if Content-Disposition attachment.
	disp, _, err := p.DispositionFilename()
	if err != nil {
		log.Debugx("parsing disposition/filename", err)
	} else if strings.EqualFold(disp, "attachment") {
		return "", nil
	}

	mt := p.MediaType + "/" + p.MediaSubType
	switch mt {
	case "TEXT/PLAIN", "/":
		r := &moxio.LimitReader{R: p.ReaderUTF8OrBinary(), Limit: 1024 * 1024}
		s, err := previewText(r)
		if err != nil {
			if errors.Is(err, moxio.ErrLimit) {
				log.Debug("no preview in first mb of text message")
				return "", nil
			}
			return "", fmt.Errorf("making preview from text part: %v", err)
		}
		return s, nil

	case "TEXT/HTML":
		r := &moxio.LimitReader{R: p.ReaderUTF8OrBinary(), Limit: 1024 * 1024}

		// First turn the HTML into text.
		s, err := previewHTML(r)
		if err != nil {
			log.Debugx("parsing html part for preview (ignored)", err)
			return "", nil
		}

		// Turn text body into a preview text.
		s, err = previewText(strings.NewReader(s))
		if err != nil {
			if errors.Is(err, moxio.ErrLimit) {
				log.Debug("no preview in first mb of html message")
				return "", nil
			}
			return "", fmt.Errorf("making preview from text from html: %v", err)
		}
		return s, nil

	case "MULTIPART/ENCRYPTED":
		return "", nil
	}

	for i, sp := range p.Parts {
		if mt == "MULTIPART/SIGNED" && i >= 1 {
			break
		}
		s, err := sp.Preview(log)
		if err != nil || s != "" {
			return s, err
		}
	}
	return "", nil
}

// previewText returns a line the client can display next to the subject line
// in a mailbox. It will replace quoted text, and any prefixing "On ... wrote:"
// line with "[...]" so only new and useful information will be displayed.
// Trailing signatures are not included.
func previewText(r io.Reader) (string, error) {
	// We look quite a bit of lines ahead for trailing signatures with trailing empty lines.
	var lines []string
	scanner := bufio.NewScanner(r)
	ensureLines := func() {
		for len(lines) < 10 && scanner.Scan() {
			lines = append(lines, strings.TrimSpace(scanner.Text()))
		}
	}
	ensureLines()

	isSnipped := func(s string) bool {
		return s == "[...]" || s == "[…]" || s == "..."
	}

	nextLineQuoted := func(i int) bool {
		if i+1 < len(lines) && lines[i+1] == "" {
			i++
		}
		return i+1 < len(lines) && (strings.HasPrefix(lines[i+1], ">") || isSnipped(lines[i+1]))
	}

	// Remainder is signature if we see a line with only and minimum 2 dashes, and
	// there are no more empty lines, and there aren't more than 5 lines left.
	isSignature := func() bool {
		if len(lines) == 0 || !strings.HasPrefix(lines[0], "--") || strings.Trim(strings.TrimSpace(lines[0]), "-") != "" {
			return false
		}
		l := lines[1:]
		for len(l) > 0 && l[len(l)-1] == "" {
			l = l[:len(l)-1]
		}
		if len(l) >= 5 {
			return false
		}
		return !slices.Contains(l, "")
	}

	result := ""

	resultSnipped := func() bool {
		return strings.HasSuffix(result, "[...]\n") || strings.HasSuffix(result, "[…]")
	}

	// Quick check for initial wrapped "On ... wrote:" line.
	if len(lines) > 3 && strings.HasPrefix(lines[0], "On ") && !strings.HasSuffix(lines[0], "wrote:") && strings.HasSuffix(lines[1], ":") && nextLineQuoted(1) {
		result = "[...]\n"
		lines = lines[3:]
		ensureLines()
	}

	for ; len(lines) > 0 && !isSignature(); ensureLines() {
		line := lines[0]
		if strings.HasPrefix(line, ">") {
			if !resultSnipped() {
				result += "[...]\n"
			}
			lines = lines[1:]
			continue
		}
		if line == "" {
			lines = lines[1:]
			continue
		}
		// Check for a "On <date>, <person> wrote:", we require digits before a quoted
		// line, with an optional empty line in between. If we don't have any text yet, we
		// don't require the digits.
		if strings.HasSuffix(line, ":") && (strings.ContainsAny(line, "0123456789") || result == "") && nextLineQuoted(0) {
			if !resultSnipped() {
				result += "[...]\n"
			}
			lines = lines[1:]
			continue
		}
		// Skip possibly duplicate snipping by author.
		if !isSnipped(line) || !resultSnipped() {
			result += line + "\n"
		}
		lines = lines[1:]
		if len(result) > 250 {
			break
		}
	}

	// Limit number of characters (not bytes). ../rfc/8970:200
	// To 256 characters. ../rfc/8970:211
	var o, n int
	for o = range result {
		n++
		if n > 256 {
			result = result[:o]
			break
		}
	}

	return result, scanner.Err()
}

// Any text inside these html elements (recursively) is ignored.
var ignoreAtoms = atomMap(
	atom.Dialog,
	atom.Head,
	atom.Map,
	atom.Math,
	atom.Script,
	atom.Style,
	atom.Svg,
	atom.Template,
)

// Inline elements don't force newlines at beginning & end of text in this element.
// https://developer.mozilla.org/en-US/docs/Web/HTML/Element#inline_text_semantics
var inlineAtoms = atomMap(
	atom.A,
	atom.Abbr,
	atom.B,
	atom.Bdi,
	atom.Bdo,
	atom.Cite,
	atom.Code,
	atom.Data,
	atom.Dfn,
	atom.Em,
	atom.I,
	atom.Kbd,
	atom.Mark,
	atom.Q,
	atom.Rp,
	atom.Rt,
	atom.Ruby,
	atom.S,
	atom.Samp,
	atom.Small,
	atom.Span,
	atom.Strong,
	atom.Sub,
	atom.Sup,
	atom.Time,
	atom.U,
	atom.Var,
	atom.Wbr,

	atom.Del,
	atom.Ins,

	// We treat these specially, inserting a space after them instead of a newline.
	atom.Td,
	atom.Th,
)

func atomMap(l ...atom.Atom) map[atom.Atom]bool {
	m := map[atom.Atom]bool{}
	for _, a := range l {
		m[a] = true
	}
	return m
}

var regexpSpace = regexp.MustCompile(`[ \t]+`)                                                    // Replaced with single space.
var regexpNewline = regexp.MustCompile(`\n\n\n+`)                                                 // Replaced with single newline.
var regexpZeroWidth = regexp.MustCompile("[\u00a0\u200b\u200c\u200d][\u00a0\u200b\u200c\u200d]+") // Removed, combinations don't make sense, generated.

func previewHTML(r io.Reader) (string, error) {
	// Stack/state, based on elements.
	var ignores []bool
	var inlines []bool

	var text string // Collecting text.
	var err error   // Set when walking DOM.
	var quoteLevel int

	// We'll walk the DOM nodes, keeping track of whether we are ignoring text, and
	// whether we are in an inline or block element, and building up the text. We stop
	// when we have enough data, returning false in that case.
	var walk func(n *html.Node) bool
	walk = func(n *html.Node) bool {
		switch n.Type {
		case html.ErrorNode:
			err = fmt.Errorf("unexpected error node")
			return false

		case html.ElementNode:
			ignores = append(ignores, ignoreAtoms[n.DataAtom])
			inline := inlineAtoms[n.DataAtom]
			inlines = append(inlines, inline)
			if n.DataAtom == atom.Blockquote {
				quoteLevel++
			}
			defer func() {
				if n.DataAtom == atom.Blockquote {
					quoteLevel--
				}
				if !inline && !strings.HasSuffix(text, "\n\n") {
					text += "\n"
				} else if (n.DataAtom == atom.Td || n.DataAtom == atom.Th) && !strings.HasSuffix(text, " ") {
					text += " "
				}

				ignores = ignores[:len(ignores)-1]
				inlines = inlines[:len(inlines)-1]
			}()

		case html.TextNode:
			if slices.Contains(ignores, true) {
				return true
			}
			// Collapse all kinds of weird whitespace-like characters into a space, except for newline and ignoring carriage return.
			var s string
			for _, c := range n.Data {
				if c == '\r' {
					continue
				} else if c == '\t' {
					s += " "
				} else {
					s += string(c)
				}
			}
			s = regexpSpace.ReplaceAllString(s, " ")
			s = regexpNewline.ReplaceAllString(s, "\n")
			s = regexpZeroWidth.ReplaceAllString(s, "")

			inline := len(inlines) > 0 && inlines[len(inlines)-1]
			ts := strings.TrimSpace(s)
			if !inline && ts == "" {
				break
			}
			if ts != "" || !strings.HasSuffix(s, " ") && !strings.HasSuffix(s, "\n") {
				if quoteLevel > 0 {
					q := strings.Repeat("> ", quoteLevel)
					var sb strings.Builder
					for s != "" {
						o := strings.IndexByte(s, '\n')
						if o < 0 {
							o = len(s)
						} else {
							o++
						}
						sb.WriteString(q)
						sb.WriteString(s[:o])
						s = s[o:]
					}
					s = sb.String()
				}
				text += s
			}
			// We need to generate at most 256 characters of preview. The text we're gathering
			// will be cleaned up, with quoting removed, so we'll end up with less. Hopefully,
			// 4k bytes is enough to read.
			if len(text) >= 4*1024 {
				return false
			}
		}
		// Ignored: DocumentNode, CommentNode, DoctypeNode, RawNode

		for cn := range n.ChildNodes() {
			if !walk(cn) {
				break
			}
		}

		return true
	}

	node, err := html.Parse(r)
	if err != nil {
		return "", fmt.Errorf("parsing html: %v", err)
	}

	// Build text.
	walk(node)

	text = strings.TrimSpace(text)
	text = regexpSpace.ReplaceAllString(text, " ")
	return text, err
}
