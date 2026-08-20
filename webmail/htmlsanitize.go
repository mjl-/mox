package webmail

import (
	"strings"

	"golang.org/x/net/html"
)

// Balanced allowlist of elements kept as-is (their attributes are still
// filtered). Elements not listed here and not in dropTags are "unwrapped":
// removed while keeping their (sanitized) children. img is handled separately.
var allowTags = map[string]bool{
	"p": true, "br": true, "div": true, "span": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"ul": true, "ol": true, "li": true, "dl": true, "dt": true, "dd": true,
	"blockquote": true, "pre": true, "code": true, "hr": true,
	"a": true, "b": true, "strong": true, "i": true, "em": true,
	"u": true, "s": true, "strike": true, "sub": true, "sup": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true,
	"tr": true, "td": true, "th": true, "caption": true,
}

// Elements removed entirely, including their children.
var dropTags = map[string]bool{
	"script": true, "style": true, "head": true, "title": true, "meta": true,
	"link": true, "base": true, "iframe": true, "object": true, "embed": true,
	"applet": true, "form": true, "input": true, "button": true, "select": true,
	"option": true, "textarea": true, "noscript": true, "svg": true, "math": true,
	"frame": true, "frameset": true, "template": true, "dialog": true,
}

// Safe CSS properties kept in a "style" attribute when sanitizing outgoing HTML
// (so user-chosen font/size/colour survive). Layout/positioning and anything
// that can load resources or script is not listed and thus dropped.
var safeStyleProps = map[string]bool{
	"color": true, "background-color": true,
	"font-family": true, "font-size": true, "font-weight": true,
	"font-style": true, "font-variant": true,
	"text-decoration": true, "text-align": true, "line-height": true,
}

// sanitizeHTML cleans s to the "Balanced" HTML subset: it keeps semantic
// structure, links (http/https/mailto only) and basic formatting, drops scripts,
// styles, classes, inline styles, event handlers and tracking, and replaces
// images with a "[image]" placeholder. The returned string is an HTML fragment
// (no <html>/<head>/<body> wrapper), suitable as a reply/forward quote.
func sanitizeHTML(s string) (string, error) {
	return sanitizeHTMLOpts(s, false)
}

// sanitizeOutgoingHTML is like sanitizeHTML but keeps a safe subset of inline
// "style" properties (see safeStyleProps), so font/size/colour chosen by the
// user in the compose editor are preserved in the sent message. Used for the
// HTML the user composed; the client is still not trusted.
func sanitizeOutgoingHTML(s string) (string, error) {
	return sanitizeHTMLOpts(s, true)
}

func sanitizeHTMLOpts(s string, allowStyles bool) (string, error) {
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		return "", err
	}
	body := findBodyNode(doc)
	if body == nil {
		return "", nil
	}
	var sb strings.Builder
	for c := body.FirstChild; c != nil; c = c.NextSibling {
		for _, sn := range sanitizeOneNode(c, allowStyles) {
			if err := html.Render(&sb, sn); err != nil {
				return "", err
			}
		}
	}
	return sb.String(), nil
}

func findBodyNode(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "body" {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if b := findBodyNode(c); b != nil {
			return b
		}
	}
	return nil
}

// sanitizeOneNode returns freshly-built, detached nodes representing the
// sanitized form of n (zero nodes if dropped, multiple if unwrapped).
func sanitizeOneNode(n *html.Node, allowStyles bool) []*html.Node {
	switch n.Type {
	case html.TextNode:
		return []*html.Node{{Type: html.TextNode, Data: n.Data}}
	case html.ElementNode:
		if dropTags[n.Data] {
			return nil
		}
		if n.Data == "img" {
			// Phase 1: no inline/external images, replace with placeholder.
			return []*html.Node{{Type: html.TextNode, Data: "[image]"}}
		}
		var kids []*html.Node
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			kids = append(kids, sanitizeOneNode(c, allowStyles)...)
		}
		if !allowTags[n.Data] {
			// Unwrap unknown but non-dangerous elements (e.g. font, center).
			return kids
		}
		el := &html.Node{Type: html.ElementNode, Data: n.Data, Attr: filterAttrs(n, allowStyles)}
		// Quoted replies/forwards must look like a quote in the recipient's client,
		// which does not have our stylesheet. So give outgoing blockquotes an inline
		// style (only when emitting outgoing HTML, not when cleaning a received quote).
		if allowStyles && n.Data == "blockquote" && !hasAttr(el.Attr, "style") {
			el.Attr = append(el.Attr, html.Attribute{Key: "style", Val: blockquoteStyle})
		}
		for _, c := range kids {
			el.AppendChild(c)
		}
		return []*html.Node{el}
	default:
		// CommentNode, DoctypeNode, etc. are dropped.
		return nil
	}
}

func filterAttrs(n *html.Node, allowStyles bool) []html.Attribute {
	var out []html.Attribute
	for _, a := range n.Attr {
		if a.Namespace != "" {
			continue
		}
		switch {
		case n.Data == "a" && a.Key == "href":
			if okURLScheme(a.Val) {
				out = append(out, html.Attribute{Key: "href", Val: a.Val})
			}
		case a.Key == "title":
			out = append(out, html.Attribute{Key: "title", Val: a.Val})
		case allowStyles && a.Key == "style":
			if v := filterStyle(a.Val); v != "" {
				out = append(out, html.Attribute{Key: "style", Val: v})
			}
		}
	}
	return out
}

// filterStyle keeps only safe CSS declarations (safeStyleProps with safe values)
// from a style attribute value, returning the rebuilt declaration string.
func filterStyle(val string) string {
	var keep []string
	for _, decl := range strings.Split(val, ";") {
		prop, value, ok := strings.Cut(decl, ":")
		if !ok {
			continue
		}
		prop = strings.ToLower(strings.TrimSpace(prop))
		value = strings.TrimSpace(value)
		if safeStyleProps[prop] && okStyleValue(value) {
			keep = append(keep, prop+": "+value)
		}
	}
	return strings.Join(keep, "; ")
}

// okStyleValue rejects CSS values that could load resources or break out of the
// attribute/property.
func okStyleValue(v string) bool {
	if v == "" {
		return false
	}
	low := strings.ToLower(v)
	for _, bad := range []string{"url(", "expression", "javascript:", "/*", "*/", "<", ">", "{", "}", "\\", "@"} {
		if strings.Contains(low, bad) {
			return false
		}
	}
	return true
}

func okURLScheme(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "mailto:")
}

// blockquoteStyle is the inline style added to outgoing blockquotes so quotes
// render with the familiar left bar in recipients' mail clients.
const blockquoteStyle = "margin: 0 0 0 0.8ex; border-left: 2px solid #ccc; padding-left: 1ex"

func hasAttr(attrs []html.Attribute, key string) bool {
	for _, a := range attrs {
		if a.Key == key {
			return true
		}
	}
	return false
}
