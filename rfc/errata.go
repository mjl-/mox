//go:build errata

package main

// Convert eid html file, e.g. https://www.rfc-editor.org/errata/eid3192 to text with leading blank line for references.
// See Makefile, run with "go run errata.go < eid.html >eid.txt"
// I could not find a source for the text version of errata.

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"golang.org/x/net/html"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		log.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func main() {
	log.SetFlags(0)
	doc, err := html.Parse(os.Stdin)
	xcheckf(err, "parsing html")
	out := bufio.NewWriter(os.Stdout)
	_, err = out.WriteString("\n") // First line for references.
	xcheckf(err, "write")

	// We will visit the html nodes. We skip <form>'s. We turn on text
	// output when we encounter an h4, and we stop again when we see a div
	// or form. This works at the moment, but may break in the future.
	output := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "form" {
				return
			}
			if !output && n.Data == "h4" {
				output = true
			} else if output && (n.Data == "div" || n.Data == "form") {
				output = false
			}
		}
		if output && n.Type == html.TextNode {
			_, err := out.WriteString(n.Data)
			xcheckf(err, "write")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	err = out.Flush()
	xcheckf(err, "flush")
}
