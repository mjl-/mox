//go:build link

package main

// Read source files and RFC and errata files, and cross-link them.

// todo: also cross-reference typescript and possibly other files. switch from go parser to just reading the source as text.

import (
	"bytes"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func usage() {
	log.Println("usage: link ../*.go ../*/*.go")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}

	type ref struct {
		srcpath   string
		srclineno int
		dstpath   string
		dstlineno int
		dstisrfc  bool
		dstrfc    string // e.g. "5322" or "6376-eid4810"
		comment   string // e.g. "todo" or "todo spec"
	}

	// RFC-file to RFC-line to references to list of file+line (possibly RFCs).
	rfcLineSources := map[string]map[int][]ref{}

	// Source-file to source-line to references of RFCs.
	sourceLineRFCs := map[string]map[int][]ref{}

	re := regexp.MustCompile(`((../)*)rfc/([0-9]{4,5})(-eid([1-9][0-9]*))?(:([1-9][0-9]*))?`)

	addRef := func(m map[string]map[int][]ref, rfc string, lineno int, r ref) {
		lineRefs := m[rfc]
		if lineRefs == nil {
			lineRefs = map[int][]ref{}
			m[rfc] = lineRefs
		}
		lineRefs[lineno] = append(lineRefs[lineno], r)
	}

	// Parse all .go files on the cli, assumed to be relative to current dir.
	fset := token.NewFileSet()
	for _, arg := range args {
		f, err := parser.ParseFile(fset, arg, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			log.Fatalf("parse file %q: %s", arg, err)
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				lines := strings.Split(c.Text, "\n")
				for i, line := range lines {
					matches := re.FindAllStringSubmatch(line, -1)
					if len(matches) == 0 {
						continue
					}

					var comment string
					if strings.HasPrefix(line, "// todo") {
						s, _, have := strings.Cut(strings.TrimPrefix(line, "// "), ":")
						if have {
							comment = s
						} else {
							comment = "todo"
						}
					}

					srcpath := arg
					srclineno := fset.Position(c.Pos()).Line + i
					dir := filepath.Dir(srcpath)
					for _, m := range matches {
						pre := m[1]
						rfc := m[3]
						eid := m[5]
						lineStr := m[7]
						if eid != "" && lineStr != "" {
							log.Fatalf("%s:%d: cannot reference both errata (eid %q) to specified line number", srcpath, srclineno, eid)
						}
						var dstlineno int
						if lineStr != "" {
							v, err := strconv.ParseInt(lineStr, 10, 32)
							if err != nil {
								log.Fatalf("%s:%d: bad linenumber %q: %v", srcpath, srclineno, lineStr, err)
							}
							dstlineno = int(v)
						}
						if dstlineno <= 0 {
							dstlineno = 1
						}
						if eid != "" {
							rfc += "-eid" + eid
						}
						dstpath := filepath.Join(dir, pre+"rfc", rfc)
						if _, err := os.Stat(dstpath); err != nil {
							log.Fatalf("%s:%d: references %s: %v", srcpath, srclineno, dstpath, err)
						}
						r := ref{srcpath, srclineno, dstpath, dstlineno, true, rfc, comment}
						addRef(sourceLineRFCs, r.srcpath, r.srclineno, r)
						addRef(rfcLineSources, r.dstrfc, r.dstlineno, ref{r.dstrfc, r.dstlineno, r.srcpath, r.srclineno, false, "", comment})
					}
				}
			}
		}
	}

	files, err := os.ReadDir(".")
	if err != nil {
		log.Fatalf("readdir: %v", err)
	}
	for _, de := range files {
		name := de.Name()
		isrfc := isRFC(name)
		iserrata := isErrata(name)
		if !isrfc && !iserrata {
			continue
		}
		oldBuf, err := os.ReadFile(name)
		if err != nil {
			log.Fatalf("readdir: %v", err)
		}
		old := string(oldBuf)
		b := &bytes.Buffer{}
		lineRefs := rfcLineSources[name]
		lines := strings.Split(old, "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		for i, line := range lines {
			if !(iserrata && i > 0) && len(line) > 80 {
				line = strings.TrimRight(line[:80], " ")
			}
			refs := lineRefs[i+1]
			if len(refs) > 0 {
				line = fmt.Sprintf("%-80s", line)

				// Lookup source files for rfc:line, so we can cross-link the rfcs.
				done := map[string]bool{}
				for _, r := range refs {
					for _, xr := range sourceLineRFCs[r.dstpath][r.dstlineno] {
						sref := fmt.Sprintf(" %s:%d", xr.dstrfc, xr.dstlineno)
						if xr.dstrfc == name && xr.dstlineno == i+1 || done[sref] {
							continue
						}
						line += sref
						done[sref] = true
					}
				}

				// Add link from rfc to source code.
				for _, r := range refs {
					comment := r.comment
					if comment != "" {
						comment += ": "
					}
					line += fmt.Sprintf(" %s%s:%d", comment, r.dstpath, r.dstlineno)
				}
			}
			line += "\n"
			b.WriteString(line)
		}
		newBuf := b.Bytes()
		if !bytes.Equal(oldBuf, newBuf) {
			if err := os.WriteFile(name, newBuf, 0660); err != nil {
				log.Printf("writefile %q: %s", name, err)
			}
			log.Print(name)
		}
	}
}

func isRFC(name string) bool {
	if len(name) < 4 || len(name) > 5 {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isErrata(name string) bool {
	t := strings.Split(name, "-")
	return len(t) == 2 && isRFC(t[0]) && strings.HasPrefix(t[1], "eid")
}
