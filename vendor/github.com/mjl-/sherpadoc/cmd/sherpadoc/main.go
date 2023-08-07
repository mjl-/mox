/*
Sherpadoc parses Go code and outputs sherpa documentation in JSON.

This documentation is provided to the sherpa HTTP handler to serve
as documentation through the _docs function.

Example:

	sherpadoc Awesome >awesome.json

Sherpadoc parses Go code, finds a struct named "Awesome", and gathers
documentation:

Comments above the struct are used as section documentation.  Fields
in section structs must are treated as subsections, and can in turn
contain subsections. These subsections and their methods are also
exported and documented in the sherpa API. Add a struct tag "sherpa"
to override the name of the subsection, for example `sherpa:"Another
Awesome API"`.

Comments above method names are function documentation. A synopsis
is automatically generated.

Types used as parameters or return values are added to the section
documentation where they are used. The comments above the type are
used, as well as the comments for each field in a struct.  The
documented field names know about the "json" struct field tags.

More eloborate example:

	sherpadoc
		-title 'Awesome API by mjl' \
		-replace 'pkg.Type string,example.com/some/pkg.SomeType [] string' \
		path/to/awesome/code Awesome \
		>awesome.json

Most common Go code patterns for API functions have been implemented
in sherpadoc, but you may run into missing support.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mjl-/sherpadoc"

	"golang.org/x/mod/modfile"
)

var (
	packagePath         = flag.String("package-path", ".", "of source code to parse")
	replace             = flag.String("replace", "", "comma-separated list of type replacements, e.g. \"somepkg.SomeType string\"")
	title               = flag.String("title", "", "title of the API, default is the name of the type of the main API")
	adjustFunctionNames = flag.String("adjust-function-names", "", `by default, the first character of function names is turned into lower case; with "lowerWord" the first string of upper case characters is lower cased, with "none" the name is left as is`)
)

// If there is a "vendor" directory, we'll load packages from there (instead of
// through (slower) packages.Load), and we need to know the module name to resolve
// imports to paths in vendor.
var (
	gomodFile *modfile.File
	gomodDir  string
)

type field struct {
	Name      string
	Typewords []string
	Doc       string
	Fields    []*field
}

func (f field) TypeString() string {
	t := []string{}
	for _, e := range f.Typewords {
		if e == "nullable" {
			e = "*"
		}
		t = append(t, e)
	}
	return strings.Join(t, "")
}

type typeKind int

const (
	typeStruct typeKind = iota
	typeInts
	typeStrings
	typeBytes
)

// NamedType represents the type of a parameter or return value.
type namedType struct {
	Name   string
	Text   string
	Kind   typeKind
	Fields []*field // For kind is typeStruct.
	// For kind is typeInts
	IntValues []struct {
		Name  string
		Value int64
		Docs  string
	}
	// For kind is typeStrings
	StringValues []struct {
		Name  string
		Value string
		Docs  string
	}
}

type function struct {
	Name    string
	Text    string
	Params  []sherpadoc.Arg
	Returns []sherpadoc.Arg
}

// Section is an API section with docs, functions and subsections.
// Types are gathered per section, and moved up the section tree to the first common ancestor, so types are only documented once.
type section struct {
	TypeName  string // Name of the type for this section.
	Name      string // Name of the section. Either same as TypeName, or overridden with a "sherpa" struct tag.
	Text      string
	Types     []*namedType
	Typeset   map[string]struct{}
	Functions []*function
	Sections  []*section
}

func check(err error, action string) {
	if err != nil {
		log.Fatalf("%s: %s", action, err)
	}
}

func usage() {
	log.Println("usage: sherpadoc [flags] section")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		usage()
	}

	// If vendor exists, we load packages from it.
	for dir, _ := os.Getwd(); dir != "" && dir != "/"; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(p); err != nil && os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Printf("searching for go.mod: %v", err)
			break
		}

		if _, err := os.Stat(filepath.Join(dir, "vendor")); err != nil {
			break
		}

		if gomod, err := os.ReadFile(p); err != nil {
			log.Fatalf("reading go.mod: %s", err)
		} else if mf, err := modfile.ParseLax("go.mod", gomod, nil); err != nil {
			log.Fatalf("parsing go.mod: %s", err)
		} else {
			gomodFile = mf
			gomodDir = dir
		}
	}

	section := parseDoc(args[0], *packagePath)
	if *title != "" {
		section.Name = *title
	}

	moveTypesUp(section)

	doc := sherpaSection(section)
	doc.SherpaVersion = 0
	doc.SherpadocVersion = sherpadoc.SherpadocVersion

	err := sherpadoc.Check(doc)
	check(err, "checking sherpadoc output before writing")

	writeJSON(doc)
}

func writeJSON(v interface{}) {
	buf, err := json.MarshalIndent(v, "", "\t")
	check(err, "marshal to json")
	_, err = os.Stdout.Write(buf)
	check(err, "writing json to stdout")
	_, err = fmt.Println()
	check(err, "write to stdout")
}

type typeCount struct {
	t     *namedType
	count int
}

// Move types used in multiple sections up to their common ancestor.
func moveTypesUp(sec *section) {
	// First, the process for each child.
	for _, s := range sec.Sections {
		moveTypesUp(s)
	}

	// Count how often a type is used from here downwards.
	// If more than once, move the type up to here.
	counts := map[string]*typeCount{}
	countTypes(counts, sec)
	for _, tc := range counts {
		if tc.count <= 1 {
			continue
		}
		for _, sub := range sec.Sections {
			removeType(sub, tc.t)
		}
		if !hasType(sec, tc.t) {
			sec.Types = append(sec.Types, tc.t)
		}
	}
}

func countTypes(counts map[string]*typeCount, sec *section) {
	for _, t := range sec.Types {
		_, ok := counts[t.Name]
		if !ok {
			counts[t.Name] = &typeCount{t, 0}
		}
		counts[t.Name].count++
	}
	for _, subsec := range sec.Sections {
		countTypes(counts, subsec)
	}
}

func removeType(sec *section, t *namedType) {
	types := make([]*namedType, 0, len(sec.Types))
	for _, tt := range sec.Types {
		if tt.Name != t.Name {
			types = append(types, tt)
		}
	}
	sec.Types = types
	for _, sub := range sec.Sections {
		removeType(sub, t)
	}
}

func hasType(sec *section, t *namedType) bool {
	for _, tt := range sec.Types {
		if tt.Name == t.Name {
			return true
		}
	}
	return false
}
