package main

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"

	"github.com/mjl-/sherpadoc"
)

// ParsedPackage possibly includes some of its imports because the package that contains the section references it.
type parsedPackage struct {
	Fset    *token.FileSet // Used with a token.Pos to get offending locations.
	Path    string         // Of import, used for keeping duplicate type names from different packages unique.
	Pkg     *ast.Package   // Needed for its files: we need a file to find the package path and identifier used to reference other types.
	Docpkg  *doc.Package
	Imports map[string]*parsedPackage // Package/import path to parsed packages.
}

type typewords []string

func (pp *parsedPackage) lookupType(name string) *doc.Type {
	for _, t := range pp.Docpkg.Types {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// Like log.Fatalf, but prefixes error message with offending file position (if known).
// pp is the package where the position tok belongs to.
func logFatalLinef(pp *parsedPackage, tok token.Pos, format string, args ...interface{}) {
	if !tok.IsValid() {
		log.Fatalf(format, args...)
	}
	msg := fmt.Sprintf(format, args...)
	log.Fatalf("%s: %s", pp.Fset.Position(tok).String(), msg)
}

// Documentation for a single field, with text above the field, and
// on the right of the field combined.
func fieldDoc(f *ast.Field) string {
	s := ""
	if f.Doc != nil {
		s += strings.Replace(strings.TrimSpace(f.Doc.Text()), "\n", " ", -1)
	}
	if f.Comment != nil {
		if s != "" {
			s += "; "
		}
		s += strings.TrimSpace(f.Comment.Text())
	}
	return s
}

// Parse string literal. Errors are fatal.
func parseStringLiteral(s string) string {
	r, err := strconv.Unquote(s)
	check(err, "parsing string literal")
	return r
}

func jsonName(tag string, name string) string {
	s := reflect.StructTag(tag).Get("json")
	if s == "" || strings.HasPrefix(s, ",") {
		return name
	} else if s == "-" {
		return ""
	} else {
		return strings.Split(s, ",")[0]
	}
}

// Return the names (can be none) for a field. Takes exportedness
// and JSON tag annotation into account.
func nameList(names []*ast.Ident, tag *ast.BasicLit) []string {
	if names == nil {
		return nil
	}
	l := []string{}
	for _, name := range names {
		if ast.IsExported(name.Name) {
			l = append(l, name.Name)
		}
	}
	if len(l) == 1 && tag != nil {
		name := jsonName(parseStringLiteral(tag.Value), l[0])
		if name != "" {
			return []string{name}
		}
		return nil
	}
	return l
}

// Parses a top-level sherpadoc section.
func parseDoc(apiName, packagePath string) *section {
	fset := token.NewFileSet()
	pkgs, firstErr := parser.ParseDir(fset, packagePath, nil, parser.ParseComments)
	check(firstErr, "parsing code")
	for _, pkg := range pkgs {
		docpkg := doc.New(pkg, "", doc.AllDecls)

		for _, t := range docpkg.Types {
			if t.Name == apiName {
				par := &parsedPackage{
					Fset:    fset,
					Path:    packagePath,
					Pkg:     pkg,
					Docpkg:  docpkg,
					Imports: make(map[string]*parsedPackage),
				}
				return parseSection(t, par)
			}
		}
	}
	log.Fatalf("type %q not found", apiName)
	return nil
}

// Parse a section and its optional subsections, recursively.
// t is the type of the struct with the sherpa methods to be parsed.
func parseSection(t *doc.Type, pp *parsedPackage) *section {
	sec := &section{
		t.Name,
		t.Name,
		strings.TrimSpace(t.Doc),
		nil,
		map[string]struct{}{},
		nil,
		nil,
	}

	// make list of methods to parse, sorted by position in file name.
	methods := make([]*doc.Func, len(t.Methods))
	copy(methods, t.Methods)
	sort.Slice(methods, func(i, j int) bool {
		return methods[i].Decl.Name.NamePos < methods[j].Decl.Name.NamePos
	})

	for _, fn := range methods {
		parseMethod(sec, fn, pp)
	}

	// parse subsections
	ts := t.Decl.Specs[0].(*ast.TypeSpec)
	expr := ts.Type
	st := expr.(*ast.StructType)
	for _, f := range st.Fields.List {
		ident, ok := f.Type.(*ast.Ident)
		if !ok || !ast.IsExported(ident.Name) {
			continue
		}
		name := ident.Name
		if f.Tag != nil {
			name = reflect.StructTag(parseStringLiteral(f.Tag.Value)).Get("sherpa")
		}
		subt := pp.lookupType(ident.Name)
		if subt == nil {
			logFatalLinef(pp, ident.Pos(), "subsection %q not found", ident.Name)
		}
		subsec := parseSection(subt, pp)
		subsec.Name = name
		sec.Sections = append(sec.Sections, subsec)
	}
	return sec
}

// Ensure type "t" (used in a field or argument) defined in package pp is parsed
// and added to the section.
func ensureNamedType(t *doc.Type, sec *section, pp *parsedPackage) {
	typePath := pp.Path + "." + t.Name
	if _, have := sec.Typeset[typePath]; have {
		return
	}

	tt := &namedType{
		Name: t.Name,
		Text: strings.TrimSpace(t.Doc),
	}
	// add it early, so self-referencing types can't cause a loop
	sec.Types = append(sec.Types, tt)
	sec.Typeset[typePath] = struct{}{}

	ts := t.Decl.Specs[0].(*ast.TypeSpec)
	if ts.Assign.IsValid() {
		logFatalLinef(pp, t.Decl.TokPos, "type aliases not yet supported")
	}

	var gatherFields func(e ast.Expr, typeName string, xpp *parsedPackage)
	var gatherStructFields func(nt *ast.StructType, typeName string, xpp *parsedPackage)

	gatherFields = func(e ast.Expr, typeName string, xpp *parsedPackage) {
		switch xt := e.(type) {
		case *ast.Ident:
			// Bare type name.
			tt := xpp.lookupType(xt.Name)
			if tt == nil {
				log.Fatalf("could not find type %q used in type %q in package %q", xt.Name, typeName, xpp.Path)
			}
			tts := tt.Decl.Specs[0].(*ast.TypeSpec)
			if ts.Assign.IsValid() {
				logFatalLinef(xpp, tt.Decl.TokPos, "type aliases not yet supported")
			}
			tst, ok := tts.Type.(*ast.StructType)
			if !ok {
				logFatalLinef(xpp, tt.Decl.TokPos, "unexpected field type %T", tts.Type)
			}
			gatherStructFields(tst, tt.Name, xpp)
		case *ast.StarExpr:
			// Field with "*", handle as if without *.
			gatherFields(xt.X, typeName, xpp)
		case *ast.SelectorExpr:
			// With package prefix, lookup the type in the package and gather its fields.
			dt, nxpp := parseFieldSelector(useSrc{xpp, typeName}, xt)
			tts := dt.Decl.Specs[0].(*ast.TypeSpec)
			if ts.Assign.IsValid() {
				logFatalLinef(nxpp, dt.Decl.TokPos, "type aliases not yet supported")
			}
			tst, ok := tts.Type.(*ast.StructType)
			if !ok {
				logFatalLinef(nxpp, dt.Decl.TokPos, "unexpected field type %T", tts.Type)
			}
			gatherStructFields(tst, dt.Name, nxpp)
		default:
			logFatalLinef(xpp, t.Decl.TokPos, "unsupported field with type %T", e)
		}
	}

	gatherStructFields = func(nt *ast.StructType, typeName string, xpp *parsedPackage) {
		for _, f := range nt.Fields.List {
			if len(f.Names) == 0 {
				// Embedded field. Treat its fields as if they were included.
				gatherFields(f.Type, typeName, xpp)
				continue
			}

			// Check if we need this type. Otherwise we may trip
			// over an unhandled type that we wouldn't include in
			// the output (eg due to a struct tag).
			names := nameList(f.Names, f.Tag)
			need := false
			for _, name := range names {
				if name != "" {
					need = true
					break
				}
			}
			if !need {
				continue
			}

			ff := &field{
				"",
				nil,
				fieldDoc(f),
				[]*field{},
			}
			ff.Typewords = gatherFieldType(t.Name, ff, f.Type, f.Tag, sec, xpp)
			for _, name := range nameList(f.Names, f.Tag) {
				nf := &field{}
				*nf = *ff
				nf.Name = name
				tt.Fields = append(tt.Fields, nf)
			}
		}
	}

	switch nt := ts.Type.(type) {
	case *ast.StructType:
		tt.Kind = typeStruct
		gatherStructFields(nt, t.Name, pp)

	case *ast.ArrayType:
		if ident, ok := nt.Elt.(*ast.Ident); ok && ident.Name == "byte" {
			tt.Kind = typeBytes
		} else {
			logFatalLinef(pp, t.Decl.TokPos, "named type with unsupported element type %T", ts.Type)
		}

	case *ast.Ident:
		if strings.HasSuffix(typePath, "sherpa.Int64s") || strings.HasSuffix(typePath, "sherpa.Uint64s") {
			return
		}

		tt.Text = t.Doc + ts.Comment.Text()
		switch nt.Name {
		case "byte", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "int", "uint":
			tt.Kind = typeInts
		case "string":
			tt.Kind = typeStrings
		default:
			logFatalLinef(pp, t.Decl.TokPos, "unrecognized type identifier %#v", nt.Name)
		}

		for _, c := range t.Consts {
			for _, spec := range c.Decl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					logFatalLinef(pp, spec.Pos(), "unsupported non-ast.ValueSpec constant %#v", spec)
				}
				if len(vs.Names) != 1 {
					logFatalLinef(pp, vs.Pos(), "unsupported multiple .Names in %#v", vs)
				}
				name := vs.Names[0].Name
				if len(vs.Values) != 1 {
					logFatalLinef(pp, vs.Pos(), "unsupported multiple .Values in %#v", vs)
				}
				lit, ok := vs.Values[0].(*ast.BasicLit)
				if !ok {
					logFatalLinef(pp, vs.Pos(), "unsupported non-ast.BasicLit first .Values %#v", vs)
				}

				comment := vs.Doc.Text() + vs.Comment.Text()
				switch lit.Kind {
				case token.INT:
					if tt.Kind != typeInts {
						logFatalLinef(pp, lit.Pos(), "int value for for non-int-enum %q", t.Name)
					}
					// Given JSON/JS lack of integers, restrict to what it can represent in its float.
					v, err := strconv.ParseInt(lit.Value, 10, 52)
					check(err, "parse int literal")
					iv := struct {
						Name  string
						Value int64
						Docs  string
					}{name, v, strings.TrimSpace(comment)}
					tt.IntValues = append(tt.IntValues, iv)
				case token.STRING:
					if tt.Kind != typeStrings {
						logFatalLinef(pp, lit.Pos(), "string for non-string-enum %q", t.Name)
					}
					v, err := strconv.Unquote(lit.Value)
					check(err, "unquote literal")
					sv := struct {
						Name  string
						Value string
						Docs  string
					}{name, v, strings.TrimSpace(comment)}
					tt.StringValues = append(tt.StringValues, sv)
				default:
					logFatalLinef(pp, lit.Pos(), "unexpected literal kind %#v", lit.Kind)
				}
			}
		}
	default:
		logFatalLinef(pp, t.Decl.TokPos, "unsupported field/param/return type %T", ts.Type)
	}
}

func hasOmitEmpty(tag *ast.BasicLit) bool {
	return hasJSONTagValue(tag, "omitempty")
}

// isCommaString returns whether the tag (may be nil) contains a "json:,string" directive.
func isCommaString(tag *ast.BasicLit) bool {
	return hasJSONTagValue(tag, "string")
}

func hasJSONTagValue(tag *ast.BasicLit, v string) bool {
	if tag == nil {
		return false
	}
	st := reflect.StructTag(parseStringLiteral(tag.Value))
	s, ok := st.Lookup("json")
	if !ok || s == "-" {
		return false
	}
	t := strings.Split(s, ",")
	for _, e := range t[1:] {
		if e == v {
			return true
		}
	}
	return false
}

func gatherFieldType(typeName string, f *field, e ast.Expr, fieldTag *ast.BasicLit, sec *section, pp *parsedPackage) typewords {
	nullablePrefix := typewords{}
	if hasOmitEmpty(fieldTag) {
		nullablePrefix = typewords{"nullable"}
	}

	name := checkReplacedType(useSrc{pp, typeName}, e)
	if name != nil {
		if name[0] != "nullable" {
			return append(nullablePrefix, name...)
		}
		return name
	}

	switch t := e.(type) {
	case *ast.Ident:
		tt := pp.lookupType(t.Name)
		if tt != nil {
			ensureNamedType(tt, sec, pp)
			return []string{t.Name}
		}
		commaString := isCommaString(fieldTag)
		name := t.Name
		switch name {
		case "byte":
			name = "uint8"
		case "bool", "int8", "uint8", "int16", "uint16", "int32", "uint32", "float32", "float64", "string", "any":
		case "int64", "uint64":
			if commaString {
				name += "s"
			}
		case "int", "uint":
			name += "32"
		default:
			logFatalLinef(pp, t.Pos(), "unsupported field type %q used in type %q in package %q", name, typeName, pp.Path)
		}
		if commaString && name != "int64s" && name != "uint64s" {
			logFatalLinef(pp, t.Pos(), "unsupported tag `json:,\"string\"` for non-64bit int in %s.%s", typeName, f.Name)
		}
		return append(nullablePrefix, name)
	case *ast.ArrayType:
		return append(nullablePrefix, append([]string{"[]"}, gatherFieldType(typeName, f, t.Elt, nil, sec, pp)...)...)
	case *ast.MapType:
		_ = gatherFieldType(typeName, f, t.Key, nil, sec, pp)
		vt := gatherFieldType(typeName, f, t.Value, nil, sec, pp)
		return append(nullablePrefix, append([]string{"{}"}, vt...)...)
	case *ast.InterfaceType:
		// If we export an interface as an "any" type, we want to make sure it's intended.
		// Require the user to be explicit with an empty interface.
		if t.Methods != nil && len(t.Methods.List) > 0 {
			logFatalLinef(pp, t.Pos(), "unsupported non-empty interface param/return type %T", t)
		}
		return append(nullablePrefix, "any")
	case *ast.StarExpr:
		tw := gatherFieldType(typeName, f, t.X, fieldTag, sec, pp)
		if tw[0] != "nullable" {
			tw = append([]string{"nullable"}, tw...)
		}
		return tw
	case *ast.SelectorExpr:
		return append(nullablePrefix, parseSelector(t, typeName, sec, pp))
	}
	logFatalLinef(pp, e.Pos(), "unimplemented ast.Expr %#v for struct %q field %q in gatherFieldType", e, typeName, f.Name)
	return nil
}

func parseArgType(e ast.Expr, sec *section, pp *parsedPackage) typewords {
	name := checkReplacedType(useSrc{pp, sec.Name}, e)
	if name != nil {
		return name
	}

	switch t := e.(type) {
	case *ast.Ident:
		tt := pp.lookupType(t.Name)
		if tt != nil {
			ensureNamedType(tt, sec, pp)
			return []string{t.Name}
		}
		name := t.Name
		switch name {
		case "byte":
			name = "uint8"
		case "bool", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float32", "float64", "string", "any":
		case "int", "uint":
			name += "32"
		case "error":
			// allowed here, checked if in right location by caller
		default:
			logFatalLinef(pp, t.Pos(), "unsupported arg type %q", name)
		}
		return []string{name}
	case *ast.ArrayType:
		return append([]string{"[]"}, parseArgType(t.Elt, sec, pp)...)
	case *ast.Ellipsis:
		// Ellipsis parameters to a function must be passed as an array, so document it that way.
		return append([]string{"[]"}, parseArgType(t.Elt, sec, pp)...)
	case *ast.MapType:
		_ = parseArgType(t.Key, sec, pp)
		vt := parseArgType(t.Value, sec, pp)
		return append([]string{"{}"}, vt...)
	case *ast.InterfaceType:
		// If we export an interface as an "any" type, we want to make sure it's intended.
		// Require the user to be explicit with an empty interface.
		if t.Methods != nil && len(t.Methods.List) > 0 {
			logFatalLinef(pp, t.Pos(), "unsupported non-empty interface param/return type %T", t)
		}
		return []string{"any"}
	case *ast.StarExpr:
		return append([]string{"nullable"}, parseArgType(t.X, sec, pp)...)
	case *ast.SelectorExpr:
		return []string{parseSelector(t, sec.TypeName, sec, pp)}
	}
	logFatalLinef(pp, e.Pos(), "unimplemented ast.Expr %#v in parseArgType", e)
	return nil
}

// Parse the selector of a field, returning the type and the parsed package it exists in. This cannot be a builtin type.
func parseFieldSelector(u useSrc, t *ast.SelectorExpr) (*doc.Type, *parsedPackage) {
	packageIdent, ok := t.X.(*ast.Ident)
	if !ok {
		u.Fatalf(t.Pos(), "unexpected non-ident for SelectorExpr.X")
	}
	pkgName := packageIdent.Name
	typeName := t.Sel.Name

	importPath := u.lookupPackageImportPath(pkgName)
	if importPath == "" {
		u.Fatalf(t.Pos(), "cannot find source for type %q that references package %q (perhaps try -replace)", u, pkgName)
	}

	opp := u.Ppkg.ensurePackageParsed(importPath)
	tt := opp.lookupType(typeName)
	if tt == nil {
		u.Fatalf(t.Pos(), "could not find type %q in package %q", typeName, importPath)
	}
	return tt, opp
}

func parseSelector(t *ast.SelectorExpr, srcTypeName string, sec *section, pp *parsedPackage) string {
	packageIdent, ok := t.X.(*ast.Ident)
	if !ok {
		logFatalLinef(pp, t.Pos(), "unexpected non-ident for SelectorExpr.X")
	}
	pkgName := packageIdent.Name
	typeName := t.Sel.Name

	if pkgName == "time" && typeName == "Time" {
		return "timestamp"
	}
	if pkgName == "sherpa" {
		switch typeName {
		case "Int64s":
			return "int64s"
		case "Uint64s":
			return "uint64s"
		}
	}

	importPath := pp.lookupPackageImportPath(srcTypeName, pkgName)
	if importPath == "" {
		logFatalLinef(pp, t.Pos(), "cannot find source for %q (perhaps try -replace)", fmt.Sprintf("%s.%s", pkgName, typeName))
	}

	opp := pp.ensurePackageParsed(importPath)
	tt := opp.lookupType(typeName)
	if tt == nil {
		logFatalLinef(pp, t.Pos(), "could not find type %q in package %q", typeName, importPath)
	}
	ensureNamedType(tt, sec, opp)
	return typeName
}

type replacement struct {
	original string // a Go type, eg "pkg.Type" or "*pkg.Type"
	target   typewords
}

var _replacements []replacement

func typeReplacements() []replacement {
	if _replacements != nil {
		return _replacements
	}

	_replacements = []replacement{}
	for _, repl := range strings.Split(*replace, ",") {
		if repl == "" {
			continue
		}
		tokens := strings.Split(repl, " ")
		if len(tokens) < 2 {
			log.Fatalf("bad replacement %q, must have at least two tokens, space-separated", repl)
		}
		r := replacement{tokens[0], tokens[1:]}
		_replacements = append(_replacements, r)
	}
	return _replacements
}

// Use of a type Name from package Ppkg. Used to look up references from that
// location (the file where the type is defined, with its imports) for a given Go
// ast.
type useSrc struct {
	Ppkg *parsedPackage
	Name string
}

func (u useSrc) lookupPackageImportPath(pkgName string) string {
	return u.Ppkg.lookupPackageImportPath(u.Name, pkgName)
}

func (u useSrc) String() string {
	return fmt.Sprintf("%s.%s", u.Ppkg.Path, u.Name)
}

func (u useSrc) Fatalf(tok token.Pos, format string, args ...interface{}) {
	logFatalLinef(u.Ppkg, tok, format, args...)
}

// Return a go type name, eg "*time.Time".
// This function does not parse the types itself, because it would mean they could
// be added to the sherpadoc output even if they aren't otherwise used (due to
// replacement).
func goTypeName(u useSrc, e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.ArrayType:
		return "[]" + goTypeName(u, t.Elt)
	case *ast.Ellipsis:
		// Ellipsis parameters to a function must be passed as an array, so document it that way.
		return "[]" + goTypeName(u, t.Elt)
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", goTypeName(u, t.Key), goTypeName(u, t.Value))
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.StarExpr:
		return "*" + goTypeName(u, t.X)
	case *ast.SelectorExpr:
		packageIdent, ok := t.X.(*ast.Ident)
		if !ok {
			u.Fatalf(t.Pos(), "unexpected non-ident for SelectorExpr.X")
		}
		pkgName := packageIdent.Name
		typeName := t.Sel.Name

		importPath := u.lookupPackageImportPath(pkgName)
		if importPath != "" {
			return fmt.Sprintf("%s.%s", importPath, typeName)
		}
		return fmt.Sprintf("%s.%s", pkgName, typeName)
		// todo: give proper error message for *ast.StructType
	}
	u.Fatalf(e.Pos(), "unimplemented ast.Expr %#v in goTypeName", e)
	return ""
}

func checkReplacedType(u useSrc, e ast.Expr) typewords {
	repls := typeReplacements()
	if len(repls) == 0 {
		return nil
	}

	name := goTypeName(u, e)
	return replacementType(repls, name)
}

func replacementType(repls []replacement, name string) typewords {
	for _, repl := range repls {
		if repl.original == name {
			return repl.target
		}
	}
	return nil
}

// Ensures the package for importPath has been parsed at least once, and return it.
func (pp *parsedPackage) ensurePackageParsed(importPath string) *parsedPackage {
	r := pp.Imports[importPath]
	if r != nil {
		return r
	}

	var localPath string
	var astPkg *ast.Package
	var fset *token.FileSet

	// If dependencies are vendored, we load packages from vendor/. This is typically
	// faster than using package.Load (the fallback), which may spawn commands.
	// For me, while testing, for loading a simple package from the same module goes
	// from 50-100 ms to 1-5ms. Loading "net" from 200ms to 65ms.

	if gomodFile != nil {
		if importPath == gomodFile.Module.Mod.Path {
			localPath = gomodDir
		} else if strings.HasPrefix(importPath, gomodFile.Module.Mod.Path+"/") {
			localPath = filepath.Join(gomodDir, strings.TrimPrefix(importPath, gomodFile.Module.Mod.Path+"/"))
		} else {
			p := filepath.Join(gomodDir, "vendor", importPath)
			if _, err := os.Stat(p); err == nil {
				localPath = p
			} else {
				localPath = filepath.Join(runtime.GOROOT(), "src", importPath)
			}
		}

		fset = token.NewFileSet()
		astPkgs, err := parser.ParseDir(fset, localPath, nil, parser.ParseComments|parser.DeclarationErrors)
		check(err, "parsing go files from "+localPath)
		for name, pkg := range astPkgs {
			if strings.HasSuffix(name, "_test") {
				continue
			}
			if astPkg != nil {
				log.Fatalf("loading package %q: multiple packages found", importPath)
			}
			astPkg = pkg
		}
	} else {
		config := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles,
		}
		pkgs, err := packages.Load(config, importPath)
		check(err, "loading package")
		if len(pkgs) != 1 {
			log.Fatalf("loading package %q: got %d packages, expected 1", importPath, len(pkgs))
		}
		pkg := pkgs[0]
		if len(pkg.GoFiles) == 0 {
			log.Fatalf("loading package %q: no go files found", importPath)
		}

		fset = token.NewFileSet()
		localPath = filepath.Dir(pkg.GoFiles[0])
		astPkgs, err := parser.ParseDir(fset, localPath, nil, parser.ParseComments)
		check(err, "parsing go files from directory")
		var ok bool
		astPkg, ok = astPkgs[pkg.Name]
		if !ok {
			log.Fatalf("loading package %q: could not find astPkg for %q", importPath, pkg.Name)
		}
	}

	docpkg := doc.New(astPkg, "", doc.AllDecls|doc.PreserveAST)

	npp := &parsedPackage{
		Fset:    fset,
		Path:    localPath,
		Pkg:     astPkg,
		Docpkg:  docpkg,
		Imports: make(map[string]*parsedPackage),
	}
	pp.Imports[importPath] = npp
	return npp
}

// LookupPackageImportPath returns the import/package path for pkgName as used as
// used in the type named typeName.
func (pp *parsedPackage) lookupPackageImportPath(typeName, pkgName string) string {
	file := pp.lookupTypeFile(typeName)
	for _, imp := range file.Imports {
		if imp.Name != nil && imp.Name.Name == pkgName || imp.Name == nil && (parseStringLiteral(imp.Path.Value) == pkgName || strings.HasSuffix(parseStringLiteral(imp.Path.Value), "/"+pkgName)) {
			return parseStringLiteral(imp.Path.Value)
		}
	}
	return ""
}

// LookupTypeFile returns the go source file that containst he definition of the type named typeName.
func (pp *parsedPackage) lookupTypeFile(typeName string) *ast.File {
	for _, file := range pp.Pkg.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.Name == typeName {
							return file
						}
					}
				}
			}
		}
	}
	log.Fatalf("could not find type %q", fmt.Sprintf("%s.%s", pp.Path, typeName))
	return nil
}

// Populate "params" with the arguments from "fields", which are function parameters or return type.
func parseArgs(params *[]sherpadoc.Arg, fields *ast.FieldList, sec *section, pp *parsedPackage, isParams bool) {
	if fields == nil {
		return
	}
	addParam := func(name string, tw typewords) {
		param := sherpadoc.Arg{Name: name, Typewords: tw}
		*params = append(*params, param)
	}
	for _, f := range fields.List {
		typ := parseArgType(f.Type, sec, pp)
		// Handle named params. Can be both arguments to a function or return types.
		for _, name := range f.Names {
			addParam(name.Name, typ)
		}
		// Return types often don't have a name, don't forget them.
		if len(f.Names) == 0 {
			addParam("", typ)
		}
	}

	for i, p := range *params {
		if p.Typewords[len(p.Typewords)-1] != "error" {
			continue
		}
		if isParams || i != len(*params)-1 {
			logFatalLinef(pp, fields.Pos(), "can only have error type as last return value")
		}
		pp := *params
		*params = pp[:len(pp)-1]
	}
}

func adjustFunctionName(s string) string {
	switch *adjustFunctionNames {
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
		panic(fmt.Sprintf("bad value for flag adjust-function-names: %q", *adjustFunctionNames))
	}
}

// ParseMethod ensures the function fn from package pp ends up in section sec, with parameters/return named types filled in.
func parseMethod(sec *section, fn *doc.Func, pp *parsedPackage) {
	f := &function{
		Name:    adjustFunctionName(fn.Name),
		Text:    fn.Doc,
		Params:  []sherpadoc.Arg{},
		Returns: []sherpadoc.Arg{},
	}

	// If first function parameter is context.Context, we skip it in the documentation.
	// The sherpa handler automatically fills it with the http request context when called.
	params := fn.Decl.Type.Params
	if params != nil && len(params.List) > 0 && len(params.List[0].Names) == 1 && goTypeName(useSrc{pp, sec.Name}, params.List[0].Type) == "context.Context" {
		params.List = params.List[1:]
	}
	isParams := true
	parseArgs(&f.Params, params, sec, pp, isParams)

	isParams = false
	parseArgs(&f.Returns, fn.Decl.Type.Results, sec, pp, isParams)
	sec.Functions = append(sec.Functions, f)
}
