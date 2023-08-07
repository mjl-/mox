package sherpats

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mjl-/sherpadoc"
)

// Keywords in Typescript, from https://github.com/microsoft/TypeScript/blob/master/doc/spec.md.
var keywords = map[string]struct{}{
	"break":       {},
	"case":        {},
	"catch":       {},
	"class":       {},
	"const":       {},
	"continue":    {},
	"debugger":    {},
	"default":     {},
	"delete":      {},
	"do":          {},
	"else":        {},
	"enum":        {},
	"export":      {},
	"extends":     {},
	"false":       {},
	"finally":     {},
	"for":         {},
	"function":    {},
	"if":          {},
	"import":      {},
	"in":          {},
	"instanceof":  {},
	"new":         {},
	"null":        {},
	"return":      {},
	"super":       {},
	"switch":      {},
	"this":        {},
	"throw":       {},
	"true":        {},
	"try":         {},
	"typeof":      {},
	"var":         {},
	"void":        {},
	"while":       {},
	"with":        {},
	"implements":  {},
	"interface":   {},
	"let":         {},
	"package":     {},
	"private":     {},
	"protected":   {},
	"public":      {},
	"static":      {},
	"yield":       {},
	"any":         {},
	"boolean":     {},
	"number":      {},
	"string":      {},
	"symbol":      {},
	"abstract":    {},
	"as":          {},
	"async":       {},
	"await":       {},
	"constructor": {},
	"declare":     {},
	"from":        {},
	"get":         {},
	"is":          {},
	"module":      {},
	"namespace":   {},
	"of":          {},
	"require":     {},
	"set":         {},
	"type":        {},
}

type sherpaType interface {
	TypescriptType() string
}

// baseType can be one of: "any", "int16", etc
type baseType struct {
	Name string
}

// nullableType is: "nullable" <type>.
type nullableType struct {
	Type sherpaType
}

// arrayType is: "[]" <type>
type arrayType struct {
	Type sherpaType
}

// objectType is: "{}" <type>
type objectType struct {
	Value sherpaType
}

// identType is: [a-zA-Z][a-zA-Z0-9]*
type identType struct {
	Name string
}

func (t baseType) TypescriptType() string {
	switch t.Name {
	case "bool":
		return "boolean"
	case "timestamp":
		return "Date"
	case "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float32", "float64":
		return "number"
	case "int64s", "uint64s":
		return "string"
	default:
		return t.Name
	}
}

func isBaseOrIdent(t sherpaType) bool {
	if _, ok := t.(baseType); ok {
		return true
	}
	if _, ok := t.(identType); ok {
		return true
	}
	return false
}

func (t nullableType) TypescriptType() string {
	if isBaseOrIdent(t.Type) {
		return t.Type.TypescriptType() + " | null"
	}
	return "(" + t.Type.TypescriptType() + ") | null"
}

func (t arrayType) TypescriptType() string {
	if isBaseOrIdent(t.Type) {
		return t.Type.TypescriptType() + "[] | null"
	}
	return "(" + t.Type.TypescriptType() + ")[] | null"
}

func (t objectType) TypescriptType() string {
	return fmt.Sprintf("{ [key: string]: %s }", t.Value.TypescriptType())
}

func (t identType) TypescriptType() string {
	return t.Name
}

type genError struct{ error }

type Options struct {
	// If not empty, the generated typescript is wrapped in a namespace. This allows
	// easy compilation, with "tsc --module none" that uses the generated typescript
	// api, while keeping all types/functions isolated.
	Namespace string

	// With SlicesNullable and MapsNullable, generated typescript types are made
	// nullable, with "| null". Go's JSON package marshals a nil slice/map to null, so
	// it can be wise to make TypeScript consumers check that. Go code typically
	// handles incoming nil and empty slices/maps in the same way.
	SlicesNullable bool
	MapsNullable   bool

	// If nullables are optional, the generated typescript types allow the "undefined"
	// value where nullable values are expected. This includes slices/maps when
	// SlicesNullable/MapsNullable is set. When JavaScript marshals JSON, a field with the
	// "undefined" value is treated as if the field doesn't exist, and isn't
	// marshalled. The "undefined" value in an array is marshalled as null. It is
	// common (though not always the case!) in Go server code to not make a difference
	// between a missing field and a null value
	NullableOptional bool

	// If set, "[]uint8" is changed into "string" before before interpreting the
	// sherpadoc definitions. Go's JSON marshaller turns []byte (which is []uint8) into
	// base64 strings. Having the same types in TypeScript is convenient.
	// If SlicesNullable is set, the strings are made nullable.
	BytesToString bool
}

// Generate reads sherpadoc from in and writes a typescript file containing a
// client package to out.  apiNameBaseURL is either an API name or sherpa
// baseURL, depending on whether it contains a slash. If it is a package name, the
// baseURL is created at runtime by adding the packageName to the current location.
func Generate(in io.Reader, out io.Writer, apiNameBaseURL string, opts Options) (retErr error) {
	defer func() {
		e := recover()
		if e == nil {
			return
		}
		g, ok := e.(genError)
		if !ok {
			panic(e)
		}
		retErr = error(g)
	}()

	var doc sherpadoc.Section
	err := json.NewDecoder(os.Stdin).Decode(&doc)
	if err != nil {
		panic(genError{fmt.Errorf("parsing sherpadoc json: %s", err)})
	}

	const sherpadocVersion = 1
	if doc.SherpadocVersion != sherpadocVersion {
		panic(genError{fmt.Errorf("unexpected sherpadoc version %d, expected %d", doc.SherpadocVersion, sherpadocVersion)})
	}

	if opts.BytesToString {
		toString := func(tw []string) []string {
			n := len(tw) - 1
			for i := 0; i < n; i++ {
				if tw[i] == "[]" && tw[i+1] == "uint8" {
					if opts.SlicesNullable && (i == 0 || tw[i-1] != "nullable") {
						tw[i] = "nullable"
						tw[i+1] = "string"
						i++
					} else {
						tw[i] = "string"
						copy(tw[i+1:], tw[i+2:])
						tw = tw[:len(tw)-1]
						n--
					}
				}
			}
			return tw
		}

		var bytesToString func(sec *sherpadoc.Section)
		bytesToString = func(sec *sherpadoc.Section) {
			for i := range sec.Functions {
				for j := range sec.Functions[i].Params {
					sec.Functions[i].Params[j].Typewords = toString(sec.Functions[i].Params[j].Typewords)
				}
				for j := range sec.Functions[i].Returns {
					sec.Functions[i].Returns[j].Typewords = toString(sec.Functions[i].Returns[j].Typewords)
				}
			}
			for i := range sec.Structs {
				for j := range sec.Structs[i].Fields {
					sec.Structs[i].Fields[j].Typewords = toString(sec.Structs[i].Fields[j].Typewords)
				}
			}
			for _, s := range sec.Sections {
				bytesToString(s)
			}
		}
		bytesToString(&doc)
	}

	// Validate the sherpadoc.
	err = sherpadoc.Check(&doc)
	if err != nil {
		panic(genError{err})
	}

	// Make a copy, the ugly way. We'll strip the documentation out before including
	// the types. We need types for runtime type checking, but the docs just bloat the
	// size.
	var typesdoc sherpadoc.Section
	if typesbuf, err := json.Marshal(doc); err != nil {
		panic(genError{fmt.Errorf("marshal sherpadoc for types: %s", err)})
	} else if err := json.Unmarshal(typesbuf, &typesdoc); err != nil {
		panic(genError{fmt.Errorf("unmarshal sherpadoc for types: %s", err)})
	}
	for i := range typesdoc.Structs {
		typesdoc.Structs[i].Docs = ""
		for j := range typesdoc.Structs[i].Fields {
			typesdoc.Structs[i].Fields[j].Docs = ""
		}
	}
	for i := range typesdoc.Ints {
		typesdoc.Ints[i].Docs = ""
		for j := range typesdoc.Ints[i].Values {
			typesdoc.Ints[i].Values[j].Docs = ""
		}
	}
	for i := range typesdoc.Strings {
		typesdoc.Strings[i].Docs = ""
		for j := range typesdoc.Strings[i].Values {
			typesdoc.Strings[i].Values[j].Docs = ""
		}
	}

	bout := bufio.NewWriter(out)
	xprintf := func(format string, args ...interface{}) {
		_, err := fmt.Fprintf(out, format, args...)
		if err != nil {
			panic(genError{err})
		}
	}

	xprintMultiline := func(indent, docs string, always bool) []string {
		lines := docLines(docs)
		if len(lines) == 1 && !always {
			return lines
		}
		for _, line := range lines {
			xprintf("%s// %s\n", indent, line)
		}
		return lines
	}

	xprintSingleline := func(lines []string) {
		if len(lines) != 1 {
			return
		}
		xprintf("  // %s", lines[0])
	}

	// Type and function names could be typescript keywords. If they are, give them a different name.
	typescriptNames := map[string]string{}
	typescriptName := func(name string, names map[string]string) string {
		if _, ok := keywords[name]; !ok {
			return name
		}
		n := names[name]
		if n != "" {
			return n
		}
		for i := 0; ; i++ {
			n = fmt.Sprintf("%s%d", name, i)
			if _, ok := names[n]; ok {
				continue
			}
			names[name] = n
			return n
		}
	}

	structTypes := map[string]bool{}
	stringsTypes := map[string]bool{}
	intsTypes := map[string]bool{}

	var generateTypes func(sec *sherpadoc.Section)
	generateTypes = func(sec *sherpadoc.Section) {
		for _, t := range sec.Structs {
			structTypes[t.Name] = true
			xprintMultiline("", t.Docs, true)
			name := typescriptName(t.Name, typescriptNames)
			xprintf("export interface %s {\n", name)
			names := map[string]string{}
			for _, f := range t.Fields {
				lines := xprintMultiline("", f.Docs, false)
				what := fmt.Sprintf("field %s for type %s", f.Name, t.Name)
				optional := ""
				if opts.NullableOptional && f.Typewords[0] == "nullable" || opts.NullableOptional && (opts.SlicesNullable && f.Typewords[0] == "[]" || opts.MapsNullable && f.Typewords[0] == "{}") {
					optional = "?"
				}
				xprintf("\t%s%s: %s", typescriptName(f.Name, names), optional, typescriptType(what, f.Typewords))
				xprintSingleline(lines)
				xprintf("\n")
			}
			xprintf("}\n\n")
		}

		for _, t := range sec.Ints {
			intsTypes[t.Name] = true
			xprintMultiline("", t.Docs, true)
			name := typescriptName(t.Name, typescriptNames)
			if len(t.Values) == 0 {
				xprintf("export type %s = number\n\n", name)
				continue
			}
			xprintf("export enum %s {\n", name)
			names := map[string]string{}
			for _, v := range t.Values {
				lines := xprintMultiline("\t", v.Docs, false)
				xprintf("\t%s = %d,", typescriptName(v.Name, names), v.Value)
				xprintSingleline(lines)
				xprintf("\n")
			}
			xprintf("}\n\n")
		}

		for _, t := range sec.Strings {
			stringsTypes[t.Name] = true
			xprintMultiline("", t.Docs, true)
			name := typescriptName(t.Name, typescriptNames)
			if len(t.Values) == 0 {
				xprintf("export type %s = string\n\n", name)
				continue
			}
			xprintf("export enum %s {\n", name)
			names := map[string]string{}
			for _, v := range t.Values {
				lines := xprintMultiline("\t", v.Docs, false)
				s := mustMarshalJSON(v.Value)
				xprintf("\t%s = %s,", typescriptName(v.Name, names), s)
				xprintSingleline(lines)
				xprintf("\n")
			}
			xprintf("}\n\n")
		}

		for _, subsec := range sec.Sections {
			generateTypes(subsec)
		}
	}

	var generateFunctionTypes func(sec *sherpadoc.Section)
	generateFunctionTypes = func(sec *sherpadoc.Section) {
		for _, typ := range sec.Structs {
			xprintf("	%s: %s,\n", mustMarshalJSON(typ.Name), mustMarshalJSON(typ))
		}
		for _, typ := range sec.Ints {
			xprintf("	%s: %s,\n", mustMarshalJSON(typ.Name), mustMarshalJSON(typ))
		}
		for _, typ := range sec.Strings {
			xprintf("	%s: %s,\n", mustMarshalJSON(typ.Name), mustMarshalJSON(typ))
		}

		for _, subsec := range sec.Sections {
			generateFunctionTypes(subsec)
		}
	}

	var generateParser func(sec *sherpadoc.Section)
	generateParser = func(sec *sherpadoc.Section) {
		for _, typ := range sec.Structs {
			xprintf("	%s: (v: any) => parse(%s, v) as %s,\n", typ.Name, mustMarshalJSON(typ.Name), typ.Name)
		}
		for _, typ := range sec.Ints {
			xprintf("	%s: (v: any) => parse(%s, v) as %s,\n", typ.Name, mustMarshalJSON(typ.Name), typ.Name)
		}
		for _, typ := range sec.Strings {
			xprintf("	%s: (v: any) => parse(%s, v) as %s,\n", typ.Name, mustMarshalJSON(typ.Name), typ.Name)
		}

		for _, subsec := range sec.Sections {
			generateParser(subsec)
		}
	}

	var generateSectionDocs func(sec *sherpadoc.Section)
	generateSectionDocs = func(sec *sherpadoc.Section) {
		xprintMultiline("", sec.Docs, true)
		for _, subsec := range sec.Sections {
			xprintf("//\n")
			xprintf("// # %s\n", subsec.Name)
			generateSectionDocs(subsec)
		}
	}

	var generateFunctions func(sec *sherpadoc.Section)
	generateFunctions = func(sec *sherpadoc.Section) {
		for i, fn := range sec.Functions {
			whatParam := "pararameter for " + fn.Name
			paramNameTypes := []string{}
			paramNames := []string{}
			sherpaParamTypes := [][]string{}
			names := map[string]string{}
			for _, p := range fn.Params {
				name := typescriptName(p.Name, names)
				v := fmt.Sprintf("%s: %s", name, typescriptType(whatParam, p.Typewords))
				paramNameTypes = append(paramNameTypes, v)
				paramNames = append(paramNames, name)
				sherpaParamTypes = append(sherpaParamTypes, p.Typewords)
			}

			var returnType string
			switch len(fn.Returns) {
			case 0:
				returnType = "void"
			case 1:
				what := "return type for " + fn.Name
				returnType = typescriptType(what, fn.Returns[0].Typewords)
			default:
				var types []string
				what := "return type for " + fn.Name
				for _, t := range fn.Returns {
					types = append(types, typescriptType(what, t.Typewords))
				}
				returnType = fmt.Sprintf("[%s]", strings.Join(types, ", "))
			}
			sherpaReturnTypes := [][]string{}
			for _, a := range fn.Returns {
				sherpaReturnTypes = append(sherpaReturnTypes, a.Typewords)
			}

			name := typescriptName(fn.Name, typescriptNames)
			xprintMultiline("\t", fn.Docs, true)
			xprintf("\tasync %s(%s): Promise<%s> {\n", name, strings.Join(paramNameTypes, ", "), returnType)
			xprintf("\t\tconst fn: string = %s\n", mustMarshalJSON(fn.Name))
			xprintf("\t\tconst paramTypes: string[][] = %s\n", mustMarshalJSON(sherpaParamTypes))
			xprintf("\t\tconst returnTypes: string[][] = %s\n", mustMarshalJSON(sherpaReturnTypes))
			xprintf("\t\tconst params: any[] = [%s]\n", strings.Join(paramNames, ", "))
			xprintf("\t\treturn await _sherpaCall(this.baseURL, { ...this.options }, paramTypes, returnTypes, fn, params) as %s\n", returnType)
			xprintf("\t}\n")
			if i < len(sec.Functions)-1 {
				xprintf("\n")
			}
		}

		for _, s := range sec.Sections {
			generateFunctions(s)
		}
	}

	xprintf("// NOTE: GENERATED by github.com/mjl-/sherpats, DO NOT MODIFY\n\n")
	if opts.Namespace != "" {
		xprintf("namespace %s {\n\n", opts.Namespace)
	}
	generateTypes(&doc)
	xprintf("export const structTypes: {[typename: string]: boolean} = %s\n", mustMarshalJSON(structTypes))
	xprintf("export const stringsTypes: {[typename: string]: boolean} = %s\n", mustMarshalJSON(stringsTypes))
	xprintf("export const intsTypes: {[typename: string]: boolean} = %s\n", mustMarshalJSON(intsTypes))
	xprintf("export const types: TypenameMap = {\n")
	generateFunctionTypes(&typesdoc)
	xprintf("}\n\n")
	xprintf("export const parser = {\n")
	generateParser(&doc)
	xprintf("}\n\n")
	generateSectionDocs(&doc)
	xprintf(`let defaultOptions: ClientOptions = {slicesNullable: %v, mapsNullable: %v, nullableOptional: %v}

export class Client {
	constructor(private baseURL=defaultBaseURL, public options?: ClientOptions) {
		if (!options) {
			this.options = defaultOptions
		}
	}

	withOptions(options: ClientOptions): Client {
		return new Client(this.baseURL, { ...this.options, ...options })
	}

`, opts.SlicesNullable, opts.MapsNullable, opts.NullableOptional)
	generateFunctions(&doc)
	xprintf("}\n\n")

	const findBaseURL = `(function() {
	let p = location.pathname
	if (p && p[p.length - 1] !== '/') {
		let l = location.pathname.split('/')
		l = l.slice(0, l.length - 1)
		p = '/' + l.join('/') + '/'
	}
	return location.protocol + '//' + location.host + p + 'API_NAME/'
})()`

	var apiJS string
	if strings.Contains(apiNameBaseURL, "/") {
		apiJS = mustMarshalJSON(apiNameBaseURL)
	} else {
		apiJS = strings.Replace(findBaseURL, "API_NAME", apiNameBaseURL, -1)
	}
	xprintf("%s\n", strings.Replace(libTS, "BASEURL", apiJS, -1))
	if opts.Namespace != "" {
		xprintf("}\n")
	}

	err = bout.Flush()
	if err != nil {
		panic(genError{err})
	}
	return nil
}

func typescriptType(what string, typeTokens []string) string {
	t := parseType(what, typeTokens)
	return t.TypescriptType()
}

func parseType(what string, tokens []string) sherpaType {
	checkOK := func(ok bool, v interface{}, msg string) {
		if !ok {
			panic(genError{fmt.Errorf("invalid type for %s: %s, saw %q", what, msg, v)})
		}
	}
	checkOK(len(tokens) > 0, tokens, "need at least one element")
	s := tokens[0]
	tokens = tokens[1:]
	switch s {
	case "any", "bool", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "int64s", "uint64s", "float32", "float64", "string", "timestamp":
		if len(tokens) != 0 {
			checkOK(false, tokens, "leftover tokens after base type")
		}
		return baseType{s}
	case "nullable":
		return nullableType{parseType(what, tokens)}
	case "[]":
		return arrayType{parseType(what, tokens)}
	case "{}":
		return objectType{parseType(what, tokens)}
	default:
		if len(tokens) != 0 {
			checkOK(false, tokens, "leftover tokens after identifier type")
		}
		return identType{s}
	}
}

func docLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func mustMarshalJSON(v interface{}) string {
	buf, err := json.Marshal(v)
	if err != nil {
		panic(genError{fmt.Errorf("marshalling json: %s", err)})
	}
	return string(buf)
}
