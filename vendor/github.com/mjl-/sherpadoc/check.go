package sherpadoc

import (
	"fmt"
)

// IsBasicType returns whether name is a basic type, like int32, string, any, timestamp, etc.
func IsBasicType(name string) bool {
	switch name {
	case "any", "bool", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "int64s", "uint64s", "float32", "float64", "string", "timestamp":
		return true
	}
	return false
}

type genError struct{ error }

func parseError(path string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	err := fmt.Errorf("invalid sherpadoc at %s: %s", path, msg)
	panic(genError{err})
}

func makePath(path string, field string, index int, name string) string {
	return fmt.Sprintf("%s.%s[%d (%q)]", path, field, index, name)
}

// NOTE: sherpaweb/ts/parse.ts and sherpadoc/check.go contain the same checking.
// The code is very similar. Best keep it in sync and modify the implementations in tandem.
type checker struct {
	types     map[string]struct{}
	functions map[string]struct{}
}

func (c checker) markIdent(path, ident string) {
	if _, ok := c.types[ident]; ok {
		parseError(path, "duplicate type %q", ident)
	}
	c.types[ident] = struct{}{}
}

func (c checker) walkTypeNames(path string, sec *Section) {
	for i, t := range sec.Structs {
		c.markIdent(makePath(path, "Structs", i, t.Name), t.Name)
	}
	for i, t := range sec.Ints {
		npath := makePath(path, "Ints", i, t.Name)
		c.markIdent(npath, t.Name)
		for j, v := range t.Values {
			c.markIdent(makePath(npath, "Values", j, v.Name), v.Name)
		}
	}
	for i, t := range sec.Strings {
		npath := makePath(path, "Strings", i, t.Name)
		c.markIdent(npath, t.Name)
		for j, v := range t.Values {
			c.markIdent(makePath(npath, "Values", j, v.Name), v.Name)
		}
	}
	for i, subsec := range sec.Sections {
		c.walkTypeNames(makePath(path, "Sections", i, subsec.Name), subsec)
	}
}

func (c checker) walkFunctionNames(path string, sec *Section) {
	for i, fn := range sec.Functions {
		npath := makePath(path, "Functions", i, fn.Name)
		if _, ok := c.functions[fn.Name]; ok {
			parseError(npath, "duplicate function %q", fn.Name)
		}
		c.functions[fn.Name] = struct{}{}

		paramNames := map[string]struct{}{}
		for i, arg := range fn.Params {
			if _, ok := paramNames[arg.Name]; ok {
				parseError(makePath(npath, "Params", i, arg.Name), "duplicate parameter name")
			}
			paramNames[arg.Name] = struct{}{}
		}

		returnNames := map[string]struct{}{}
		for i, arg := range fn.Returns {
			if _, ok := returnNames[arg.Name]; ok {
				parseError(makePath(npath, "Returns", i, arg.Name), "duplicate return name")
			}
			returnNames[arg.Name] = struct{}{}
		}
	}
	for i, subsec := range sec.Sections {
		c.walkFunctionNames(makePath(path, "Sections", i, subsec.Name), subsec)
	}
}

func (c checker) checkTypewords(path string, tokens []string, okNullable bool) {
	if len(tokens) == 0 {
		parseError(path, "unexpected end of typewords")
	}
	t := tokens[0]
	tokens = tokens[1:]
	if IsBasicType(t) {
		if len(tokens) != 0 {
			parseError(path, "leftover typewords %v", tokens)
		}
		return
	}

	switch t {
	case "nullable":
		if !okNullable {
			parseError(path, "repeated nullable in typewords")
		}
		if len(tokens) == 0 {
			parseError(path, "missing typeword after %#v", t)
		}
		c.checkTypewords(path, tokens, false)
	case "[]", "{}":
		if len(tokens) == 0 {
			parseError(path, "missing typeword after %#v", t)
		}
		c.checkTypewords(path, tokens, true)
	default:
		_, ok := c.types[t]
		if !ok {
			parseError(path, "referenced type %q does not exist", t)
		}
		if len(tokens) != 0 {
			parseError(path, "leftover typewords %v", tokens)
		}
	}
}

func (c checker) walkTypewords(path string, sec *Section) {
	for i, t := range sec.Structs {
		npath := makePath(path, "Structs", i, t.Name)
		for j, f := range t.Fields {
			c.checkTypewords(makePath(npath, "Fields", j, f.Name), f.Typewords, true)
		}
	}
	for i, fn := range sec.Functions {
		npath := makePath(path, "Functions", i, fn.Name)
		for j, arg := range fn.Params {
			c.checkTypewords(makePath(npath, "Params", j, arg.Name), arg.Typewords, true)
		}
		for j, arg := range fn.Returns {
			c.checkTypewords(makePath(npath, "Returns", j, arg.Name), arg.Typewords, true)
		}
	}
	for i, subsec := range sec.Sections {
		c.walkTypewords(makePath(path, "Sections", i, subsec.Name), subsec)
	}
}

// Check walks the sherpa section and checks it for correctness. It checks for:
//
// - Duplicate type names.
// - Duplicate parameter or return names.
// - References to types that are not defined.
// - Validity of typewords.
func Check(doc *Section) (retErr error) {
	defer func() {
		e := recover()
		if e != nil {
			g, ok := e.(genError)
			if !ok {
				panic(e)
			}
			retErr = error(g)
		}
	}()

	c := checker{map[string]struct{}{}, map[string]struct{}{}}

	c.walkTypeNames("", doc)
	c.walkFunctionNames("", doc)
	c.walkTypewords("", doc)

	return nil
}
