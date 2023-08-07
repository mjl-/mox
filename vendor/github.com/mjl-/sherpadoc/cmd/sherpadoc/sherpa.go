package main

import (
	"fmt"
	"strings"

	"github.com/mjl-/sherpadoc"
)

func sherpaSection(sec *section) *sherpadoc.Section {
	doc := &sherpadoc.Section{
		Name:      sec.Name,
		Docs:      sec.Text,
		Functions: []*sherpadoc.Function{},
		Sections:  []*sherpadoc.Section{},
		Structs:   []sherpadoc.Struct{},
		Ints:      []sherpadoc.Ints{},
		Strings:   []sherpadoc.Strings{},
	}
	for _, t := range sec.Types {
		switch t.Kind {
		case typeStruct:
			tt := sherpadoc.Struct{
				Name:   t.Name,
				Docs:   t.Text,
				Fields: []sherpadoc.Field{},
			}
			for _, f := range t.Fields {
				ff := sherpadoc.Field{
					Name:      f.Name,
					Docs:      f.Doc,
					Typewords: f.Typewords,
				}
				tt.Fields = append(tt.Fields, ff)
			}
			doc.Structs = append(doc.Structs, tt)
		case typeInts:
			e := sherpadoc.Ints{
				Name:   t.Name,
				Docs:   strings.TrimSpace(t.Text),
				Values: t.IntValues,
			}
			doc.Ints = append(doc.Ints, e)
		case typeStrings:
			e := sherpadoc.Strings{
				Name:   t.Name,
				Docs:   strings.TrimSpace(t.Text),
				Values: t.StringValues,
			}
			doc.Strings = append(doc.Strings, e)
		case typeBytes:
			// todo: hack. find proper way to docment them. better for larger functionality: add generic support for lists of types. for now we'll fake this being a string...
			e := sherpadoc.Strings{
				Name: t.Name,
				Docs: strings.TrimSpace(t.Text),
				Values: []struct {
					Name  string
					Value string
					Docs  string
				}{},
			}
			doc.Strings = append(doc.Strings, e)
		default:
			panic("missing case")
		}
	}
	for _, fn := range sec.Functions {
		// Ensure returns always have a name. Go can leave them nameless.
		// Either they all have names or they don't, so the names we make up will never clash.
		for i := range fn.Returns {
			if fn.Returns[i].Name == "" {
				fn.Returns[i].Name = fmt.Sprintf("r%d", i)
			}
		}

		f := &sherpadoc.Function{
			Name:    fn.Name,
			Docs:    strings.TrimSpace(fn.Text),
			Params:  fn.Params,
			Returns: fn.Returns,
		}
		doc.Functions = append(doc.Functions, f)
	}
	for _, subsec := range sec.Sections {
		doc.Sections = append(doc.Sections, sherpaSection(subsec))
	}
	doc.Docs = strings.TrimSpace(doc.Docs)
	return doc
}
