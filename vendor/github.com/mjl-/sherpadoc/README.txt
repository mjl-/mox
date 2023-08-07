sherpadoc - documentation for sherpa API's

Go package containing type defintions for sherpa documentation for encoding to and decoding from json.
Also contains the sherpadoc command reads Go code and writes sherpadoc JSON.

Use together with the sherpa library, github.com/mjl-/sherpa.
Read more about sherpa at https://www.ueber.net/who/mjl/sherpa/

# About

Written by Mechiel Lukkien, mechiel@ueber.net.
Bug fixes, patches, comments are welcome.
MIT-licensed, see LICENSE.

# todo

- major cleanup required. too much parsing is done that can probably be handled by the go/* packages.
- check that all cases of embedding work (seems like we will include duplicates: when a struct has fields that override an embedded struct, we generate duplicate fields).
- check that all cross-package referencing (ast.SelectorExpr) works
- better cli syntax for replacements, and always replace based on fully qualified names. currently you need to specify both the fully qualified and unqualified type paths.
- see if order of items in output depends on a map somewhere, i've seen diffs for generated jsons where a type was only moved, not modified.
- better error messages and error handling, stricter parsing
- support type aliases
- support plain iota enums? currently only simple literals are supported for enums.
- support complete expressions for enum consts?
- find out which go constructs people want to use that aren't yet implemented by sherpadoc
- when to make a field nullable. when omitempty is set? (currently yes), when field is a pointer type (currently yes). should we have a way to prevent nullable without omitempty set, or make field a pointer without it being nullable?
- write tests
