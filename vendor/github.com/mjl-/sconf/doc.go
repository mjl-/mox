/*
Package sconf parses simple configuration files and generates commented example config files.

Sconf is the name of this package and of the config file format. The file format
is inspired by JSON and yaml, but easier to write and use correctly.

Sconf goals:

  - Make the application self-documenting about its configuration requirements.
  - Require full configuration of an application via a config file, finding
    mistakes by the operator.
  - Make it easy to write a correct config file, no surprises.

Workflow for using this package:

  - Write a Go struct with the config for your application.
  - Simply parse a config into that struct with Parse() or ParseFile().
  - Write out an example config file with all fields that need to be set with
    Describe(), and associated comments that you configured in struct tags.

Features of sconf as file format:

  - Types similar to JSON, mapping naturally to types in programming languages.
  - Requires far fewer type-describing tokens. no "" for map keys, strings don't
    require "", no [] for arrays or {} for maps (like in JSON). Sconf uses the Go
    types to guide parsing the config.
  - Can have comments (JSON cannot).
  - Is simple, does not allow all kinds of syntaxes you would not ever want to use.
  - Uses indenting for nested structures (with the indent character).

An example config file:

	# comment for stringKey (optional)
	StringKey: value1
	IntKey: 123
	BoolKey: true
	Struct:
		# this is the A-field
		A: 321
		B: true
		# (optional)
		C: this is text
	StringArray:
		- blah
		- blah
	# nested structs work just as well
	Nested:
		-
			A: 1
			B: false
			C: hoi
		-
			A: -1
			B: true
			C: hallo

The top-level is always a map, typically parsed into a Go struct. Maps start
with a key, followed by a colon, followed by a value. Basic values like
strings, ints, bools run to the end of the line. The leading space after a
colon or dash is removed. Other values like maps and lists start on a new line,
with an additional level of indenting. List values start with a dash. Empty
lines are allowed. Multiline strings are not possible. Strings do not have
escaped characters.

And the struct that generated this:

	var config struct {
		StringKey string `sconf-doc:"comment for stringKey" sconf:"optional"`
		IntKey    int64
		BoolKey   bool
		Struct    struct {
			A int `sconf-doc:"this is the A-field"`
			B bool
			C string `sconf:"optional"`
		}
		StringArray []string
		Nested      []struct {
			A int
			B bool
			C string
		} `sconf-doc:"nested structs work just as well"`
	}

See cmd/sconfexample/main.go for more details.

In practice, you will mostly have nested maps:

	Database:
		Host: localhost
		DBName: myapp
		User: myuser
	Mail:
		SMTP:
			TLS: true
			Host: mail.example.org

Sconf only parses config files. It does not deal with command-line flags or
environment variables. Flags and environment variables are too limiting in data
types. Especially environment variables are error prone: Applications typically
have default values they fall back to, so will not notice typo's or unrecognized
variables. Config files also have the nice property of being easy to diff, copy
around, store in a VCS. In practice, command-line flags and environment
variables are commonly stored in config files. Sconf goes straight to the config
files.
*/
package sconf
