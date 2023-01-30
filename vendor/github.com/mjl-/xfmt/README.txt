xfmt formats long lines, playing nice with text in code.

To install:

	go get github.com/mjl-/xfmt/cmd/xfmt

Xfmt reads from stdin, writes formatted output to stdout.

Xfmt wraps long lines at 80 characters, configurable through -width. But it
counts text width excluding indenting and markup. Fmt formats to a max line
length that includes indenting. We don't care about total max line length
nowadays, we care about a human readable paragraph, which has a certain text
width regardless of indent.

Xfmt recognizes lines with first non-whitespace of "//" and "#" as line
comments, and repeats that prefix on later lines.

Xfmt keep does not merge lines if the first non-prefix text starts with
interpunction or numbers. E.g. "- item1" or "1. point 1".

Xfmt does not merge multiple spaces, it assumes you intended what you typed.

# todo

- possibly recognize itemized lists in comments and indent the later lines with whitespace
- something else
