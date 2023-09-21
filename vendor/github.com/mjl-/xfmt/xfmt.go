// Package xfmt reformats text, wrapping it while recognizing comments.
package xfmt

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Config tells format how to reformat text.
type Config struct {
	// Max width of content (excluding indenting), after which lines are wrapped.
	MaxWidth int

	// String prefixes that cause a line to break, instead of being merged into the
	// previous line.
	BreakPrefixes []string
}

// Format reads text from r and writes reformatted text to w, according to
// instructions in config. Lines ending with \r\n are formatted with \r\n as well.
func Format(w io.Writer, r io.Reader, config Config) error {
	f := &formatter{
		in:     bufio.NewReader(r),
		out:    bufio.NewWriter(w),
		config: config,
	}
	return f.format()
}

type formatter struct {
	in         *bufio.Reader
	out        *bufio.Writer
	config     Config
	curLine    string
	curLineend string
}

type parseError struct{ error }

func (f *formatter) format() (rerr error) {
	defer func() {
		e := recover()
		if e != nil {
			if pe, ok := e.(parseError); ok {
				rerr = pe
			} else {
				panic(e)
			}
		}
	}()

	for {
		line, end := f.gatherLine()
		if line == "" && end == "" {
			break
		}
		prefix, rem := parseLine(line)
		for _, s := range f.splitLine(rem) {
			f.write(prefix)
			f.write(s)
			f.write(end)
		}
	}
	return f.out.Flush()

}

func (f *formatter) check(err error, action string) {
	if err != nil {
		panic(parseError{fmt.Errorf("%s: %s", action, err)})
	}
}

func (f *formatter) write(s string) {
	_, err := f.out.Write([]byte(s))
	f.check(err, "write")
}

func (f *formatter) peekLine() (string, string) {
	if f.curLine != "" || f.curLineend != "" {
		return f.curLine, f.curLineend
	}

	line, err := f.in.ReadString('\n')
	if err != io.EOF {
		f.check(err, "read")
	}
	if line == "" {
		return "", ""
	}
	if strings.HasSuffix(line, "\r\n") {
		f.curLine, f.curLineend = line[:len(line)-2], "\r\n"
	} else if strings.HasSuffix(line, "\n") {
		f.curLine, f.curLineend = line[:len(line)-1], "\n"
	} else {
		f.curLine, f.curLineend = line, ""
	}
	return f.curLine, f.curLineend
}

func (f *formatter) consumeLine() {
	if f.curLine == "" && f.curLineend == "" {
		panic("bad")
	}
	f.curLine = ""
	f.curLineend = ""
}

func (f *formatter) gatherLine() (string, string) {
	var curLine, curLineend string
	var curPrefix string

	n := 0
	for {
		line, end := f.peekLine()
		if line == "" && end == "" {
			break
		}
		if curLine == "" {
			curLineend = end
		}
		prefix, rem := parseLine(line)
		if prefix == "" && rem == "" {
			if curLine == "" {
				f.consumeLine()
			}
			break
		}
		if n > 0 && (curPrefix != prefix || rem == "" || f.causeBreak(rem)) {
			break
		}
		curPrefix = prefix
		if curLine != "" {
			curLine += " "
		}
		curLine += rem
		f.consumeLine()
		// Control at begin or end of line are not merged.
		if curLine != "" && curLine[len(curLine)-1] < 0x20 {
			break
		}
		n++
	}

	return curPrefix + curLine, curLineend
}

func (f *formatter) causeBreak(s string) bool {
	c := s[0]
	if c < 0x20 {
		return true
	}
	for _, ss := range f.config.BreakPrefixes {
		if strings.HasPrefix(s, ss) {
			return true
		}
	}

	// Don't merge lines starting with eg "1. ".
	for i, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && c == '.' && strings.HasPrefix(s[i:], ". ") {
			return true
		}
		break
	}
	return false
}

func parseLine(s string) (string, string) {
	orig := s
	s = strings.TrimLeft(orig, " \t")
	prefix := orig[:len(orig)-len(s)]
	if strings.HasPrefix(s, "//") {
		prefix += "//"
		s = s[2:]
	} else if strings.HasPrefix(s, "#") {
		prefix += "#"
		s = s[1:]
	}
	ns := strings.TrimLeft(s, " \t")
	prefix += s[:len(s)-len(ns)]
	s = ns
	return prefix, s
}

func (f *formatter) splitLine(s string) []string {
	if len(s) <= f.config.MaxWidth {
		return []string{s}
	}

	line := ""
	r := []string{}
	for _, w := range strings.Split(s, " ") {
		if line != "" && len(line)+1+len(w) > f.config.MaxWidth {
			r = append(r, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		r = append(r, line)
	}
	return r
}
