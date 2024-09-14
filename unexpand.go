//go:build tools
// +build tools

// For unexpand the 4 spaces that the typescript compiler outputs into tabs.
// Not all unexpand commands implement the -t flag (openbsd).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		log.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func main() {
	log.SetFlags(0)
	var width int
	flag.IntVar(&width, "t", 8, "tab width")
	flag.Parse()
	flag.Usage = func() {
		log.Print("usage: unexpand [-t tabwidth] < input.spaces >output.tabs")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		flag.Usage()
	}
	if width <= 0 {
		flag.Usage()
	}

	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)

	nspace := 0
	start := true

	flush := func() {
		for ; nspace > 0; nspace-- {
			err := w.WriteByte(' ')
			xcheckf(err, "write")
		}
	}
	write := func(b byte) {
		err := w.WriteByte(b)
		xcheckf(err, "write")
	}

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		xcheckf(err, "read")

		if start && b == ' ' {
			nspace++
			if nspace == width {
				write('\t')
				nspace = 0
			}
		} else {
			flush()
			write(b)
			start = b == '\n'
		}
	}
	flush()
	err := w.Flush()
	xcheckf(err, "flush output")
}
