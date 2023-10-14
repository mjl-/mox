package main

import (
	"log"
)

// also see localserve.go, code is similar or even shared.
func cmdServe(c *cmd) {
	c.help = `Start mox, serving SMTP/IMAP/HTTPS. Not implemented on windows.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}
	log.Fatalln("mox serve not implemented on windows yet due to unfamiliarity with the windows security model, other commands including localserve do work")
}
