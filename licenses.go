package main

import (
	"embed"
	"os"

	"github.com/mjl-/mox/mox-"
)

//go:embed LICENSE.MIT LICENSE.MPLv2.0 licenses/*
var licensesFsys embed.FS

func init() {
	mox.LicensesFsys = licensesFsys
}

func cmdLicenses(c *cmd) {
	c.help = `Print licenses of mox source code and dependencies.`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	err := mox.LicensesWrite(os.Stdout)
	xcheckf(err, "write")
}
