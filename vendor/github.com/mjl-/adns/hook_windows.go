// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"golang.org/x/sys/windows"
)

func windowsGetSystemDirectory() string {
	p, _ := windows.GetSystemDirectory()
	return p
}

var (
	hostsFilePath = windowsGetSystemDirectory() + "/Drivers/etc/hosts"
)
