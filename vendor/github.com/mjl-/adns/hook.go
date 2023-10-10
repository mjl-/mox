// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adns

import (
	"context"
	"net"
)

var (
	testHookHostsPath = "/etc/hosts"
	testHookLookupIP  = func(
		ctx context.Context,
		fn func(context.Context, string, string) ([]net.IPAddr, Result, error),
		network string,
		host string,
	) ([]net.IPAddr, Result, error) {
		return fn(ctx, network, host)
	}
)
