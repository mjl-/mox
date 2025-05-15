//go:build !go1.24

package main

import (
	"crypto/tls"
)

var curvesList = []tls.CurveID{
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
	tls.X25519,
}
