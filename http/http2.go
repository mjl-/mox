//go:build go1.27

package http

import (
	"net/http"
)

// Set server.Protocols to enable both http1 and http2. Needed for go1.27 to enable
// http2, only calling http2.ConfigureServer is no longer enough.
func setHTTP2Protocol(server *http.Server) {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	server.Protocols = &p
}
