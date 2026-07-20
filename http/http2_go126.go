//go:build !go1.27

package http

import (
	"net/http"
)

func setHTTP2Protocol(server *http.Server) {
}
