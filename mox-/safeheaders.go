package mox

import (
	"net/http"
)

// Set some http headers that should prevent potential abuse. Better safe than sorry.
func SafeHeaders(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "deny")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:")
		h.Set("Referrer-Policy", "same-origin")
		fn.ServeHTTP(w, r)
	})
}
