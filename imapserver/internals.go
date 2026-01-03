package imapserver

import (
	"crypto/tls"
	"net"
)

// internalsStruct exports some private top-level identifiers
type internalsStruct struct {
	// LimitersInit configures mox’ connection rate limiting and max connections
	LimitersInit func()
	// Serve launches the mox imap server with storage using provided connection
	Serve func(listenerName string, cid int64, tlsConfig *tls.Config, nc net.Conn, xtls bool, noRequireSTARTTLS bool)
}

// internalsValue exports some private top-level identifiers
var internalsValue = internalsStruct{
	LimitersInit: limitersInit,
	Serve:        serve,
}

// Internals exports some private top-level identifiers
func Internals() (internals internalsStruct) { return internalsValue }
