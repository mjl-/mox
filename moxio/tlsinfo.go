package moxio

import (
	"crypto/tls"
	"fmt"
)

// TLSInfo returns human-readable strings about the TLS connection, for use in
// logging.
func TLSInfo(conn *tls.Conn) (version, ciphersuite string) {
	st := conn.ConnectionState()

	versions := map[uint16]string{
		tls.VersionTLS10: "TLS1.0",
		tls.VersionTLS11: "TLS1.1",
		tls.VersionTLS12: "TLS1.2",
		tls.VersionTLS13: "TLS1.3",
	}

	v, ok := versions[st.Version]
	if ok {
		version = v
	} else {
		version = fmt.Sprintf("TLS %x", st.Version)
	}

	ciphersuite = tls.CipherSuiteName(st.CipherSuite)
	return
}
