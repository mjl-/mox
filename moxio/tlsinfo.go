package moxio

import (
	"crypto/tls"
	"strings"
)

// TLSInfo returns human-readable strings about the TLS connection, for use in
// logging.
func TLSInfo(cs tls.ConnectionState) (version, ciphersuite string) {
	// e.g. tls1.3, instead of "TLS 1.3"
	version = tls.VersionName(cs.Version)
	version = strings.ToLower(version)
	version = strings.ReplaceAll(version, " ", "")

	ciphersuite = tls.CipherSuiteName(cs.CipherSuite)
	ciphersuite = strings.ToLower(ciphersuite)

	return
}
