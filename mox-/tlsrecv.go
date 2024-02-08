package mox

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/mjl-/mox/mlog"
)

// TLSReceivedComment returns a comment about TLS of the connection for use in a Receive header.
func TLSReceivedComment(log mlog.Log, cs tls.ConnectionState) []string {
	// todo future: we could use the "tls" clause for the Received header as specified in ../rfc/8314:496. however, the text implies it is only for submission, not regular smtp. and it cannot specify the tls version. for now, not worth the trouble.

	// Comments from other mail servers:
	// gmail.com: (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128)
	// yahoo.com: (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256)
	// proton.me: (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256) (No client certificate requested)
	// outlook.com: (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)

	var l []string
	add := func(s string) {
		l = append(l, s)
	}

	versions := map[uint16]string{
		tls.VersionTLS10: "TLS1.0",
		tls.VersionTLS11: "TLS1.1",
		tls.VersionTLS12: "TLS1.2",
		tls.VersionTLS13: "TLS1.3",
	}

	if version, ok := versions[cs.Version]; ok {
		add(version)
	} else {
		log.Info("unknown tls version identifier", slog.Any("version", cs.Version))
		add(fmt.Sprintf("TLS identifier %x", cs.Version))
	}

	add(tls.CipherSuiteName(cs.CipherSuite))

	// Make it a comment.
	l[0] = "(" + l[0]
	l[len(l)-1] = l[len(l)-1] + ")"

	return l
}
