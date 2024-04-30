//go:build go1.21

// From go1.21 and onwards.

package tlsrpt

import (
	"crypto/tls"
	"fmt"
	"strings"
)

func formatAlert(alert uint8) string {
	s := fmt.Sprintf("alert-%d", alert)
	err := tls.AlertError(alert) // Since go1.21.0
	// crypto/tls returns messages like "tls: short message" or "tls: alert(321)".
	if str := err.Error(); !strings.Contains(str, "alert(") {
		s += "-" + strings.ReplaceAll(strings.TrimPrefix(str, "tls: "), " ", "-")
	}
	return s
}
