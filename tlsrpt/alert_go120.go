//go:build !go1.21

// For go1.20 and earlier.

package tlsrpt

import (
	"fmt"
)

// FormatAlert formats a TLS alert in the form "alert-<num>".
func FormatAlert(alert uint8) string {
	return fmt.Sprintf("alert-%d", alert)
}
