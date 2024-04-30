//go:build !go1.21

// For go1.20 and earlier.

package tlsrpt

import (
	"fmt"
)

func formatAlert(alert uint8) string {
	return fmt.Sprintf("alert-%d", alert)
}
