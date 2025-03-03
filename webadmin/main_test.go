package webadmin

import (
	"fmt"
	"os"
	"testing"

	"github.com/mjl-/mox/metrics"
)

func TestMain(m *testing.M) {
	m.Run()
	if metrics.Panics.Load() > 0 {
		fmt.Println("unhandled panics encountered")
		os.Exit(2)
	}
}
