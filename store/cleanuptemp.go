package store

import (
	"os"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/mlog"
)

// CloseRemoveTempFile closes and removes f, a file described by descr. Often
// used in a defer after creating a temporary file.
func CloseRemoveTempFile(log mlog.Log, f *os.File, descr string) {
	name := f.Name()
	err := f.Close()
	log.Check(err, "closing temporary file", slog.String("kind", descr))
	err = os.Remove(name)
	log.Check(err, "removing temporary file", slog.String("kind", descr))
}
