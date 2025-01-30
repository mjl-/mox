package moxvar

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"testing"
)

var skipRegisterLogging = testing.Testing()

// RegisterLogger should be used as parameter to bstore.Options.RegisterLogger.
//
// RegisterLogger returns nil when running under test and the database file does
// not yet exist to reduce lots of unhelpful logging, and returns logger log
// otherwise.
func RegisterLogger(path string, log *slog.Logger) *slog.Logger {
	if !skipRegisterLogging {
		return log
	}
	if _, err := os.Stat(path); err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return log
}
