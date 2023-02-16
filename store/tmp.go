package store

import (
	"os"

	"github.com/mjl-/mox/mox-"
)

// CreateMessageTemp creates a temporary file for a message to be delivered.
// Caller is responsible for removing the temporary file on error, and for closing the file.
// Caller should ensure the contents of the file are synced to disk before
// attempting to deliver the message.
func CreateMessageTemp(pattern string) (*os.File, error) {
	dir := mox.DataDirPath("tmp")
	os.MkdirAll(dir, 0770)
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	err = f.Chmod(0660)
	if err != nil {
		xerr := f.Close()
		xlog.Check(xerr, "closing temp message file after chmod error")
		return nil, err
	}
	return f, err
}
