package store

import (
	"os"

	"github.com/mjl-/mox/mox-"
)

// CreateMessageTemp creates a temporary file, e.g. for delivery. The is created in
// subdirectory tmp of the data directory, so the file is on the same file system
// as the accounts directory, so renaming files can succeed. The caller is
// responsible for closing and possibly removing the file. The caller should ensure
// the contents of the file are synced to disk before attempting to deliver the
// message.
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
