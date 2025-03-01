package moxio

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/mjl-/mox/mlog"
)

// LinkOrCopy attempts to make a hardlink dst. If that fails, it will try to do a
// regular file copy. If srcReaderOpt is not nil, it will be used for reading. If
// fileSync is true and the file is copied instead of hardlinked, fsync is called
// on the file after writing to ensure the file is flushed to disk. Callers should
// also sync the directory of the destination file, but may want to do that after
// linking/copying multiple files. If dst was created and an error occurred, it is
// removed.
func LinkOrCopy(log mlog.Log, dst, src string, srcReaderOpt io.Reader, fileSync bool) (rerr error) {

	// Try hardlink first.
	err := os.Link(src, dst)
	if err == nil {
		return nil
	} else if os.IsNotExist(err) {
		// No point in trying with regular copy, we would fail again. Either src doesn't
		// exist or dst directory doesn't exist.
		return err
	}

	// File system may not support hardlinks, or link could be crossing file systems.
	// Do a regular file copy.
	if srcReaderOpt == nil {
		sf, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open source file: %w", err)
		}
		defer func() {
			err := sf.Close()
			log.Check(err, "closing copied source file")
		}()
		srcReaderOpt = sf
	}

	df, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0660)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() {
		if df != nil {
			err := df.Close()
			log.Check(err, "closing partial destination file")
		}
		if rerr != nil {
			err = os.Remove(dst)
			log.Check(err, "removing partial destination file", slog.String("path", dst))
		}
	}()

	if _, err := io.Copy(df, srcReaderOpt); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	if fileSync {
		if err := df.Sync(); err != nil {
			return fmt.Errorf("sync destination: %w", err)
		}
	}
	if err := df.Close(); err != nil {
		return fmt.Errorf("flush and close destination file: %w", err)
	}
	df = nil
	return nil
}
