package moxio

import (
	"fmt"
	"io"
	"os"

	"github.com/mjl-/mox/mlog"
)

// LinkOrCopy attempts to make a hardlink dst. If that fails, it will try to do a
// regular file copy. If srcReaderOpt is not nil, it will be used for reading. If
// sync is true and the file is copied, Sync is called on the file after writing to
// ensure the file is written on disk. Callers should also sync the directory of
// the destination file, but may want to do that after linking/copying multiple
// files. If dst was created and an error occurred, it is removed.
func LinkOrCopy(log *mlog.Log, dst, src string, srcReaderOpt io.Reader, sync bool) (rerr error) {
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
			err = os.Remove(dst)
			log.Check(err, "removing partial destination file")
			err = df.Close()
			log.Check(err, "closing partial destination file")
		}
	}()

	if _, err := io.Copy(df, srcReaderOpt); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	if sync {
		if err := df.Sync(); err != nil {
			return fmt.Errorf("sync destination: %w", err)
		}
	}
	err = df.Close()
	df = nil
	if err != nil {
		err := os.Remove(dst)
		log.Check(err, "removing partial destination file")
		return err
	}
	return nil
}
