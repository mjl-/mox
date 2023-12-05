//go:build !windows

package moxio

import (
	"fmt"
	"os"

	"github.com/mjl-/mox/mlog"
)

// SyncDir opens a directory and syncs its contents to disk.
func SyncDir(log mlog.Log, dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory: %v", err)
	}
	err = d.Sync()
	xerr := d.Close()
	log.Check(xerr, "closing directory after sync")
	return err
}
