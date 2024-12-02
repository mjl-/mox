package store

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/updates"
)

// StoreLastKnown stores the the last known version. Future update checks compare
// against it, or the currently running version, whichever is newer.
func StoreLastKnown(v updates.Version) error {
	return os.WriteFile(mox.DataDirPath("lastknownversion"), []byte(v.String()), 0660)
}

// LastKnown returns the last known version that has been mentioned in an update
// email, or the current application.
func LastKnown() (current, lastknown updates.Version, mtime time.Time, rerr error) {
	curv, curerr := updates.ParseVersion(moxvar.VersionBare)

	p := mox.DataDirPath("lastknownversion")
	fi, _ := os.Stat(p)
	if fi != nil {
		mtime = fi.ModTime()
	}

	vbuf, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return curv, updates.Version{}, mtime, err
	}

	lastknown, lasterr := updates.ParseVersion(strings.TrimSpace(string(vbuf)))

	if curerr == nil && lasterr == nil {
		if curv.After(lastknown) {
			return curv, curv, mtime, nil
		}
		return curv, lastknown, mtime, nil
	} else if curerr == nil {
		return curv, curv, mtime, nil
	} else if lasterr == nil {
		return curv, lastknown, mtime, nil
	}
	if strings.HasPrefix(moxvar.Version, "(devel)") {
		return curv, updates.Version{}, mtime, fmt.Errorf("development version")
	}
	return curv, updates.Version{}, mtime, fmt.Errorf("parsing version: %w", err)
}
