package mox

import (
	"errors"
	"os"
	"runtime"
)

// todo: perhaps find and document the recommended way to get this on other platforms?

// LinuxSetcapHint returns a hint about using setcap for binding to privileged
// ports, only if relevant the error and GOOS (Linux).
func LinuxSetcapHint(err error) string {
	if runtime.GOOS == "linux" && errors.Is(err, os.ErrPermission) {
		return " (privileged port? try again after: sudo setcap 'cap_net_bind_service=+ep' mox)"
	}
	return ""
}
