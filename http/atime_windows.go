//go:build windows

package http

import (
	"fmt"
	"syscall"
)

func statAtime(sys any) (int64, error) {
	x, ok := sys.(*syscall.Win32FileAttributeData)
	if !ok {
		return 0, fmt.Errorf("sys is a %T, expected *syscall.Win32FileAttributeData", sys)
	}
	return x.LastAccessTime.Nanoseconds(), nil
}
