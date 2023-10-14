//go:build netbsd || freebsd || darwin

package http

import (
	"fmt"
	"syscall"
)

func statAtime(sys any) (int64, error) {
	x, ok := sys.(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat sys is a %T, expected *syscall.Stat_t", sys)
	}
	return int64(x.Atimespec.Sec)*1000*1000*1000 + int64(x.Atimespec.Nsec), nil
}
