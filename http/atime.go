//go:build !netbsd && !freebsd && !darwin

package http

import "syscall"

func statAtime(sys *syscall.Stat_t) int64 {
	return int64(sys.Atim.Sec)*1000*1000*1000 + int64(sys.Atim.Nsec)
}
