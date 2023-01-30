package moxio

import (
	"errors"
	"syscall"
)

// In separate file because of syscall import.

// IsStorageSpace returns whether the error is for storage space issue.
// Like disk full, no inodes, quota reached.
func IsStorageSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
