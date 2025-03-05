package mox

import (
	"strings"
)

// ParentMailboxName returns the name of the parent mailbox, returning empty if
// there is no parent.
func ParentMailboxName(name string) string {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return ""
	}
	return name[:i]
}
