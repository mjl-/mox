package mox

import (
	"sync/atomic"
	"time"
)

var cid atomic.Int64

func init() {
	cid.Store(time.Now().UnixMilli())
}

// Cid returns a new unique id to be used for connections/sessions/requests.
func Cid() int64 {
	return cid.Add(1)
}
