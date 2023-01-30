package store

import (
	"github.com/mjl-/bstore"
)

// todo: get rid of this. it's a bad idea to indiscriminately turn all panics into an error.
func extransact(db *bstore.DB, write bool, fn func(tx *bstore.Tx) error) (rerr error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok {
			rerr = err
		} else {
			panic(x)
		}
	}()
	if write {
		return db.Write(fn)
	}
	return db.Read(fn)
}
