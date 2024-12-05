package mox

import (
	"errors"
	"net"
	"reflect"
)

func AsTLSAlert(err error) (alert uint8, ok bool) {
	// If the remote client aborts the connection, it can send an alert indicating why.
	// crypto/tls gives us a net.OpError with "Op" set to "remote error", an an Err
	// with the unexported type "alert", a uint8. So we try to read it.

	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return
	}
	v := reflect.ValueOf(opErr.Err)
	if v.Kind() != reflect.Uint8 || v.Type().Name() != "alert" {
		return
	}
	return uint8(v.Uint()), true
}
