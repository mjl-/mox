package sherpa

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Int64s is an int64 that can be read as either a JSON string or JSON number, to
// be used in sherpa function parameters for compatibility with JavaScript.
// For struct fields, use the "json:,string" struct tag instead.
type Int64s int64

// Int returns the int64 value.
func (i Int64s) Int() int64 {
	return int64(i)
}

// MarshalJSON returns a JSON-string-encoding of the int64.
func (i *Int64s) MarshalJSON() ([]byte, error) {
	var v int64
	if i != nil {
		v = int64(*i)
	}
	return json.Marshal(fmt.Sprintf("%d", v))
}

// UnmarshalJSON parses JSON into the int64. Both a string encoding as a number
// encoding are allowed. JavaScript clients must use the string encoding because
// the number encoding loses precision at 1<<53.
func (i *Int64s) UnmarshalJSON(buf []byte) error {
	var s string
	if len(buf) > 0 && buf[0] == '"' {
		err := json.Unmarshal(buf, &s)
		if err != nil {
			return err
		}
	} else {
		s = string(buf)
	}
	vv, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*i = Int64s(vv)
	return nil
}

// Uint64s is an uint64 that can be read as either a JSON string or JSON number, to
// be used in sherpa function parameters for compatibility with JavaScript.
// For struct fields, use the "json:,string" struct tag instead.
type Uint64s uint64

// Int returns the uint64 value.
func (i Uint64s) Int() uint64 {
	return uint64(i)
}

// MarshalJSON returns a JSON-string-encoding of the uint64.
func (i *Uint64s) MarshalJSON() ([]byte, error) {
	var v uint64
	if i != nil {
		v = uint64(*i)
	}
	return json.Marshal(fmt.Sprintf("%d", v))
}

// UnmarshalJSON parses JSON into the uint64. Both a string encoding as a number
// encoding are allowed. JavaScript clients must use the string encoding because
// the number encoding loses precision at 1<<53.
func (i *Uint64s) UnmarshalJSON(buf []byte) error {
	var s string
	if len(buf) > 0 && buf[0] == '"' {
		err := json.Unmarshal(buf, &s)
		if err != nil {
			return err
		}
	} else {
		s = string(buf)
	}
	vv, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*i = Uint64s(vv)
	return nil
}
