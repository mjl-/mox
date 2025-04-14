package imapclient

import (
	"fmt"
	"reflect"
	"testing"
)

func tcheckf(t *testing.T, err error, format string, args ...any) {
	if err != nil {
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

func tcompare(t *testing.T, a, b any) {
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("got:\n%#v\nexpected:\n%#v", a, b)
	}
}

func uint32ptr(v uint32) *uint32 { return &v }

func TestParse(t *testing.T) {
	code, err := ParseCode("COPYUID 1 1:3 2:4")
	tcheckf(t, err, "parsing code")
	tcompare(t, code,
		CodeCopyUID{
			DestUIDValidity: 1,
			From:            []NumRange{{First: 1, Last: uint32ptr(3)}},
			To:              []NumRange{{First: 2, Last: uint32ptr(4)}},
		},
	)

	ut, err := ParseUntagged("* BYE done\r\n")
	tcheckf(t, err, "parsing untagged")
	tcompare(t, ut, UntaggedBye{Text: "done"})

	tag, result, err := ParseResult("tag1 OK [ALERT] Hello\r\n")
	tcheckf(t, err, "parsing result")
	tcompare(t, tag, "tag1")
	tcompare(t, result, Result{Status: OK, Code: CodeWord("ALERT"), Text: "Hello"})
}
