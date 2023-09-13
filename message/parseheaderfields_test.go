package message

import (
	"net/textproto"
	"reflect"
	"strings"
	"testing"
)

func TestParseHeaderFields(t *testing.T) {
	check := func(headers string, fields []string, expHdrs textproto.MIMEHeader, expErr error) {
		t.Helper()

		buffields := [][]byte{}
		for _, f := range fields {
			buffields = append(buffields, []byte(f))
		}

		scratches := [][]byte{
			make([]byte, 0),
			make([]byte, 4*1024),
		}
		for _, scratch := range scratches {
			hdrs, err := ParseHeaderFields([]byte(strings.ReplaceAll(headers, "\n", "\r\n")), scratch, buffields)
			if !reflect.DeepEqual(hdrs, expHdrs) || !reflect.DeepEqual(err, expErr) {
				t.Fatalf("got %v %v, expected %v %v", hdrs, err, expHdrs, expErr)
			}
		}
	}

	check("", []string{"subject"}, textproto.MIMEHeader(nil), nil)
	check("Subject: test\n", []string{"subject"}, textproto.MIMEHeader{"Subject": []string{"test"}}, nil)
	check("References: <id@host>\nOther: ignored\nSubject: first\nSubject: test\n\tcontinuation\n", []string{"subject", "REFERENCES"}, textproto.MIMEHeader{"References": []string{"<id@host>"}, "Subject": []string{"first", "test continuation"}}, nil)
	check(":\n", []string{"subject"}, textproto.MIMEHeader(nil), nil)
	check("bad\n", []string{"subject"}, textproto.MIMEHeader(nil), nil)
	check("subject: test\n continuation without end\n", []string{"subject"}, textproto.MIMEHeader{"Subject": []string{"test continuation without end"}}, nil)
	check("subject: test\n", []string{"subject"}, textproto.MIMEHeader{"Subject": []string{"test"}}, nil)
	check("subject \t: test\n", []string{"subject"}, textproto.MIMEHeader(nil), nil) // Note: In go1.20, this would be interpreted as valid "Subject" header. Not in go1.21.
	// note: in go1.20, missing end of line would cause it to be ignored, in go1.21 it is used.
}
