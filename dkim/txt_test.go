package dkim

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
)

func TestParseRecord(t *testing.T) {
	test := func(txt string, expRec *Record, expIsDKIM bool, expErr error) {
		t.Helper()

		isParseErr := func(err error) bool {
			_, ok := err.(parseErr)
			return ok
		}

		r, isdkim, err := ParseRecord(txt)
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr) && !(isParseErr(err) && isParseErr(expErr)) {
			t.Fatalf("parsing record: got error %v %#v, expected %#v, txt %q", err, err, expErr, txt)
		}
		if isdkim != expIsDKIM {
			t.Fatalf("got isdkim %v, expected %v", isdkim, expIsDKIM)
		}
		if r != nil && expRec != nil {
			expRec.PublicKey = r.PublicKey
		}
		if !reflect.DeepEqual(r, expRec) {
			t.Fatalf("got record %#v, expected %#v, for txt %q", r, expRec, txt)
		}
		if r != nil {
			pk := r.Pubkey
			for i := 0; i < 2; i++ {
				ntxt, err := r.Record()
				if err != nil {
					t.Fatalf("making record: %v", err)
				}
				nr, _, _ := ParseRecord(ntxt)
				r.Pubkey = pk
				if !reflect.DeepEqual(r, nr) {
					t.Fatalf("after packing and parsing, got %#v, expected %#v", nr, r)
				}

				// Generate again, now based on parsed public key.
				pk = r.Pubkey
				r.Pubkey = nil
			}
		}
	}

	xbase64 := func(s string) []byte {
		t.Helper()
		buf, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("parsing base64: %v", err)
		}
		return buf
	}

	test("", nil, false, parseErr(""))
	test("v=DKIM1", nil, true, errRecordMissingField) // Missing p=.
	test("p=; v=DKIM1", nil, true, errRecordVersionFirst)
	test("v=DKIM1; p=; ", nil, true, parseErr(""))                                                    // Whitespace after last ; is not allowed.
	test("v=dkim1; p=; ", nil, false, parseErr(""))                                                   // dkim1-value is case-sensitive.
	test("v=DKIM1; p=JDcbZ0Hpba5NKXI4UAW3G0IDhhFOxhJTDybZEwe1FeA=", nil, true, errRecordBadPublicKey) // Not an rsa key.
	test("v=DKIM1; p=; p=", nil, true, errRecordDuplicateTag)                                         // Duplicate tag.
	test("v=DKIM1; k=ed25519; p=HbawiMnQXTCopHTkR0jlKQ==", nil, true, errRecordBadPublicKey)          // Short key.
	test("v=DKIM1; k=unknown; p=", nil, true, errRecordUnknownAlgorithm)

	empty := &Record{
		Version:  "DKIM1",
		Key:      "rsa",
		Services: []string{"*"},
		Pubkey:   []uint8{},
	}
	test("V=DKIM2; p=;", empty, true, nil) // Tag names are case-sensitive.

	record := &Record{
		Version:  "DKIM1",
		Hashes:   []string{"sha1", "SHA256", "unknown"},
		Key:      "ed25519",
		Notes:    "notes...",
		Pubkey:   xbase64("JDcbZ0Hpba5NKXI4UAW3G0IDhhFOxhJTDybZEwe1FeA="),
		Services: []string{"email", "tlsrpt"},
		Flags:    []string{"y", "t"},
	}
	test("v = DKIM1 ;   h\t=\tsha1 \t:\t SHA256:unknown\t;k=ed25519; n = notes...; p = JDc bZ0Hpb a5NK\tXI4UAW3G0IDhhFOxhJTDybZEwe1FeA=  ;s = email : tlsrpt; t = y\t: t; unknown = bogus;", record, true, nil)

	edpkix, err := x509.MarshalPKIXPublicKey(record.PublicKey)
	if err != nil {
		t.Fatalf("marshal ed25519 public key")
	}
	recordx := &Record{
		Version: "DKIM1",
		Key:     "rsa",
		Pubkey:  edpkix,
	}
	txtx, err := recordx.Record()
	if err != nil {
		t.Fatalf("making record: %v", err)
	}
	test(txtx, nil, true, errRecordBadPublicKey)

	record2 := &Record{
		Version:  "DKIM1",
		Key:      "rsa",
		Services: []string{"*"},
		Pubkey:   xbase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3Z9ffZe8gUTJrdGuKj6IwEembmKYpp0jMa8uhudErcI4gFVUaFiiRWxc4jP/XR9NAEv3XwHm+CVcHu+L/n6VWt6g59U7vHXQicMfKGmEp2VplsgojNy/Y5X9HdVYM0azsI47NcJCDW9UVfeOHdOSgFME4F8dNtUKC4KTB2d1pqj/yixz+V8Sv8xkEyPfSRHcNXIw0LvelqJ1MRfN3hO/3uQSVrPYYk4SyV0b6wfnkQs28fpiIpGQvzlGI5WkrdOQT5k4YHaEvZDLNdwiMeVZOEL7dDoFs2mQsovm+tH0StUAZTnr61NLVFfD5V6Ip1V9zVtspPHvYSuOWwyArFZ9QIDAQAB"),
	}
	test("v=DKIM1;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3Z9ffZe8gUTJrdGuKj6IwEembmKYpp0jMa8uhudErcI4gFVUaFiiRWxc4jP/XR9NAEv3XwHm+CVcHu+L/n6VWt6g59U7vHXQicMfKGmEp2VplsgojNy/Y5X9HdVYM0azsI47NcJCDW9UVfeOHdOSgFME4F8dNtUKC4KTB2d1pqj/yixz+V8Sv8xkEyPfSRHcNXIw0LvelqJ1MRfN3hO/3uQSVrPYYk4SyV0b6wfnkQs28fpiIpGQvzlGI5WkrdOQT5k4YHaEvZDLNdwiMeVZOEL7dDoFs2mQsovm+tH0StUAZTnr61NLVFfD5V6Ip1V9zVtspPHvYSuOWwyArFZ9QIDAQAB", record2, true, nil)

}

func TestQPSection(t *testing.T) {
	var tests = []struct {
		input  string
		expect string
	}{
		{"test", "test"},
		{"hi=", "hi=3D"},
		{"hi there", "hi there"},
		{" hi", "=20hi"},
		{"t\x7f", "t=7F"},
	}
	for _, v := range tests {
		r := qpSection(v.input)
		if r != v.expect {
			t.Fatalf("qpSection: input %q, expected %q, got %q", v.input, v.expect, r)
		}
	}
}
