package imapserver

import (
	"crypto/tls"
	"testing"
)

func TestCompress(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Login("mjl@mox.example", password0)

	tc.transactf("bad", "compress")
	tc.transactf("bad", "compress bogus ")
	tc.transactf("no", "compress bogus")

	tc.client.CompressDeflate()
	tc.transactf("no", "compress deflate") // Cannot have multiple.
	tc.xcode("COMPRESSIONACTIVE")

	tc.client.Select("inbox")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "noop")
	tc.transactf("ok", "fetch 1 body.peek[1]")
}

func TestCompressStartTLS(t *testing.T) {
	tc := start(t)
	defer tc.close()

	tc.client.Starttls(&tls.Config{InsecureSkipVerify: true})
	tc.client.Login("mjl@mox.example", password0)
	tc.client.CompressDeflate()
	tc.client.Select("inbox")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "noop")
	tc.transactf("ok", "fetch 1 body.peek[1]")
}
