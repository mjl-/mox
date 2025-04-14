package imapserver

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	mathrand "math/rand/v2"
	"testing"
	"time"
)

func TestCompress(t *testing.T) {
	tc := start(t, false)
	defer tc.close()

	tc.login("mjl@mox.example", password0)

	tc.transactf("bad", "compress")
	tc.transactf("bad", "compress bogus ")
	tc.transactf("no", "compress bogus")

	tc.client.CompressDeflate()
	tc.transactf("no", "compress deflate") // Cannot have multiple.
	tc.xcodeWord("COMPRESSIONACTIVE")

	tc.client.Select("inbox")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "noop")
	tc.transactf("ok", "fetch 1 body.peek[1]")
}

func TestCompressStartTLS(t *testing.T) {
	tc := start(t, false)
	defer tc.close()

	tc.client.StartTLS(&tls.Config{InsecureSkipVerify: true})
	tc.login("mjl@mox.example", password0)
	tc.client.CompressDeflate()
	tc.client.Select("inbox")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "noop")
	tc.transactf("ok", "fetch 1 body.peek[1]")
}

func TestCompressBreak(t *testing.T) {
	// Close the client connection when the server is writing. That causes writes in
	// the server to fail (panic), jumping out of the flate writer and leaving its
	// state inconsistent. We must not call into the flate writer again because due to
	// its broken internal state it may cause array out of bounds accesses.

	tc := start(t, false)
	defer tc.close()

	msg := exampleMsg
	// Add random data (so it is not compressible). Don't know why, but only
	// reproducible with large writes. As if setting socket buffers had no effect.
	buf := make([]byte, 64*1024)
	_, err := io.ReadFull(mathrand.NewChaCha8([32]byte{}), buf)
	tcheck(t, err, "read random")
	text := base64.StdEncoding.EncodeToString(buf)
	for len(text) > 0 {
		n := min(76, len(text))
		msg += text[:n] + "\r\n"
		text = text[n:]
	}

	tc.login("mjl@mox.example", password0)
	tc.client.CompressDeflate()
	tc.client.Select("inbox")
	tc.transactf("ok", "append inbox (\\seen) {%d+}\r\n%s", len(msg), msg)
	tc.transactf("ok", "noop")

	// Write request. Close connection instead of reading data. Write will panic,
	// coming through flate writer leaving its state inconsistent. Server must not try
	// to Flush/Write again on flate writer or it may panic.
	tc.client.Writelinef("x fetch 1 body.peek[1]")

	// Close client connection and prevent cleanup from closing the client again.
	time.Sleep(time.Second / 10)
	tc.client = nil
	tc.conn.Close() // Simulate client disappearing.
}
