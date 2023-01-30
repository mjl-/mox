package message

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func tcompare(t *testing.T, got, exp any) {
	t.Helper()
	if !reflect.DeepEqual(got, exp) {
		t.Fatalf("got %q, expected %q", got, exp)
	}
}

func tfail(t *testing.T, err, expErr error) {
	t.Helper()
	if (err == nil) != (expErr == nil) || expErr != nil && !errors.Is(err, expErr) {
		t.Fatalf("got err %v, expected %v", err, expErr)
	}
}

func TestEmptyHeader(t *testing.T) {
	s := "\r\nx"
	p, err := EnsurePart(strings.NewReader(s), int64(len(s)))
	tcheck(t, err, "parse empty headers")
	buf, err := io.ReadAll(p.Reader())
	tcheck(t, err, "read")
	expBody := "x"
	tcompare(t, string(buf), expBody)
	tcompare(t, p.MediaType, "")
	tcompare(t, p.MediaSubType, "")
}

func TestBadContentType(t *testing.T) {
	s := "content-type: text/html;;\r\n\r\ntest"
	p, err := EnsurePart(strings.NewReader(s), int64(len(s)))
	tfail(t, err, ErrBadContentType)
	buf, err := io.ReadAll(p.Reader())
	tcheck(t, err, "read")
	expBody := "test"
	tcompare(t, string(buf), expBody)
	tcompare(t, p.MediaType, "APPLICATION")
	tcompare(t, p.MediaSubType, "OCTET-STREAM")
}

var basicMsg = strings.ReplaceAll(`From: <mjl@mox.example>
Content-Type: text/plain
Content-Transfer-Encoding: base64

aGkK
`, "\n", "\r\n")

func TestBasic(t *testing.T) {
	r := strings.NewReader(basicMsg)
	p, err := Parse(r)
	tcheck(t, err, "new reader")

	buf, err := io.ReadAll(p.RawReader())
	tcheck(t, err, "read raw")
	expBody := "aGkK\r\n"
	tcompare(t, string(buf), expBody)

	buf, err = io.ReadAll(p.Reader())
	tcheck(t, err, "read decoded")
	tcompare(t, string(buf), "hi\r\n")

	if p.RawLineCount != 1 {
		t.Fatalf("basic message, got %d lines, expected 1", p.RawLineCount)
	}
	if size := p.EndOffset - p.BodyOffset; size != int64(len(expBody)) {
		t.Fatalf("basic message, got size %d, expected %d", size, len(expBody))
	}
}

// From ../rfc/3501:2589
var basicMsg2 = strings.ReplaceAll(`Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)
From: Fred Foobar <foobar@Blurdybloop.example>
Subject: afternoon meeting
To: mooch@owatagu.siam.edu.example
Message-Id: <B27397-0100000@Blurdybloop.example>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII

Hello Joe, do you think we can meet at 3:30 tomorrow?

`, "\n", "\r\n")

func TestBasic2(t *testing.T) {
	r := strings.NewReader(basicMsg2)
	p, err := Parse(r)
	tcheck(t, err, "new reader")

	buf, err := io.ReadAll(p.RawReader())
	tcheck(t, err, "read raw")
	expBody := "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n\r\n"
	tcompare(t, string(buf), expBody)

	buf, err = io.ReadAll(p.Reader())
	tcheck(t, err, "read decoded")
	tcompare(t, string(buf), expBody)

	if p.RawLineCount != 2 {
		t.Fatalf("basic message, got %d lines, expected 2", p.RawLineCount)
	}
	if size := p.EndOffset - p.BodyOffset; size != int64(len(expBody)) {
		t.Fatalf("basic message, got size %d, expected %d", size, len(expBody))
	}

	r = strings.NewReader(basicMsg2)
	p, err = Parse(r)
	tcheck(t, err, "new reader")
	err = p.Walk()
	tcheck(t, err, "walk")
	if p.RawLineCount != 2 {
		t.Fatalf("basic message, got %d lines, expected 2", p.RawLineCount)
	}
	if size := p.EndOffset - p.BodyOffset; size != int64(len(expBody)) {
		t.Fatalf("basic message, got size %d, expected %d", size, len(expBody))
	}
}

var mimeMsg = strings.ReplaceAll(`From: Nathaniel Borenstein <nsb@bellcore.com>
To: Ned Freed <ned@innosoft.com>
Date: Sun, 21 Mar 1993 23:56:48 -0800 (PST)
Subject: Sample message
MIME-Version: 1.0
Content-type: multipart/mixed; boundary="simple boundary"

This is the preamble.  It is to be ignored, though it
is a handy place for composition agents to include an
explanatory note to non-MIME conformant readers.

--simple boundary

This is implicitly typed plain US-ASCII text.
It does NOT end with a linebreak.
--simple boundary
Content-type: text/plain; charset=us-ascii

This is explicitly typed plain US-ASCII text.
It DOES end with a linebreak.

--simple boundary--

This is the epilogue.  It is also to be ignored.
`, "\n", "\r\n")

func TestMime(t *testing.T) {
	// from ../rfc/2046:1148
	r := strings.NewReader(mimeMsg)
	p, err := Parse(r)
	tcheck(t, err, "new reader")
	if len(p.bound) == 0 {
		t.Fatalf("got no bound, expected bound for mime message")
	}

	pp, err := p.ParseNextPart()
	tcheck(t, err, "next part")
	buf, err := io.ReadAll(pp.Reader())
	tcheck(t, err, "read all")
	tcompare(t, string(buf), "This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak.")

	pp, err = p.ParseNextPart()
	tcheck(t, err, "next part")
	buf, err = io.ReadAll(pp.Reader())
	tcheck(t, err, "read all")
	tcompare(t, string(buf), "This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n")

	_, err = p.ParseNextPart()
	tcompare(t, err, io.EOF)

	if len(p.Parts) != 2 {
		t.Fatalf("got %d parts, expected 2", len(p.Parts))
	}
	if p.Parts[0].RawLineCount != 2 {
		t.Fatalf("got %d lines for first part, expected 2", p.Parts[0].RawLineCount)
	}
	if p.Parts[1].RawLineCount != 2 {
		t.Fatalf("got %d lines for second part, expected 2", p.Parts[1].RawLineCount)
	}
}

func TestLongLine(t *testing.T) {
	line := make([]byte, maxLineLength+1)
	for i := range line {
		line[i] = 'a'
	}
	_, err := Parse(bytes.NewReader(line))
	tfail(t, err, errLineTooLong)
}

func TestHalfCrLf(t *testing.T) {
	_, err := Parse(strings.NewReader("test\rtest"))
	tfail(t, err, errHalfLineSep)

	_, err = Parse(strings.NewReader("test\ntest"))
	tfail(t, err, errHalfLineSep)
}

func TestMissingClosingBoundary(t *testing.T) {
	message := strings.ReplaceAll(`Content-Type: multipart/mixed; boundary=x

--x

test
`, "\n", "\r\n")
	msg, err := Parse(strings.NewReader(message))
	tcheck(t, err, "new reader")
	err = walkmsg(&msg)
	tfail(t, err, errMissingClosingBoundary)

	msg, _ = Parse(strings.NewReader(message))
	err = msg.Walk()
	tfail(t, err, errMissingClosingBoundary)
}

func TestHeaderEOF(t *testing.T) {
	message := "header: test"
	_, err := Parse(strings.NewReader(message))
	tfail(t, err, errUnexpectedEOF)
}

func TestBodyEOF(t *testing.T) {
	message := "header: test\r\n\r\ntest"
	msg, err := Parse(strings.NewReader(message))
	tcheck(t, err, "new reader")
	buf, err := io.ReadAll(msg.Reader())
	tcheck(t, err, "read body")
	tcompare(t, string(buf), "test")
}

func TestWalk(t *testing.T) {
	var message = strings.ReplaceAll(`Content-Type: multipart/related; boundary="----=_NextPart_afb3ad6f146b12b709deac3e387a3ad7"

------=_NextPart_afb3ad6f146b12b709deac3e387a3ad7
Content-Type: multipart/alternative; boundary="----=_NextPart_afb3ad6f146b12b709deac3e387a3ad7_alt"

------=_NextPart_afb3ad6f146b12b709deac3e387a3ad7_alt
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

test


------=_NextPart_afb3ad6f146b12b709deac3e387a3ad7_alt
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 8bit

test

------=_NextPart_afb3ad6f146b12b709deac3e387a3ad7_alt--
------=_NextPart_afb3ad6f146b12b709deac3e387a3ad7--

`, "\n", "\r\n")

	msg, err := Parse(strings.NewReader(message))
	tcheck(t, err, "new reader")
	enforceSequential = true
	defer func() {
		enforceSequential = false
	}()
	err = walkmsg(&msg)
	tcheck(t, err, "walkmsg")

	msg, _ = Parse(strings.NewReader(message))
	err = msg.Walk()
	tcheck(t, err, "msg.Walk")
}

func TestNested(t *testing.T) {
	// From ../rfc/2049:801
	nestedMessage := strings.ReplaceAll(`MIME-Version: 1.0
From: Nathaniel Borenstein <nsb@nsb.fv.com>
To: Ned Freed <ned@innosoft.com>
Date: Fri, 07 Oct 1994 16:15:05 -0700 (PDT)
Subject: A multipart example
Content-Type: multipart/mixed;
              boundary=unique-boundary-1

This is the preamble area of a multipart message.
Mail readers that understand multipart format
should ignore this preamble.

If you are reading this text, you might want to
consider changing to a mail reader that understands
how to properly display multipart messages.

--unique-boundary-1

  ... Some text appears here ...

[Note that the blank between the boundary and the start
 of the text in this part means no header fields were
 given and this is text in the US-ASCII character set.
 It could have been done with explicit typing as in the
 next part.]

--unique-boundary-1
Content-type: text/plain; charset=US-ASCII

This could have been part of the previous part, but
illustrates explicit versus implicit typing of body
parts.

--unique-boundary-1
Content-Type: multipart/parallel; boundary=unique-boundary-2

--unique-boundary-2
Content-Type: audio/basic
Content-Transfer-Encoding: base64


--unique-boundary-2
Content-Type: image/jpeg
Content-Transfer-Encoding: base64


--unique-boundary-2--

--unique-boundary-1
Content-type: text/enriched

This is <bold><italic>enriched.</italic></bold>
<smaller>as defined in RFC 1896</smaller>

Isn't it
<bigger><bigger>cool?</bigger></bigger>

--unique-boundary-1
Content-Type: message/rfc822

From: (mailbox in US-ASCII)
To: (address in US-ASCII)
Subject: (subject in US-ASCII)
Content-Type: Text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: Quoted-printable

  ... Additional text in ISO-8859-1 goes here ...

--unique-boundary-1--
`, "\n", "\r\n")

	msg, err := Parse(strings.NewReader(nestedMessage))
	tcheck(t, err, "new reader")
	enforceSequential = true
	defer func() {
		enforceSequential = false
	}()
	err = walkmsg(&msg)
	tcheck(t, err, "walkmsg")

	if len(msg.Parts) != 5 {
		t.Fatalf("got %d parts, expected 5", len(msg.Parts))
	}
	sub := msg.Parts[4].Message
	if sub == nil {
		t.Fatalf("missing part.Message")
	}
	buf, err := io.ReadAll(sub.Reader())
	if err != nil {
		t.Fatalf("read message body: %v", err)
	}
	exp := "  ... Additional text in ISO-8859-1 goes here ...\r\n"
	if string(buf) != exp {
		t.Fatalf("got %q, expected %q", buf, exp)
	}

	msg, _ = Parse(strings.NewReader(nestedMessage))
	err = msg.Walk()
	tcheck(t, err, "msg.Walk")

}

func TestWalkdir(t *testing.T) {
	// Ensure these dirs exist. Developers should bring their own ham/spam example
	// emails.
	os.MkdirAll("../testdata/train/ham", 0770)
	os.MkdirAll("../testdata/train/spam", 0770)

	var n, nfail int
	twalkdir(t, "../testdata/train/ham", &n, &nfail)
	twalkdir(t, "../testdata/train/spam", &n, &nfail)
	log.Printf("parsing messages: %d/%d failed", nfail, n)
}

func twalkdir(t *testing.T, dir string, n, nfail *int) {
	names, err := os.ReadDir(dir)
	tcheck(t, err, "readdir")
	if len(names) > 1000 {
		names = names[:1000]
	}
	for _, name := range names {
		p := filepath.Join(dir, name.Name())
		*n++
		err := walk(p)
		if err != nil {
			*nfail++
			log.Printf("%s: %v", p, err)
		}
	}
}

func walk(path string) error {
	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	msg, err := Parse(r)
	if err != nil {
		return err
	}
	return walkmsg(&msg)
}

func walkmsg(msg *Part) error {
	enforceSequential = true
	defer func() {
		enforceSequential = false
	}()

	if len(msg.bound) == 0 {
		buf, err := io.ReadAll(msg.Reader())
		if err != nil {
			return err
		}

		if msg.MediaType == "MESSAGE" && (msg.MediaSubType == "RFC822" || msg.MediaSubType == "GLOBAL") {
			mp, err := Parse(bytes.NewReader(buf))
			if err != nil {
				return err
			}
			msg.Message = &mp
			walkmsg(msg.Message)
		}

		size := msg.EndOffset - msg.BodyOffset
		if size < 0 {
			log.Printf("msg %v", msg)
			panic("inconsistent body/end offset")
		}
		sr := io.NewSectionReader(msg.r, msg.BodyOffset, size)
		decsr := msg.bodyReader(sr)
		buf2, err := io.ReadAll(decsr)
		if err != nil {
			return err
		}

		if !bytes.Equal(buf, buf2) {
			panic("data mismatch reading sequentially vs via offsets")
		}

		return nil
	}

	for {
		pp, err := msg.ParseNextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := walkmsg(pp); err != nil {
			return err
		}
		enforceSequential = true
	}
}

func TestEmbedded(t *testing.T) {
	f, err := os.Open("../testdata/message/message-rfc822-multipart.eml")
	tcheck(t, err, "open")
	fi, err := f.Stat()
	tcheck(t, err, "stat")
	_, err = EnsurePart(f, fi.Size())
	tcheck(t, err, "parse")
}

func TestEmbedded2(t *testing.T) {
	buf, err := os.ReadFile("../testdata/message/message-rfc822-multipart2.eml")
	tcheck(t, err, "readfile")
	buf = bytes.ReplaceAll(buf, []byte("\n"), []byte("\r\n"))

	_, err = EnsurePart(bytes.NewReader(buf), int64(len(buf)))
	tfail(t, err, errUnexpectedEOF) // todo: be able to parse this without an error? truncate message/rfc822 in dsn.
}
