package message_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

func ExampleDecodeReader() {
	// Convert from iso-8859-1 to utf-8.
	input := []byte{'t', 0xe9, 's', 't'}
	output, err := io.ReadAll(message.DecodeReader("iso-8859-1", bytes.NewReader(input)))
	if err != nil {
		log.Fatalf("read from decoder: %v", err)
	}
	fmt.Printf("%s\n", string(output))
	// Output: tést
}

func ExampleMessageIDCanonical() {
	// Valid message-id.
	msgid, invalidAddress, err := message.MessageIDCanonical("<ok@localhost>")
	if err != nil {
		fmt.Printf("invalid message-id: %v\n", err)
	} else {
		fmt.Printf("canonical: %s %v\n", msgid, invalidAddress)
	}

	// Missing <>.
	msgid, invalidAddress, err = message.MessageIDCanonical("bogus@localhost")
	if err != nil {
		fmt.Printf("invalid message-id: %v\n", err)
	} else {
		fmt.Printf("canonical: %s %v\n", msgid, invalidAddress)
	}

	// Invalid address, but returned as not being in error.
	msgid, invalidAddress, err = message.MessageIDCanonical("<invalid>")
	if err != nil {
		fmt.Printf("invalid message-id: %v\n", err)
	} else {
		fmt.Printf("canonical: %s %v\n", msgid, invalidAddress)
	}

	// Output:
	// canonical: ok@localhost false
	// invalid message-id: not a message-id: missing <
	// canonical: invalid true
}

func ExampleThreadSubject() {
	// Basic subject.
	s, isResp := message.ThreadSubject("nothing special", false)
	fmt.Printf("%s, response: %v\n", s, isResp)

	// List tags and "re:" are stripped.
	s, isResp = message.ThreadSubject("[list1] [list2] Re: test", false)
	fmt.Printf("%s, response: %v\n", s, isResp)

	// "fwd:" is stripped.
	s, isResp = message.ThreadSubject("fwd: a forward", false)
	fmt.Printf("%s, response: %v\n", s, isResp)

	// Trailing "(fwd)" is also a forward.
	s, isResp = message.ThreadSubject("another forward (fwd)", false)
	fmt.Printf("%s, response: %v\n", s, isResp)

	// [fwd: ...] is stripped.
	s, isResp = message.ThreadSubject("[fwd: [list] fwd: re: it's complicated]", false)
	fmt.Printf("%s, response: %v\n", s, isResp)

	// Output:
	// nothing special, response: false
	// test, response: true
	// a forward, response: true
	// another forward, response: true
	// it's complicated, response: true
}

func ExampleComposer() {
	// We store in a buffer. We could also write to a file.
	var b bytes.Buffer

	// NewComposer. Keep in mind that operations on a Composer will panic on error.
	xc := message.NewComposer(&b, 10*1024*1024)

	// Catch and handle errors when composing.
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if err, ok := x.(error); ok && errors.Is(err, message.ErrCompose) {
			log.Printf("compose: %v", err)
		}
		panic(x)
	}()

	// Add an address header.
	xc.HeaderAddrs("From", []message.NameAddress{{DisplayName: "Charlie", Address: smtp.Address{Localpart: "root", Domain: dns.Domain{ASCII: "localhost"}}}})

	// Add subject header, with encoding
	xc.Subject("hi ☺")

	// Add Date and Message-ID headers, required.
	tm, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")
	xc.Header("Date", tm.Format(message.RFC5322Z))
	xc.Header("Message-ID", "<unique@host>") // Should generate unique id for each message.

	xc.Header("MIME-Version", "1.0")

	// Write content-* headers for the text body.
	body, ct, cte := xc.TextPart("this is the body")
	xc.Header("Content-Type", ct)
	xc.Header("Content-Transfer-Encoding", cte)

	// Header/Body separator
	xc.Line()

	// The part body. Use mime/multipart to make messages with multiple parts.
	xc.Write(body)

	// Flush any buffered writes to the original writer.
	xc.Flush()

	fmt.Println(strings.ReplaceAll(b.String(), "\r\n", "\n"))
	// Output:
	// From: "Charlie" <root@localhost>
	// Subject: hi =?utf-8?q?=E2=98=BA?=
	// Date: 2 Jan 2006 15:04:05 +0700
	// Message-ID: <unique@host>
	// MIME-Version: 1.0
	// Content-Type: text/plain; charset=us-ascii
	// Content-Transfer-Encoding: 7bit
	//
	// this is the body
}

func ExamplePart() {
	// Parse a message from an io.ReaderAt, which could be a file.
	strict := false
	r := strings.NewReader("header: value\r\nanother: value\r\n\r\nbody ...\r\n")
	part, err := message.Parse(slog.Default(), strict, r)
	if err != nil {
		log.Fatalf("parsing message: %v", err)
	}

	// The headers of the first part have been parsed, i.e. the message headers.
	// A message can be multipart (e.g. alternative, related, mixed), and possibly
	// nested.

	// By walking the entire message, all part metadata (like offsets into the file
	// where a part starts) is recorded.
	err = part.Walk(slog.Default(), nil)
	if err != nil {
		log.Fatalf("walking message: %v", err)
	}

	// Messages can have a recursive multipart structure. Print the structure.
	var printPart func(indent string, p message.Part)
	printPart = func(indent string, p message.Part) {
		log.Printf("%s- part: %v", indent, part)
		for _, pp := range p.Parts {
			printPart("  "+indent, pp)
		}
	}
	printPart("", part)
}

func ExampleWriter() {
	// NewWriter on a string builder.
	var b strings.Builder
	w := message.NewWriter(&b)

	// Write some lines, some with proper CRLF line ending, others without.
	fmt.Fprint(w, "header: value\r\n")
	fmt.Fprint(w, "another: value\n") // missing \r
	fmt.Fprint(w, "\r\n")
	fmt.Fprint(w, "hi ☺\n") // missing \r

	fmt.Printf("%q\n", b.String())
	fmt.Printf("%v %v", w.HaveBody, w.Has8bit)
	// Output:
	// "header: value\r\nanother: value\r\n\r\nhi ☺\r\n"
	// true true
}
