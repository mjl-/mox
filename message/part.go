package message

// todo: we should be more forgiving when parsing, at least as an option for imported messages, possibly incoming as well, but not for submitted/outgoing messages.
// todo: allow more invalid content-type values, we now stop parsing on: empty media type (eg "content-type: ; name=..."), empty value for property (eg "charset=", missing quotes for characters that should be quoted (eg boundary containing "=" but without quotes), duplicate properties (two charsets), empty pairs (eg "text/html;;").
// todo: what should our max line length be? rfc says 1000. messages exceed that. we should enforce 1000 for outgoing messages.
// todo: should we be forgiving when closing boundary in multipart message is missing? seems like spam messages do this...
// todo: allow bare \r (without \n)? this does happen in messages.
// todo: should we allow base64 messages where a line starts with a space? and possibly more whitespace. is happening in messages. coreutils base64 accepts it, encoding/base64 does not.
// todo: handle comments in headers?
// todo: should we just always store messages with \n instead of \r\n? \r\n seems easier for use with imap.
// todo: is a header always \r\n\r\n-separated? or is \r\n enough at the beginning of a file? because what would this mean: "\r\ndata"? data isn't a header.
// todo: can use a cleanup

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"golang.org/x/text/encoding/ianaindex"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/smtp"
)

var xlog = mlog.New("message")

var (
	ErrBadContentType = errors.New("bad content-type")
)

var (
	errNotMultipart           = errors.New("not a multipart message")
	errFirstBoundCloses       = errors.New("first boundary cannot be finishing boundary")
	errLineTooLong            = errors.New("line too long")
	errMissingBoundaryParam   = errors.New("missing/empty boundary content-type parameter")
	errMissingClosingBoundary = errors.New("eof without closing boundary")
	errHalfLineSep            = errors.New("invalid CR or LF without the other")
	errUnexpectedEOF          = errors.New("unexpected eof")
)

// If set, during tests, attempts to reparse a part will cause an error, because sequentially reading parts should not lead to reparsing.
var enforceSequential bool

// Part represents a whole mail message, or a part of a multipart message. It
// is designed to handle IMAP requirements efficiently.
type Part struct {
	BoundaryOffset int64 // Offset in message where bound starts. -1 for top-level message.
	HeaderOffset   int64 // Offset in message file where header starts.
	BodyOffset     int64 // Offset in message file where body starts.
	EndOffset      int64 // Where body of part ends. Set when part is fully read.
	RawLineCount   int64 // Number of lines in raw, undecoded, body of part. Set when part is fully read.
	DecodedSize    int64 // Number of octets when decoded. If this is a text mediatype, lines ending only in LF are changed end in CRLF and DecodedSize reflects that.

	MediaType               string            // From Content-Type, upper case. E.g. "TEXT". Can be empty because content-type may be absent. In this case, the part may be treated as TEXT/PLAIN.
	MediaSubType            string            // From Content-Type, upper case. E.g. "PLAIN".
	ContentTypeParams       map[string]string // E.g. holds "boundary" for multipart messages. Has lower-case keys, and original case values.
	ContentID               string
	ContentDescription      string
	ContentTransferEncoding string    // In upper case.
	Envelope                *Envelope // Email message headers. Not for non-message parts.

	Parts []Part // Parts if this is a multipart.

	// Only for message/rfc822 and message/global. This part may have a buffer as
	// backing io.ReaderAt, because a message/global can have a non-identity
	// content-transfer-encoding. This part has a nil parent.
	Message *Part

	r               io.ReaderAt
	header          textproto.MIMEHeader // Parsed header.
	nextBoundOffset int64                // If >= 0, the offset where the next part header starts. We can set this when a user fully reads each part.
	lastBoundOffset int64                // Start of header of last/previous part. Used to skip a part if ParseNextPart is called and nextBoundOffset is -1.
	parent          *Part                // Parent part, for getting bound from, and setting nextBoundOffset when a part has finished reading. Only for subparts, not top-level parts.
	bound           []byte               // Only set if valid multipart with boundary, includes leading --, excludes \r\n.
}

// todo: have all Content* fields in Part?
// todo: make Address contain a type Localpart and dns.Domain?
// todo: if we ever make a major change and reparse all parts, switch to lower-case values if not too troublesome.

// Envelope holds the basic/common message headers as used in IMAP4.
type Envelope struct {
	Date      time.Time
	Subject   string
	From      []Address
	Sender    []Address
	ReplyTo   []Address
	To        []Address
	CC        []Address
	BCC       []Address
	InReplyTo string
	MessageID string
}

// Address as used in From and To headers.
type Address struct {
	Name string // Free-form name for display in mail applications.
	User string // Localpart.
	Host string // Domain in ASCII.
}

// Parse reads the headers of the mail message and returns a part.
// A part provides access to decoded and raw contents of a message and its multiple parts.
func Parse(r io.ReaderAt) (Part, error) {
	return newPart(r, 0, nil)
}

// EnsurePart parses a part as with Parse, but ensures a usable part is always
// returned, even if error is non-nil. If a parse error occurs, the message is
// returned as application/octet-stream, and headers can still be read if they
// were valid.
func EnsurePart(r io.ReaderAt, size int64) (Part, error) {
	p, err := Parse(r)
	if err == nil {
		err = p.Walk(nil)
	}
	if err != nil {
		np, err2 := fallbackPart(p, r, size)
		if err2 != nil {
			err = err2
		}
		p = np
	}
	return p, err
}

func fallbackPart(p Part, r io.ReaderAt, size int64) (Part, error) {
	np := Part{
		HeaderOffset:            p.HeaderOffset,
		BodyOffset:              p.BodyOffset,
		EndOffset:               size,
		MediaType:               "APPLICATION",
		MediaSubType:            "OCTET-STREAM",
		ContentTypeParams:       p.ContentTypeParams,
		ContentID:               p.ContentID,
		ContentDescription:      p.ContentDescription,
		ContentTransferEncoding: p.ContentTransferEncoding,
		Envelope:                p.Envelope,
		// We don't keep:
		//   - BoundaryOffset: irrelevant for top-level message.
		//   - RawLineCount and DecodedSize: set below.
		//   - Parts: we are not treating this as a multipart message.
	}
	np.SetReaderAt(r)
	// By reading body, the number of lines and decoded size will be set.
	_, err := io.Copy(io.Discard, np.Reader())
	return np, err
}

// SetReaderAt sets r as reader for this part and all its sub parts, recursively.
// No reader is set for any Message subpart, see SetMessageReaderAt.
func (p *Part) SetReaderAt(r io.ReaderAt) {
	if r == nil {
		panic("nil reader")
	}
	p.r = r
	for i := range p.Parts {
		pp := &p.Parts[i]
		pp.SetReaderAt(r)
	}
}

// SetMessageReaderAt sets a reader on p.Message, which must be non-nil.
func (p *Part) SetMessageReaderAt() error {
	// todo: if p.Message does not contain any non-identity content-transfer-encoding, we should set an offsetReader of p.Message, recursively.
	buf, err := io.ReadAll(p.Reader())
	if err != nil {
		return err
	}
	p.Message.SetReaderAt(bytes.NewReader(buf))
	return nil
}

// Walk through message, decoding along the way, and collecting mime part offsets and sizes, and line counts.
func (p *Part) Walk(parent *Part) error {
	if len(p.bound) == 0 {
		if p.MediaType == "MESSAGE" && (p.MediaSubType == "RFC822" || p.MediaSubType == "GLOBAL") {
			// todo: don't read whole submessage in memory...
			buf, err := io.ReadAll(p.Reader())
			if err != nil {
				return err
			}
			br := bytes.NewReader(buf)
			mp, err := Parse(br)
			if err != nil {
				return fmt.Errorf("parsing embedded message: %w", err)
			}
			if err := mp.Walk(nil); err != nil {
				// If this is a DSN and we are not in pedantic mode, accept unexpected end of
				// message. This is quite common because MTA's sometimes just truncate the original
				// message in a place that makes the message invalid.
				if errors.Is(err, errUnexpectedEOF) && !moxvar.Pedantic && parent != nil && len(parent.Parts) >= 3 && p == &parent.Parts[2] && parent.MediaType == "MULTIPART" && parent.MediaSubType == "REPORT" {
					mp, err = fallbackPart(mp, br, int64(len(buf)))
					if err != nil {
						return fmt.Errorf("parsing invalid embedded message: %w", err)
					}
				} else {
					return fmt.Errorf("parsing parts of embedded message: %w", err)
				}
			}
			// todo: if mp does not contain any non-identity content-transfer-encoding, we should set an offsetReader of p.r on mp, recursively.
			p.Message = &mp
			return nil
		}
		_, err := io.Copy(io.Discard, p.Reader())
		return err
	}

	for {
		pp, err := p.ParseNextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := pp.Walk(p); err != nil {
			return err
		}
	}
}

// String returns a debugging representation of the part.
func (p *Part) String() string {
	return fmt.Sprintf("&Part{%s/%s offsets %d/%d/%d/%d lines %d decodedsize %d next %d last %d bound %q parts %v}", p.MediaType, p.MediaSubType, p.BoundaryOffset, p.HeaderOffset, p.BodyOffset, p.EndOffset, p.RawLineCount, p.DecodedSize, p.nextBoundOffset, p.lastBoundOffset, p.bound, p.Parts)
}

// newPart parses a new part, which can be the top-level message.
// offset is the bound offset for parts, and the start of message for top-level messages. parent indicates if this is a top-level message or sub-part.
// If an error occurs, p's exported values can still be relevant. EnsurePart uses these values.
func newPart(r io.ReaderAt, offset int64, parent *Part) (p Part, rerr error) {
	if r == nil {
		panic("nil reader")
	}
	p = Part{
		BoundaryOffset: -1,
		EndOffset:      -1,
		r:              r,
		parent:         parent,
	}

	b := &bufAt{r: r, offset: offset}

	if parent != nil {
		p.BoundaryOffset = offset
		if line, _, err := b.ReadLine(true); err != nil {
			return p, err
		} else if match, finish := checkBound(line, parent.bound); !match {
			return p, fmt.Errorf("missing bound")
		} else if finish {
			return p, fmt.Errorf("new part for closing boundary")
		}
	}

	// Collect header.
	p.HeaderOffset = b.offset
	p.BodyOffset = b.offset
	hb := &bytes.Buffer{}
	for {
		line, _, err := b.ReadLine(true)
		if err != nil {
			return p, err
		}
		hb.Write(line)
		if len(line) == 2 {
			break // crlf
		}
	}
	p.BodyOffset = b.offset

	h, err := parseHeader(hb)
	if err != nil {
		return p, fmt.Errorf("parsing header: %w", err)
	}
	p.header = h

	ct := h.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil && ct != "" {
		return p, fmt.Errorf("%w: %s: %q", ErrBadContentType, err, ct)
	}
	if mt != "" {
		t := strings.SplitN(strings.ToUpper(mt), "/", 2)
		if len(t) != 2 {
			return p, fmt.Errorf("bad content-type: %q (content-type %q)", mt, ct)
		}
		p.MediaType = t[0]
		p.MediaSubType = t[1]
		p.ContentTypeParams = params
	}

	p.ContentID = h.Get("Content-Id")
	p.ContentDescription = h.Get("Content-Description")
	p.ContentTransferEncoding = strings.ToUpper(h.Get("Content-Transfer-Encoding"))

	if parent == nil {
		p.Envelope, err = parseEnvelope(mail.Header(h))
		if err != nil {
			return p, err
		}
	}

	if p.MediaType == "MULTIPART" {
		s := params["boundary"]
		if s == "" {
			return p, errMissingBoundaryParam
		}
		p.bound = append([]byte("--"), s...)

		// Discard preamble, before first boundary.
		for {
			line, _, err := b.PeekLine(true)
			if err != nil {
				return p, fmt.Errorf("parsing line for part preamble: %w", err)
			}
			// Line only needs boundary prefix, not exact match. ../rfc/2046:1103
			// Well, for compatibility, we require whitespace after the boundary. Because some
			// software use the same boundary but with text appended for sub parts.
			if match, finish := checkBound(line, p.bound); match {
				if finish {
					return p, errFirstBoundCloses
				}
				break
			}
			b.ReadLine(true)
		}
		p.nextBoundOffset = b.offset
		p.lastBoundOffset = b.offset
	}

	return p, nil
}

// Header returns the parsed header of this part.
func (p *Part) Header() (textproto.MIMEHeader, error) {
	if p.header != nil {
		return p.header, nil
	}
	h, err := parseHeader(p.HeaderReader())
	p.header = h
	return h, err
}

// HeaderReader returns a reader for the header section of this part, including ending bare CRLF.
func (p *Part) HeaderReader() io.Reader {
	return io.NewSectionReader(p.r, p.HeaderOffset, p.BodyOffset-p.HeaderOffset)
}

func parseHeader(r io.Reader) (textproto.MIMEHeader, error) {
	// We read using mail.ReadMessage instead of textproto.ReadMIMEHeaders because the
	// first handles email messages properly, while the second only works for HTTP
	// headers.
	var zero textproto.MIMEHeader
	msg, err := mail.ReadMessage(bufio.NewReader(r))
	if err != nil {
		return zero, err
	}
	return textproto.MIMEHeader(msg.Header), nil
}

var wordDecoder = mime.WordDecoder{
	CharsetReader: func(charset string, r io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "", "us-ascii", "utf-8":
			return r, nil
		}
		enc, _ := ianaindex.MIME.Encoding(charset)
		if enc == nil {
			enc, _ = ianaindex.IANA.Encoding(charset)
		}
		if enc == nil {
			return r, fmt.Errorf("unknown charset %q", charset)
		}
		return enc.NewDecoder().Reader(r), nil
	},
}

func parseEnvelope(h mail.Header) (*Envelope, error) {
	date, _ := h.Date()

	// We currently marshal this field to JSON. But JSON cannot represent all
	// time.Time. Time zone of 24:00 was seen in the wild. We won't try for extreme
	// years, but we can readjust timezones.
	// todo: remove this once we no longer store using json.
	_, offset := date.Zone()
	if date.Year() > 9999 {
		date = time.Time{}
	} else if offset <= -24*3600 || offset >= 24*3600 {
		date = time.Unix(date.Unix(), 0).UTC()
	}

	subject := h.Get("Subject")
	if s, err := wordDecoder.DecodeHeader(subject); err == nil {
		subject = s
	}

	env := &Envelope{
		date,
		subject,
		parseAddressList(h, "from"),
		parseAddressList(h, "sender"),
		parseAddressList(h, "reply-to"),
		parseAddressList(h, "to"),
		parseAddressList(h, "cc"),
		parseAddressList(h, "bcc"),
		h.Get("In-Reply-To"),
		h.Get("Message-Id"),
	}
	return env, nil
}

func parseAddressList(h mail.Header, k string) []Address {
	l, err := h.AddressList(k)
	if err != nil {
		return nil
	}
	var r []Address
	for _, a := range l {
		// todo: parse more fully according to ../rfc/5322:959
		var user, host string
		addr, err := smtp.ParseAddress(a.Address)
		if err != nil {
			// todo: pass a ctx to this function so we can log with cid.
			xlog.Infox("parsing address", err, mlog.Field("address", a.Address))
		} else {
			user = addr.Localpart.String()
			host = addr.Domain.ASCII
		}
		r = append(r, Address{a.Name, user, host})
	}
	return r
}

// ParseNextPart parses the next (sub)part of this multipart message.
// ParseNextPart returns io.EOF and a nil part when there are no more parts.
// Only use for initial parsing of message. Once parsed, use p.Parts.
func (p *Part) ParseNextPart() (*Part, error) {
	if len(p.bound) == 0 {
		return nil, errNotMultipart
	}
	if p.nextBoundOffset == -1 {
		if enforceSequential {
			panic("access not sequential")
		}
		// Set nextBoundOffset by fully reading the last part.
		last, err := newPart(p.r, p.lastBoundOffset, p)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(io.Discard, last.RawReader()); err != nil {
			return nil, err
		}
		if p.nextBoundOffset == -1 {
			return nil, fmt.Errorf("internal error: reading part did not set nextBoundOffset")
		}
	}
	b := &bufAt{r: p.r, offset: p.nextBoundOffset}
	// todo: should we require a crlf on final closing bound? we don't require it because some message/rfc822 don't have a crlf after their closing boundary, so those messages don't end in crlf.
	line, crlf, err := b.ReadLine(false)
	if err != nil {
		return nil, err
	}
	if match, finish := checkBound(line, p.bound); !match {
		return nil, fmt.Errorf("expected bound, got %q", line)
	} else if finish {
		// Read any trailing data.
		if p.parent != nil {
			for {
				line, _, err := b.PeekLine(false)
				if err != nil {
					break
				}
				if match, _ := checkBound(line, p.parent.bound); match {
					break
				}
				b.ReadLine(false)
			}
			if p.parent.lastBoundOffset == p.BoundaryOffset {
				p.parent.nextBoundOffset = b.offset
			}
		}
		p.EndOffset = b.offset
		return nil, io.EOF
	} else if !crlf {
		return nil, fmt.Errorf("non-finishing bound without crlf: %w", errUnexpectedEOF)
	}
	boundOffset := p.nextBoundOffset
	p.lastBoundOffset = boundOffset
	p.nextBoundOffset = -1
	np, err := newPart(p.r, boundOffset, p)
	if err != nil {
		return nil, err
	}
	p.Parts = append(p.Parts, np)
	return &p.Parts[len(p.Parts)-1], nil
}

// Reader returns a reader for the decoded body content.
func (p *Part) Reader() io.Reader {
	return p.bodyReader(p.RawReader())
}

// ReaderUTF8OrBinary returns a reader for the decode body content, transformed to
// utf-8 for known mime/iana encodings (only if they aren't us-ascii or utf-8
// already). For unknown or missing character sets/encodings, the original reader
// is returned.
func (p *Part) ReaderUTF8OrBinary() io.Reader {
	return moxio.DecodeReader(p.ContentTypeParams["charset"], p.Reader())
}

func (p *Part) bodyReader(r io.Reader) io.Reader {
	r = newDecoder(p.ContentTransferEncoding, r)
	if p.MediaType == "TEXT" {
		return &textReader{p, bufio.NewReader(r), 0, false}
	}
	return &countReader{p, r, 0}
}

// countReader is an io.Reader that passes Reads to the underlying reader.
// when eof is read, it sets p.DecodedSize to the number of bytes returned.
type countReader struct {
	p     *Part
	r     io.Reader
	count int64
}

func (cr *countReader) Read(buf []byte) (int, error) {
	n, err := cr.r.Read(buf)
	if n >= 0 {
		cr.count += int64(n)
	}
	if err == io.EOF {
		cr.p.DecodedSize = cr.count
	}
	return n, err
}

// textReader is an io.Reader that ensures all lines return end in CRLF.
// when eof is read from the underlying reader, it sets p.DecodedSize.
type textReader struct {
	p      *Part
	r      *bufio.Reader
	count  int64
	prevcr bool // If previous byte returned was a CR.
}

func (tr *textReader) Read(buf []byte) (int, error) {
	o := 0
	for o < len(buf) {
		c, err := tr.r.ReadByte()
		if err != nil {
			tr.count += int64(o)
			tr.p.DecodedSize = tr.count
			return o, err
		}
		if c == '\n' && !tr.prevcr {
			buf[o] = '\r'
			o++
			tr.prevcr = true
			tr.r.UnreadByte()
			continue
		}
		buf[o] = c
		tr.prevcr = c == '\r'
		o++
	}
	tr.count += int64(o)
	return o, nil
}

func newDecoder(cte string, r io.Reader) io.Reader {
	// ../rfc/2045:775
	switch cte {
	case "BASE64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "QUOTED-PRINTABLE":
		return quotedprintable.NewReader(r)
	}
	return r
}

// RawReader returns a reader for the raw, undecoded body content. E.g. with
// quoted-printable or base64 content intact.
// Fully reading a part helps its parent part find its next part efficiently.
func (p *Part) RawReader() io.Reader {
	if p.r == nil {
		panic("missing reader")
	}
	if p.EndOffset >= 0 {
		return io.NewSectionReader(p.r, p.BodyOffset, p.EndOffset-p.BodyOffset)
	}
	p.RawLineCount = 0
	if p.parent == nil {
		return &offsetReader{p, p.BodyOffset, true}
	}
	return &boundReader{p: p, b: &bufAt{r: p.r, offset: p.BodyOffset}, lastnewline: true}
}

// bufAt is a buffered reader on an underlying ReaderAt.
type bufAt struct {
	offset int64 // Offset in r currently consumed, i.e. ignoring any buffered data.

	r       io.ReaderAt
	buf     []byte // Buffered data.
	nbuf    int    // Valid bytes in buf.
	scratch []byte
}

// todo: lower max line length? at least have a mode where we refuse anything beyong 1000 bytes. ../rfc/5321:3512
const maxLineLength = 8 * 1024

// ensure makes sure b.nbuf is up to maxLineLength, unless eof is encountered.
func (b *bufAt) ensure() error {
	for _, c := range b.buf[:b.nbuf] {
		if c == '\n' {
			return nil
		}
	}
	if b.scratch == nil {
		b.scratch = make([]byte, maxLineLength)
	}
	if b.buf == nil {
		b.buf = make([]byte, maxLineLength)
	}
	for b.nbuf < maxLineLength {
		n, err := b.r.ReadAt(b.buf[b.nbuf:], b.offset+int64(b.nbuf))
		if n > 0 {
			b.nbuf += n
		}
		if err != nil && err != io.EOF || err == io.EOF && b.nbuf+n == 0 {
			return err
		}
		if n == 0 || err == io.EOF {
			break
		}
	}
	return nil
}

// ReadLine reads a line until \r\n is found, returning the line including \r\n.
// If not found, or a single \r or \n is encountered, ReadLine returns an error, e.g. io.EOF.
func (b *bufAt) ReadLine(requirecrlf bool) (buf []byte, crlf bool, err error) {
	return b.line(true, requirecrlf)
}

func (b *bufAt) PeekLine(requirecrlf bool) (buf []byte, crlf bool, err error) {
	return b.line(false, requirecrlf)
}

func (b *bufAt) line(consume, requirecrlf bool) (buf []byte, crlf bool, err error) {
	if err := b.ensure(); err != nil {
		return nil, false, err
	}
	for i, c := range b.buf[:b.nbuf] {
		if c == '\n' {
			return nil, false, errHalfLineSep
		}
		if c != '\r' {
			continue
		}
		i++
		if i >= b.nbuf || b.buf[i] != '\n' {
			return nil, false, errHalfLineSep
		}
		b.scratch = b.scratch[:i+1]
		copy(b.scratch, b.buf[:i+1])
		if consume {
			copy(b.buf, b.buf[i+1:])
			b.offset += int64(i + 1)
			b.nbuf -= i + 1
		}
		return b.scratch, true, nil
	}
	if b.nbuf >= maxLineLength {
		return nil, false, errLineTooLong
	}
	if requirecrlf {
		return nil, false, errUnexpectedEOF
	}
	b.scratch = b.scratch[:b.nbuf]
	copy(b.scratch, b.buf[:b.nbuf])
	if consume {
		b.offset += int64(b.nbuf)
		b.nbuf = 0
	}
	return b.scratch, false, nil
}

// PeekByte returns the next unread byte, or an error.
func (b *bufAt) PeekByte() (byte, error) {
	if err := b.ensure(); err != nil {
		return 0, err
	}
	if b.nbuf == 0 {
		return 0, io.EOF
	}
	return b.buf[0], nil
}

type offsetReader struct {
	p           *Part
	offset      int64
	lastnewline bool
}

func (r *offsetReader) Read(buf []byte) (int, error) {
	n, err := r.p.r.ReadAt(buf, r.offset)
	if n > 0 {
		r.offset += int64(n)

		for _, c := range buf[:n] {
			if r.lastnewline {
				r.p.RawLineCount++
			}
			r.lastnewline = c == '\n'
		}
	}
	if err == io.EOF {
		r.p.EndOffset = r.offset
	}
	return n, err
}

var crlf = []byte("\r\n")

// boundReader is a reader that stops at a closing multipart boundary.
type boundReader struct {
	p           *Part
	b           *bufAt
	buf         []byte // Data from previous line, to be served first.
	nbuf        int    // Number of valid bytes in buf.
	crlf        []byte // Possible crlf, to be returned if we do not yet encounter a boundary.
	lastnewline bool   // If last char return was a newline. For counting lines.
}

func (b *boundReader) Read(buf []byte) (count int, rerr error) {
	origBuf := buf
	defer func() {
		if count > 0 {
			for _, c := range origBuf[:count] {
				if b.lastnewline {
					b.p.RawLineCount++
				}
				b.lastnewline = c == '\n'
			}
		}
	}()

	for {
		// Read data from earlier line.
		if b.nbuf > 0 {
			n := b.nbuf
			if n > len(buf) {
				n = len(buf)
			}
			copy(buf, b.buf[:n])
			copy(b.buf, b.buf[n:])
			buf = buf[n:]
			b.nbuf -= n
			count += n
			if b.nbuf > 0 {
				break
			}
		}

		// Look at next line. If it is a boundary, we are done and won't serve the crlf from the last line.
		line, _, err := b.b.PeekLine(false)
		if match, _ := checkBound(line, b.p.parent.bound); match {
			b.p.EndOffset = b.b.offset - int64(len(b.crlf))
			if b.p.parent.lastBoundOffset == b.p.BoundaryOffset {
				b.p.parent.nextBoundOffset = b.b.offset
			} else if enforceSequential {
				panic("access not sequential")
			}
			return count, io.EOF
		}
		if err == io.EOF {
			err = errMissingClosingBoundary
		}
		if err != nil && err != io.EOF {
			return count, err
		}
		if len(b.crlf) > 0 {
			n := len(b.crlf)
			if n > len(buf) {
				n = len(buf)
			}
			copy(buf, b.crlf[:n])
			count += n
			buf = buf[n:]
			b.crlf = b.crlf[n:]
		}
		if len(buf) == 0 {
			break
		}
		line, _, err = b.b.ReadLine(true)
		if err != nil {
			// Could be an unexpected end of the part.
			return 0, err
		}
		b.crlf = crlf // crlf will be read next time, but not if a boundary follows.
		n := len(line) - 2
		line = line[:n]
		if n > len(buf) {
			n = len(buf)
		}
		copy(buf, line[:n])
		count += n
		buf = buf[n:]
		line = line[n:]
		if len(line) > 0 {
			if b.buf == nil {
				b.buf = make([]byte, maxLineLength)
			}
			copy(b.buf, line)
			b.nbuf = len(line)
		}
	}
	return count, nil
}

func checkBound(line, bound []byte) (bool, bool) {
	if !bytes.HasPrefix(line, bound) {
		return false, false
	}
	line = line[len(bound):]
	if bytes.HasPrefix(line, []byte("--")) {
		return true, true
	}
	if len(line) == 0 {
		return true, false
	}
	c := line[0]
	switch c {
	case ' ', '\t', '\r', '\n':
		return true, false
	}
	return false, false
}
