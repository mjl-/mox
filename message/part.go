package message

// todo: allow more invalid content-type values, we now stop parsing on: empty media type (eg "content-type: ; name=..."), empty value for property (eg "charset=", missing quotes for characters that should be quoted (eg boundary containing "=" but without quotes), duplicate properties (two charsets), empty pairs (eg "text/html;;").
// todo: should we be forgiving when closing boundary in multipart message is missing? seems like spam messages do this...
// todo: should we allow base64 messages where a line starts with a space? and possibly more whitespace. is happening in messages. coreutils base64 accepts it, encoding/base64 does not.
// todo: handle comments in headers?
// todo: should we just always store messages with \n instead of \r\n? \r\n seems easier for use with imap.
// todo: can use a cleanup

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/encoding/ianaindex"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
	"slices"
)

// Pedantic enables stricter parsing.
var Pedantic bool

var (
	ErrBadContentType = errors.New("bad content-type")
	ErrHeader         = errors.New("bad message header")
)

var (
	errNotMultipart           = errors.New("not a multipart message")
	errFirstBoundCloses       = errors.New("first boundary cannot be finishing boundary")
	errLineTooLong            = errors.New("line too long")
	errMissingBoundaryParam   = errors.New("missing/empty boundary content-type parameter")
	errMissingClosingBoundary = errors.New("eof without closing boundary")
	errBareLF                 = errors.New("invalid bare line feed")
	errBareCR                 = errors.New("invalid bare carriage return")
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
	ContentID               *string           `json:",omitempty"`
	ContentDescription      *string           `json:",omitempty"`
	ContentTransferEncoding *string           `json:",omitempty"` // In upper case.
	ContentDisposition      *string           `json:",omitempty"`
	ContentMD5              *string           `json:",omitempty"`
	ContentLanguage         *string           `json:",omitempty"`
	ContentLocation         *string           `json:",omitempty"`
	Envelope                *Envelope         `json:",omitempty"` // Email message headers. Not for non-message parts.

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
	strict          bool                 // If set, valid crlf line endings are verified when reading body.
}

// todo: have all Content* fields in Part?
// todo: make Address contain a type Localpart and dns.Domain?
// todo: if we ever make a major change and reparse all parts, switch to lower-case values if not too troublesome.

// Envelope holds the basic/common message headers as used in IMAP4.
type Envelope struct {
	Date      time.Time
	Subject   string // Q/B-word-decoded.
	From      []Address
	Sender    []Address
	ReplyTo   []Address
	To        []Address
	CC        []Address
	BCC       []Address
	InReplyTo string // From In-Reply-To header, includes <>.
	MessageID string // From Message-Id header, includes <>.
}

// Address as used in From and To headers.
type Address struct {
	Name string // Free-form name for display in mail applications.
	User string // Localpart, encoded as string. Must be parsed before using as Localpart.
	Host string // Domain in ASCII.
}

// Parse reads the headers of the mail message and returns a part.
// A part provides access to decoded and raw contents of a message and its multiple parts.
//
// If strict is set, fewer attempts are made to continue parsing when errors are
// encountered, such as with invalid content-type headers or bare carriage returns.
func Parse(elog *slog.Logger, strict bool, r io.ReaderAt) (Part, error) {
	log := mlog.New("message", elog)
	return newPart(log, strict, r, 0, nil)
}

// EnsurePart parses a part as with Parse, but ensures a usable part is always
// returned, even if error is non-nil. If a parse error occurs, the message is
// returned as application/octet-stream, and headers can still be read if they
// were valid.
//
// If strict is set, fewer attempts are made to continue parsing when errors are
// encountered, such as with invalid content-type headers or bare carriage returns.
func EnsurePart(elog *slog.Logger, strict bool, r io.ReaderAt, size int64) (Part, error) {
	log := mlog.New("message", elog)
	p, err := Parse(log.Logger, strict, r)
	if err == nil {
		err = p.Walk(log.Logger, nil)
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
		ContentDisposition:      p.ContentDisposition,
		ContentMD5:              p.ContentMD5,
		ContentLanguage:         p.ContentLanguage,
		ContentLocation:         p.ContentLocation,
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
func (p *Part) Walk(elog *slog.Logger, parent *Part) error {
	log := mlog.New("message", elog)

	if len(p.bound) == 0 {
		if p.MediaType == "MESSAGE" && (p.MediaSubType == "RFC822" || p.MediaSubType == "GLOBAL") {
			// todo: don't read whole submessage in memory...
			buf, err := io.ReadAll(p.Reader())
			if err != nil {
				return err
			}
			br := bytes.NewReader(buf)
			mp, err := Parse(log.Logger, p.strict, br)
			if err != nil {
				return fmt.Errorf("parsing embedded message: %w", err)
			}
			if err := mp.Walk(log.Logger, nil); err != nil {
				// If this is a DSN and we are not in pedantic mode, accept unexpected end of
				// message. This is quite common because MTA's sometimes just truncate the original
				// message in a place that makes the message invalid.
				if errors.Is(err, errUnexpectedEOF) && !Pedantic && parent != nil && len(parent.Parts) >= 3 && p == &parent.Parts[2] && parent.MediaType == "MULTIPART" && parent.MediaSubType == "REPORT" {
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
		pp, err := p.ParseNextPart(log.Logger)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := pp.Walk(log.Logger, p); err != nil {
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
func newPart(log mlog.Log, strict bool, r io.ReaderAt, offset int64, parent *Part) (p Part, rerr error) {
	if r == nil {
		panic("nil reader")
	}
	p = Part{
		BoundaryOffset: -1,
		EndOffset:      -1,
		r:              r,
		parent:         parent,
		strict:         strict,
	}

	b := &bufAt{strict: strict, r: r, offset: offset}

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
		if err == io.EOF {
			// No body is valid.
			break
		}
		if err != nil {
			return p, fmt.Errorf("reading header line: %w", err)
		}
		hb.Write(line)
		if len(line) == 2 {
			break // crlf
		}
	}
	p.BodyOffset = b.offset

	// Don't attempt to parse empty header, mail.ReadMessage doesn't like it.
	if p.HeaderOffset == p.BodyOffset {
		p.header = textproto.MIMEHeader{}
	} else {
		h, err := parseHeader(hb)
		if err != nil {
			return p, fmt.Errorf("parsing header: %w", err)
		}
		p.header = h
	}

	ct := p.header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil && ct != "" {
		if Pedantic || strict {
			return p, fmt.Errorf("%w: %s: %q", ErrBadContentType, err, ct)
		}

		// Try parsing just a content-type, ignoring parameters.
		// ../rfc/2045:628
		ct = strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
		t := strings.SplitN(ct, "/", 2)
		isToken := func(s string) bool {
			const separators = `()<>@,;:\\"/[]?= ` // ../rfc/2045:663
			for _, c := range s {
				if c < 0x20 || c >= 0x80 || strings.ContainsRune(separators, c) {
					return false
				}
			}
			return len(s) > 0
		}
		// We cannot recover content-type of multipart, we won't have a boundary.
		if len(t) == 2 && isToken(t[0]) && !strings.EqualFold(t[0], "multipart") && isToken(t[1]) {
			p.MediaType = strings.ToUpper(t[0])
			p.MediaSubType = strings.ToUpper(t[1])
		} else {
			p.MediaType = "APPLICATION"
			p.MediaSubType = "OCTET-STREAM"
		}
		log.Debugx("malformed content-type, attempting to recover and continuing", err,
			slog.String("contenttype", p.header.Get("Content-Type")),
			slog.String("mediatype", p.MediaType),
			slog.String("mediasubtype", p.MediaSubType))
	} else if mt != "" {
		t := strings.SplitN(strings.ToUpper(mt), "/", 2)
		if len(t) != 2 {
			if Pedantic || strict {
				return p, fmt.Errorf("bad content-type: %q (content-type %q)", mt, ct)
			}
			log.Debug("malformed media-type, ignoring and continuing", slog.String("type", mt))
			p.MediaType = "APPLICATION"
			p.MediaSubType = "OCTET-STREAM"
		} else {
			p.MediaType = t[0]
			p.MediaSubType = t[1]
			p.ContentTypeParams = params
		}
	}

	p.ContentID = p.headerGet("Content-Id")
	p.ContentDescription = p.headerGet("Content-Description")
	cte := p.headerGet("Content-Transfer-Encoding")
	if cte != nil {
		s := strings.ToUpper(*cte)
		cte = &s
	}
	p.ContentTransferEncoding = cte
	p.ContentDisposition = p.headerGet("Content-Disposition")
	p.ContentMD5 = p.headerGet("Content-Md5")
	p.ContentLanguage = p.headerGet("Content-Language")
	p.ContentLocation = p.headerGet("Content-Location")

	if parent == nil {
		p.Envelope, err = parseEnvelope(log, mail.Header(p.header))
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
//
// Returns a ErrHeader for messages with invalid header syntax.
func (p *Part) Header() (textproto.MIMEHeader, error) {
	if p.header != nil {
		return p.header, nil
	}
	if p.HeaderOffset == p.BodyOffset {
		p.header = textproto.MIMEHeader{}
		return p.header, nil
	}
	h, err := parseHeader(p.HeaderReader())
	p.header = h
	return h, err
}

func (p *Part) headerGet(k string) *string {
	l := p.header.Values(k)
	if len(l) == 0 {
		return nil
	}
	s := l[0]
	return &s
}

// HeaderReader returns a reader for the header section of this part, including ending bare CRLF.
func (p *Part) HeaderReader() io.Reader {
	return io.NewSectionReader(p.r, p.HeaderOffset, p.BodyOffset-p.HeaderOffset)
}

// parse a header, only call this on non-empty input (even though that is a valid header).
func parseHeader(r io.Reader) (textproto.MIMEHeader, error) {
	// We read using mail.ReadMessage instead of textproto.ReadMIMEHeaders because the
	// first handles email messages properly, while the second only works for HTTP
	// headers.
	var zero textproto.MIMEHeader

	// We read the header and add the optional \r\n header/body separator. If the \r\n
	// is missing, parsing with Go <1.21 results in an EOF error.
	// todo: directly parse from reader r when Go 1.20 is no longer supported.
	buf, err := io.ReadAll(r)
	if err != nil {
		return zero, err
	}
	if bytes.HasSuffix(buf, []byte("\r\n")) && !bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
		buf = append(buf, "\r\n"...)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(buf))
	if err != nil {
		// Recognize parsing errors from net/mail.ReadMessage.
		// todo: replace with own message parsing code that returns proper error types.
		errstr := err.Error()
		if strings.HasPrefix(errstr, "malformed initial line:") || strings.HasPrefix(errstr, "malformed header line:") {
			err = fmt.Errorf("%w: %v", ErrHeader, err)
		}
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

func parseEnvelope(log mlog.Log, h mail.Header) (*Envelope, error) {
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
		parseAddressList(log, h, "from"),
		parseAddressList(log, h, "sender"),
		parseAddressList(log, h, "reply-to"),
		parseAddressList(log, h, "to"),
		parseAddressList(log, h, "cc"),
		parseAddressList(log, h, "bcc"),
		h.Get("In-Reply-To"),
		h.Get("Message-Id"),
	}
	return env, nil
}

func parseAddressList(log mlog.Log, h mail.Header, k string) []Address {
	// todo: possibly work around ios mail generating incorrect q-encoded "phrases" with unencoded double quotes? ../rfc/2047:382
	v := h.Get(k)
	if v == "" {
		return nil
	}
	parser := mail.AddressParser{WordDecoder: &wordDecoder}
	l, err := parser.ParseList(v)
	if err != nil {
		return nil
	}
	var r []Address
	for _, a := range l {
		// todo: parse more fully according to ../rfc/5322:959
		var user, host string
		addr, err := smtp.ParseNetMailAddress(a.Address)
		if err != nil {
			log.Infox("parsing address (continuing)", err, slog.Any("netmailaddress", a.Address))
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
// Only used for initial parsing of message. Once parsed, use p.Parts.
func (p *Part) ParseNextPart(elog *slog.Logger) (*Part, error) {
	log := mlog.New("message", elog)

	if len(p.bound) == 0 {
		return nil, errNotMultipart
	}
	if p.nextBoundOffset == -1 {
		if enforceSequential {
			panic("access not sequential")
		}
		// Set nextBoundOffset by fully reading the last part.
		last, err := newPart(log, p.strict, p.r, p.lastBoundOffset, p)
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
	b := &bufAt{strict: p.strict, r: p.r, offset: p.nextBoundOffset}
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
	np, err := newPart(log, p.strict, p.r, boundOffset, p)
	if err != nil {
		return nil, err
	}
	p.Parts = append(p.Parts, np)
	return &p.Parts[len(p.Parts)-1], nil
}

// IsDSN returns whether the MIME structure of the part is a DSN.
func (p *Part) IsDSN() bool {
	return p.MediaType == "MULTIPART" &&
		p.MediaSubType == "REPORT" &&
		len(p.Parts) >= 2 &&
		p.Parts[1].MediaType == "MESSAGE" &&
		(p.Parts[1].MediaSubType == "DELIVERY-STATUS" || p.Parts[1].MediaSubType == "GLOBAL-DELIVERY-STATUS")
}

func hasNonASCII(r io.Reader) (bool, error) {
	br := bufio.NewReader(r)
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return false, err
		}
		if b > unicode.MaxASCII {
			return true, nil
		}
	}
	return false, nil
}

// NeedsSMTPUTF8 returns whether the part needs the SMTPUTF8 extension to be
// transported, due to non-ascii in message headers.
func (p *Part) NeedsSMTPUTF8() (bool, error) {
	if has, err := hasNonASCII(p.HeaderReader()); err != nil {
		return false, fmt.Errorf("reading header: %w", err)
	} else if has {
		return true, nil
	}
	for _, pp := range p.Parts {
		if has, err := pp.NeedsSMTPUTF8(); err != nil || has {
			return has, err
		}
	}
	return false, nil
}

var ErrParamEncoding = errors.New("bad header parameter encoding")

// DispositionFilename tries to parse the disposition header and the "filename"
// parameter. If the filename parameter is absent or can't be parsed, the "name"
// parameter from the Content-Type header is used for the filename. The returned
// filename is decoded according to RFC 2231 or RFC 2047. This is a best-effort
// attempt to find a filename for a part. If no Content-Disposition header, or
// filename was found, empty values without error are returned.
//
// If the returned error is an ErrParamEncoding, it can be treated as a diagnostic
// and a filename may still be returned.
func (p *Part) DispositionFilename() (disposition string, filename string, err error) {
	cd := p.ContentDisposition
	var disp string
	var params map[string]string
	if cd != nil && *cd != "" {
		disp, params, err = mime.ParseMediaType(*cd)
	}
	if err != nil {
		return "", "", fmt.Errorf("%w: parsing disposition header: %v", ErrParamEncoding, err)
	}
	filename, err = tryDecodeParam(params["filename"])
	if filename == "" {
		s, err2 := tryDecodeParam(p.ContentTypeParams["name"])
		filename = s
		if err == nil {
			err = err2
		}
	}
	return disp, filename, err
}

// Attempt q/b-word-decode name, coming from Content-Type "name" field or
// Content-Disposition "filename" field.
//
// RFC 2231 specifies an encoding for non-ascii values in mime header parameters. But
// it appears common practice to instead just q/b-word encode the values.
// Thunderbird and gmail.com do this for the Content-Type "name" parameter.
// gmail.com also does that for the Content-Disposition "filename" parameter, where
// Thunderbird uses the RFC 2231-defined encoding. Go's mime.ParseMediaType parses
// the mechanism specified in RFC 2231 only. The value for "name" we get here would
// already be decoded properly for standards-compliant headers, like
// "filename*0*=UTF-8”%...; filename*1*=%.... We'll look for Q/B-word encoding
// markers ("=?"-prefix or "?="-suffix) and try to decode if present. This would
// only cause trouble for filenames having this prefix/suffix.
func tryDecodeParam(name string) (string, error) {
	if name == "" || !strings.HasPrefix(name, "=?") && !strings.HasSuffix(name, "?=") {
		return name, nil
	}
	// todo: find where this is allowed. it seems quite common. perhaps we should remove the pedantic check?
	if Pedantic {
		return name, fmt.Errorf("%w: attachment contains rfc2047 q/b-word-encoded mime parameter instead of rfc2231-encoded", ErrParamEncoding)
	}
	s, err := wordDecoder.DecodeHeader(name)
	if err != nil {
		return name, fmt.Errorf("%w: q/b-word decoding mime parameter: %v", ErrParamEncoding, err)
	}
	return s, nil
}

// Reader returns a reader for the decoded body content.
func (p *Part) Reader() io.Reader {
	return p.bodyReader(p.RawReader())
}

// ReaderUTF8OrBinary returns a reader for the decoded body content, transformed to
// utf-8 for known mime/iana encodings (only if they aren't us-ascii or utf-8
// already). For unknown or missing character sets/encodings, the original reader
// is returned.
func (p *Part) ReaderUTF8OrBinary() io.Reader {
	return DecodeReader(p.ContentTypeParams["charset"], p.Reader())
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
			if err := tr.r.UnreadByte(); err != nil {
				return o, err
			}
			buf[o] = '\r'
			o++
			tr.prevcr = true
			continue
		}
		buf[o] = c
		tr.prevcr = c == '\r'
		o++
	}
	tr.count += int64(o)
	return o, nil
}

func newDecoder(cte *string, r io.Reader) io.Reader {
	var s string
	if cte != nil {
		s = *cte
	}
	// ../rfc/2045:775
	switch s {
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
		return &crlfReader{strict: p.strict, r: io.NewSectionReader(p.r, p.BodyOffset, p.EndOffset-p.BodyOffset)}
	}
	p.RawLineCount = 0
	if p.parent == nil {
		return &offsetReader{p, p.BodyOffset, p.strict, true, false, 0}
	}
	return &boundReader{p: p, b: &bufAt{strict: p.strict, r: p.r, offset: p.BodyOffset}, prevlf: true}
}

// crlfReader verifies there are no bare newlines and optionally no bare carriage returns.
type crlfReader struct {
	r      io.Reader
	strict bool
	prevcr bool
}

func (r *crlfReader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	if err == nil || err == io.EOF {
		for _, b := range buf[:n] {
			if b == '\n' && !r.prevcr {
				err = errBareLF
				break
			} else if b != '\n' && r.prevcr && (r.strict || Pedantic) {
				err = errBareCR
				break
			}
			r.prevcr = b == '\r'
		}
	}
	return n, err
}

// bufAt is a buffered reader on an underlying ReaderAt.
// bufAt verifies that lines end with crlf.
type bufAt struct {
	offset int64 // Offset in r currently consumed, i.e. not including any buffered data.

	strict  bool
	r       io.ReaderAt
	buf     []byte // Buffered data.
	nbuf    int    // Valid bytes in buf.
	scratch []byte
}

// Messages should not have lines longer than 78+2 bytes, and must not have
// lines longer than 998+2 bytes. But in practice they have longer lines. We
// have a higher limit, but for when parsing with strict we check for the 1000
// bytes limit.
// ../rfc/5321:3512
const maxLineLength = 8 * 1024

func (b *bufAt) maxLineLength() int {
	if b.strict || Pedantic {
		return 1000
	}
	return maxLineLength
}

// ensure makes sure b.nbuf is up to maxLineLength, unless eof is encountered.
func (b *bufAt) ensure() error {
	if slices.Contains(b.buf[:b.nbuf], '\n') {
		return nil
	}
	if b.scratch == nil {
		b.scratch = make([]byte, b.maxLineLength())
	}
	if b.buf == nil {
		b.buf = make([]byte, b.maxLineLength())
	}
	for b.nbuf < b.maxLineLength() {
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
// If not found, or a bare \n is encountered, or a bare \r is enountered in pedantic mode, ReadLine returns an error.
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
			// Should have seen a \r, which should have been handled below.
			return nil, false, errBareLF
		}
		if c != '\r' {
			continue
		}
		i++
		if i >= b.nbuf || b.buf[i] != '\n' {
			if b.strict || Pedantic {
				return nil, false, errBareCR
			}
			continue
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
	if b.nbuf >= b.maxLineLength() {
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

// offsetReader reads from p.r starting from offset, and RawLineCount on p.
// offsetReader validates lines end with \r\n.
type offsetReader struct {
	p          *Part
	offset     int64
	strict     bool
	prevlf     bool
	prevcr     bool
	linelength int
}

func (r *offsetReader) Read(buf []byte) (int, error) {
	n, err := r.p.r.ReadAt(buf, r.offset)
	if n > 0 {
		r.offset += int64(n)
		max := maxLineLength
		if r.strict || Pedantic {
			max = 1000
		}

		for _, c := range buf[:n] {
			if r.prevlf {
				r.p.RawLineCount++
			}
			if err == nil || err == io.EOF {
				if c == '\n' && !r.prevcr {
					err = errBareLF
				} else if c != '\n' && r.prevcr && (r.strict || Pedantic) {
					err = errBareCR
				}
			}
			r.prevlf = c == '\n'
			r.prevcr = c == '\r'
			r.linelength++
			if c == '\n' {
				r.linelength = 0
			} else if r.linelength > max && err == nil {
				err = errLineTooLong
			}
		}
	}
	if err == io.EOF {
		r.p.EndOffset = r.offset
	}
	return n, err
}

var crlf = []byte("\r\n")

// boundReader is a reader that stops at a closing multipart boundary.
// boundReader ensures lines end with crlf through its use of bufAt.
type boundReader struct {
	p      *Part
	b      *bufAt
	buf    []byte // Data from previous line, to be served first.
	nbuf   int    // Number of valid bytes in buf.
	crlf   []byte // Possible crlf, to be returned if we do not yet encounter a boundary.
	prevlf bool   // If last char returned was a newline. For counting lines.
}

func (b *boundReader) Read(buf []byte) (count int, rerr error) {
	origBuf := buf
	defer func() {
		if count > 0 {
			for _, c := range origBuf[:count] {
				if b.prevlf {
					b.p.RawLineCount++
				}
				b.prevlf = c == '\n'
			}
		}
	}()

	for {
		// Read data from earlier line.
		if b.nbuf > 0 {
			n := min(b.nbuf, len(buf))
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
			n := min(len(b.crlf), len(buf))
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
				b.buf = make([]byte, b.b.maxLineLength())
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
