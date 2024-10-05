package webmail

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/url"
	"strings"

	"golang.org/x/text/encoding/ianaindex"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// todo: we should have all needed information for messageItem in store.Message (perhaps some data in message.Part) for fast access, not having to parse the on-disk message file.

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

// Attempt q/b-word-decode name, coming from Content-Type "name" field or
// Content-Disposition "filename" field.
//
// RFC 2231 specify an encoding for non-ascii values in mime header parameters. But
// it appears common practice to instead just q/b-word encode the values.
// Thunderbird and gmail.com do this for the Content-Type "name" parameter.
// gmail.com also does that for the Content-Disposition "filename" parameter, where
// Thunderbird uses the RFC 2231-defined encoding. Go's mime.ParseMediaType parses
// the mechanism specified in RFC 2231 only. The value for "name" we get here would
// already be decoded properly for standards-compliant headers, like
// "filename*0*=UTF-8”%...; filename*1*=%.... We'll look for Q/B-word encoding
// markers ("=?"-prefix or "?="-suffix) and try to decode if present. This would
// only cause trouble for filenames having this prefix/suffix.
func tryDecodeParam(log mlog.Log, name string) string {
	if name == "" || !strings.HasPrefix(name, "=?") && !strings.HasSuffix(name, "?=") {
		return name
	}
	// todo: find where this is allowed. it seems quite common. perhaps we should remove the pedantic check?
	if mox.Pedantic {
		log.Debug("attachment contains rfc2047 q/b-word-encoded mime parameter instead of rfc2231-encoded", slog.String("name", name))
		return name
	}
	s, err := wordDecoder.DecodeHeader(name)
	if err != nil {
		log.Debugx("q/b-word decoding mime parameter", err, slog.String("name", name))
		return name
	}
	return s
}

// todo: mime.FormatMediaType does not wrap long lines. should do it ourselves, and split header into several parts (if commonly supported).

func messageItem(log mlog.Log, m store.Message, state *msgState) (MessageItem, error) {
	pm, err := parsedMessage(log, m, state, false, true)
	if err != nil {
		return MessageItem{}, fmt.Errorf("parsing message %d for item: %v", m.ID, err)
	}
	// Clear largish unused data.
	m.MsgPrefix = nil
	m.ParsedBuf = nil
	return MessageItem{m, pm.envelope, pm.attachments, pm.isSigned, pm.isEncrypted, pm.firstLine, true}, nil
}

// formatFirstLine returns a line the client can display next to the subject line
// in a mailbox. It will replace quoted text, and any prefixing "On ... write:"
// line with "[...]" so only new and useful information will be displayed.
// Trailing signatures are not included.
func formatFirstLine(r io.Reader) (string, error) {
	// We look quite a bit of lines ahead for trailing signatures with trailing empty lines.
	var lines []string
	scanner := bufio.NewScanner(r)
	ensureLines := func() {
		for len(lines) < 10 && scanner.Scan() {
			lines = append(lines, strings.TrimSpace(scanner.Text()))
		}
	}
	ensureLines()

	isSnipped := func(s string) bool {
		return s == "[...]" || s == "[…]" || s == "..."
	}

	nextLineQuoted := func(i int) bool {
		if i+1 < len(lines) && lines[i+1] == "" {
			i++
		}
		return i+1 < len(lines) && (strings.HasPrefix(lines[i+1], ">") || isSnipped(lines[i+1]))
	}

	// Remainder is signature if we see a line with only and minimum 2 dashes, and
	// there are no more empty lines, and there aren't more than 5 lines left.
	isSignature := func() bool {
		if len(lines) == 0 || !strings.HasPrefix(lines[0], "--") || strings.Trim(strings.TrimSpace(lines[0]), "-") != "" {
			return false
		}
		l := lines[1:]
		for len(l) > 0 && l[len(l)-1] == "" {
			l = l[:len(l)-1]
		}
		if len(l) >= 5 {
			return false
		}
		for _, line := range l {
			if line == "" {
				return false
			}
		}
		return true
	}

	result := ""

	resultSnipped := func() bool {
		return strings.HasSuffix(result, "[...]\n") || strings.HasSuffix(result, "[…]")
	}

	// Quick check for initial wrapped "On ... wrote:" line.
	if len(lines) > 3 && strings.HasPrefix(lines[0], "On ") && !strings.HasSuffix(lines[0], "wrote:") && strings.HasSuffix(lines[1], ":") && nextLineQuoted(1) {
		result = "[...]\n"
		lines = lines[3:]
		ensureLines()
	}

	for ; len(lines) > 0 && !isSignature(); ensureLines() {
		line := lines[0]
		if strings.HasPrefix(line, ">") {
			if !resultSnipped() {
				result += "[...]\n"
			}
			lines = lines[1:]
			continue
		}
		if line == "" {
			lines = lines[1:]
			continue
		}
		// Check for a "On <date>, <person> wrote:", we require digits before a quoted
		// line, with an optional empty line in between. If we don't have any text yet, we
		// don't require the digits.
		if strings.HasSuffix(line, ":") && (strings.ContainsAny(line, "0123456789") || result == "") && nextLineQuoted(0) {
			if !resultSnipped() {
				result += "[...]\n"
			}
			lines = lines[1:]
			continue
		}
		// Skip possibly duplicate snipping by author.
		if !isSnipped(line) || !resultSnipped() {
			result += line + "\n"
		}
		lines = lines[1:]
		if len(result) > 250 {
			break
		}
	}
	if len(result) > 250 {
		result = result[:230] + "..."
	}
	return result, scanner.Err()
}

func parsedMessage(log mlog.Log, m store.Message, state *msgState, full, msgitem bool) (pm ParsedMessage, rerr error) {
	pm.ViewMode = store.ModeText // Valid default, in case this makes it to frontend.

	if full || msgitem {
		if !state.ensurePart(m, true) {
			return pm, state.err
		}
		if full {
			pm.Part = *state.part
		}
	} else {
		if !state.ensurePart(m, false) {
			return pm, state.err
		}
	}

	// todo: we should store this form in message.Part, requires a data structure update.

	convertAddrs := func(l []message.Address) []MessageAddress {
		r := make([]MessageAddress, len(l))
		for i, a := range l {
			d, err := dns.ParseDomain(a.Host)
			log.Check(err, "parsing domain")
			if err != nil {
				d = dns.Domain{ASCII: a.Host}
			}
			r[i] = MessageAddress{a.Name, a.User, d}
		}
		return r
	}

	if full || msgitem {
		env := MessageEnvelope{}
		if state.part.Envelope != nil {
			e := *state.part.Envelope
			env.Date = e.Date
			env.Subject = e.Subject
			env.InReplyTo = e.InReplyTo
			env.MessageID = e.MessageID
			env.From = convertAddrs(e.From)
			env.Sender = convertAddrs(e.Sender)
			env.ReplyTo = convertAddrs(e.ReplyTo)
			env.To = convertAddrs(e.To)
			env.CC = convertAddrs(e.CC)
			env.BCC = convertAddrs(e.BCC)
		}
		pm.envelope = env
	}

	if full && state.part.BodyOffset > 0 {
		hdrs, err := state.part.Header()
		if err != nil {
			return ParsedMessage{}, fmt.Errorf("parsing headers: %w", err)
		}
		pm.Headers = hdrs

		pm.ListReplyAddress = parseListPostAddress(hdrs.Get("List-Post"))
	} else {
		pm.Headers = map[string][]string{}
	}

	pm.Texts = []string{}

	// We track attachments from multipart/mixed differently from other attachments.
	// The others are often inline, sometimes just some logo's in HTML alternative
	// messages. We want to have our mixed attachments at the start of the list, but
	// our descent-first parsing would result in inline messages first in the typical
	// message.
	var attachmentsMixed []Attachment
	var attachmentsOther []Attachment

	addAttachment := func(a Attachment, isMixed bool) {
		if isMixed {
			attachmentsMixed = append(attachmentsMixed, a)
		} else {
			attachmentsOther = append(attachmentsOther, a)
		}
	}

	// todo: how should we handle messages where a user prefers html, and we want to show it, but it's a DSN that also has textual-only parts? e.g. gmail's dsn where the first part is multipart/related with multipart/alternative, and second part is the regular message/delivery-status. we want to display both the html and the text.

	var usePart func(p message.Part, index int, parent *message.Part, path []int, parentMixed bool)
	usePart = func(p message.Part, index int, parent *message.Part, path []int, parentMixed bool) {
		mt := p.MediaType + "/" + p.MediaSubType
		newParentMixed := mt == "MULTIPART/MIXED"
		for i, sp := range p.Parts {
			if mt == "MULTIPART/SIGNED" && i >= 1 {
				continue
			}
			usePart(sp, i, &p, append(append([]int{}, path...), i), newParentMixed)
		}
		switch mt {
		case "TEXT/PLAIN", "/":
			// Don't include if Content-Disposition attachment.
			if full || msgitem {
				// todo: should have this, and perhaps all content-* headers, preparsed in message.Part?
				h, err := p.Header()
				log.Check(err, "parsing attachment headers", slog.Int64("msgid", m.ID))
				cp := h.Get("Content-Disposition")
				if cp != "" {
					disp, params, err := mime.ParseMediaType(cp)
					log.Check(err, "parsing content-disposition", slog.String("cp", cp))
					if strings.EqualFold(disp, "attachment") {
						name := tryDecodeParam(log, p.ContentTypeParams["name"])
						if name == "" {
							name = tryDecodeParam(log, params["filename"])
						}
						addAttachment(Attachment{path, name, p}, parentMixed)
						return
					}
				}
			}

			if full {
				buf, err := io.ReadAll(&moxio.LimitReader{R: p.ReaderUTF8OrBinary(), Limit: 2 * 1024 * 1024})
				if err != nil {
					rerr = fmt.Errorf("reading text part: %v", err)
					return
				}
				pm.Texts = append(pm.Texts, string(buf))
			}
			if msgitem && pm.firstLine == "" {
				pm.firstLine, rerr = formatFirstLine(p.ReaderUTF8OrBinary())
				if rerr != nil {
					rerr = fmt.Errorf("reading text for first line snippet: %v", rerr)
					return
				}
			}

		case "TEXT/HTML":
			pm.HasHTML = true

		default:
			// todo: see if there is a common nesting messages that are both signed and encrypted.
			if parent == nil && mt == "MULTIPART/SIGNED" {
				pm.isSigned = true
			}
			if parent == nil && mt == "MULTIPART/ENCRYPTED" {
				pm.isEncrypted = true
			}
			// todo: possibly do not include anything below multipart/alternative that starts with text/html, they may be cids. perhaps have a separate list of attachments for the text vs html version?
			if p.MediaType != "MULTIPART" {
				var parentct string
				if parent != nil {
					parentct = parent.MediaType + "/" + parent.MediaSubType
				}

				// Recognize DSNs.
				if parentct == "MULTIPART/REPORT" && index == 1 && (mt == "MESSAGE/GLOBAL-DELIVERY-STATUS" || mt == "MESSAGE/DELIVERY-STATUS") {
					if full {
						buf, err := io.ReadAll(&moxio.LimitReader{R: p.ReaderUTF8OrBinary(), Limit: 1024 * 1024})
						if err != nil {
							rerr = fmt.Errorf("reading text part: %v", err)
							return
						}
						pm.Texts = append(pm.Texts, string(buf))
					}
					return
				}
				if parentct == "MULTIPART/REPORT" && index == 2 && (mt == "MESSAGE/GLOBAL-HEADERS" || mt == "TEXT/RFC822-HEADERS") {
					if full {
						buf, err := io.ReadAll(&moxio.LimitReader{R: p.ReaderUTF8OrBinary(), Limit: 1024 * 1024})
						if err != nil {
							rerr = fmt.Errorf("reading text part: %v", err)
							return
						}
						pm.Texts = append(pm.Texts, string(buf))
					}
					return
				}
				if parentct == "MULTIPART/REPORT" && index == 2 && (mt == "MESSAGE/GLOBAL" || mt == "TEXT/RFC822") {
					addAttachment(Attachment{path, "original.eml", p}, parentMixed)
					return
				}

				name := tryDecodeParam(log, p.ContentTypeParams["name"])
				if name == "" && (full || msgitem) {
					// todo: should have this, and perhaps all content-* headers, preparsed in message.Part?
					h, err := p.Header()
					log.Check(err, "parsing attachment headers", slog.Int64("msgid", m.ID))
					cp := h.Get("Content-Disposition")
					if cp != "" {
						_, params, err := mime.ParseMediaType(cp)
						log.Check(err, "parsing content-disposition", slog.String("cp", cp))
						name = tryDecodeParam(log, params["filename"])
					}
				}
				addAttachment(Attachment{path, name, p}, parentMixed)
			}
		}
	}
	usePart(*state.part, -1, nil, []int{}, false)

	pm.attachments = []Attachment{}
	pm.attachments = append(pm.attachments, attachmentsMixed...)
	pm.attachments = append(pm.attachments, attachmentsOther...)

	if rerr == nil {
		pm.ID = m.ID
	}
	return
}

// parses List-Post header, returning an address if it could be found, and nil otherwise.
func parseListPostAddress(s string) *MessageAddress {
	/*
		Examples:
		List-Post: <mailto:list@host.com>
		List-Post: <mailto:moderator@host.com> (Postings are Moderated)
		List-Post: <mailto:moderator@host.com?subject=list%20posting>
		List-Post: NO (posting not allowed on this list)
		List-Post: <https://groups.google.com/group/golang-dev/post>, <mailto:golang-dev@googlegroups.com>
	*/
	s = strings.TrimSpace(s)
	for s != "" {
		if !strings.HasPrefix(s, "<") {
			return nil
		}
		addr, ns, found := strings.Cut(s[1:], ">")
		if !found {
			return nil
		}
		if strings.HasPrefix(addr, "mailto:") {
			u, err := url.Parse(addr)
			if err != nil {
				return nil
			}
			addr, err := smtp.ParseAddress(u.Opaque)
			if err != nil {
				return nil
			}
			return &MessageAddress{User: addr.Localpart.String(), Domain: addr.Domain}
		}
		s = strings.TrimSpace(ns)
		s = strings.TrimPrefix(s, ",")
		s = strings.TrimSpace(s)
	}
	return nil
}
