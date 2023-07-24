package imapclient

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

func (c *Conn) recorded() string {
	s := string(c.recordBuf)
	c.recordBuf = nil
	c.record = false
	return s
}

func (c *Conn) recordAdd(buf []byte) {
	if c.record {
		c.recordBuf = append(c.recordBuf, buf...)
	}
}

func (c *Conn) xtake(s string) {
	buf := make([]byte, len(s))
	_, err := io.ReadFull(c.r, buf)
	c.xcheckf(err, "taking %q", s)
	if !strings.EqualFold(string(buf), s) {
		c.xerrorf("got %q, expected %q", buf, s)
	}
	c.recordAdd(buf)
}

func (c *Conn) readbyte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.recordAdd([]byte{b})
	}
	return b, err
}

func (c *Conn) unreadbyte() {
	if c.record {
		c.recordBuf = c.recordBuf[:len(c.recordBuf)-1]
	}
	err := c.r.UnreadByte()
	c.xcheckf(err, "unread byte")
}

func (c *Conn) readrune() (rune, error) {
	x, _, err := c.r.ReadRune()
	if err == nil {
		c.recordAdd([]byte(string(x)))
	}
	return x, err
}

func (c *Conn) xspace() {
	c.xtake(" ")
}

func (c *Conn) xcrlf() {
	c.xtake("\r\n")
}

func (c *Conn) peek(exp byte) bool {
	b, err := c.readbyte()
	if err == nil {
		c.unreadbyte()
	}
	return err == nil && strings.EqualFold(string(rune(b)), string(rune(exp)))
}

func (c *Conn) take(exp byte) bool {
	if c.peek(exp) {
		_, _ = c.readbyte()
		return true
	}
	return false
}

func (c *Conn) xstatus() Status {
	w := c.xword()
	W := strings.ToUpper(w)
	switch W {
	case "OK":
		return OK
	case "NO":
		return NO
	case "BAD":
		return BAD
	}
	c.xerrorf("expected status, got %q", w)
	panic("not reached")
}

// Already consumed: tag SP status SP
func (c *Conn) xresult(status Status) Result {
	respText := c.xrespText()
	return Result{status, respText}
}

func (c *Conn) xrespText() RespText {
	var code string
	var codeArg CodeArg
	if c.take('[') {
		code, codeArg = c.xrespCode()
		c.xtake("]")
		c.xspace()
	}
	more := ""
	for !c.peek('\r') {
		more += string(rune(c.xbyte()))
	}
	return RespText{code, codeArg, more}
}

var knownCodes = stringMap(
	// Without parameters.
	"ALERT", "PARSE", "READ-ONLY", "READ-WRITE", "TRYCREATE", "UIDNOTSTICKY", "UNAVAILABLE", "AUTHENTICATIONFAILED", "AUTHORIZATIONFAILED", "EXPIRED", "PRIVACYREQUIRED", "CONTACTADMIN", "NOPERM", "INUSE", "EXPUNGEISSUED", "CORRUPTION", "SERVERBUG", "CLIENTBUG", "CANNOT", "LIMIT", "OVERQUOTA", "ALREADYEXISTS", "NONEXISTENT", "NOTSAVED", "HASCHILDREN", "CLOSED", "UNKNOWN-CTE",
	// With parameters.
	"BADCHARSET", "CAPABILITY", "PERMANENTFLAGS", "UIDNEXT", "UIDVALIDITY", "UNSEEN", "APPENDUID", "COPYUID",
	"HIGHESTMODSEQ", "MODIFIED",
)

func stringMap(l ...string) map[string]struct{} {
	r := map[string]struct{}{}
	for _, s := range l {
		r[s] = struct{}{}
	}
	return r
}

// ../rfc/9051:6895
func (c *Conn) xrespCode() (string, CodeArg) {
	w := ""
	for !c.peek(' ') && !c.peek(']') {
		w += string(rune(c.xbyte()))
	}
	W := strings.ToUpper(w)

	if _, ok := knownCodes[W]; !ok {
		var args []string
		for c.take(' ') {
			arg := ""
			for !c.peek(' ') && !c.peek(']') {
				arg += string(rune(c.xbyte()))
			}
			args = append(args, arg)
		}
		return W, CodeOther{W, args}
	}

	var codeArg CodeArg
	switch W {
	case "BADCHARSET":
		var l []string // Must be nil initially.
		if c.take(' ') {
			c.xtake("(")
			l = []string{c.xcharset()}
			for c.take(' ') {
				l = append(l, c.xcharset())
			}
			c.xtake(")")
		}
		codeArg = CodeList{W, l}
	case "CAPABILITY":
		c.xtake(" ")
		caps := []string{c.xatom()}
		for c.take(' ') {
			caps = append(caps, c.xatom())
		}
		c.CapAvailable = map[Capability]struct{}{}
		for _, cap := range caps {
			c.CapAvailable[Capability(cap)] = struct{}{}
		}
		codeArg = CodeWords{W, caps}

	case "PERMANENTFLAGS":
		l := []string{} // Must be non-nil.
		if c.take(' ') {
			c.xtake("(")
			l = []string{c.xflagPerm()}
			for c.take(' ') {
				l = append(l, c.xflagPerm())
			}
			c.xtake(")")
		}
		codeArg = CodeList{W, l}
	case "UIDNEXT", "UIDVALIDITY", "UNSEEN":
		c.xspace()
		codeArg = CodeUint{W, c.xnzuint32()}
	case "APPENDUID":
		c.xspace()
		destUIDValidity := c.xnzuint32()
		c.xspace()
		uid := c.xnzuint32()
		codeArg = CodeAppendUID{destUIDValidity, uid}
	case "COPYUID":
		c.xspace()
		destUIDValidity := c.xnzuint32()
		c.xspace()
		from := c.xuidset()
		c.xspace()
		to := c.xuidset()
		codeArg = CodeCopyUID{destUIDValidity, from, to}
	case "HIGHESTMODSEQ":
		c.xspace()
		codeArg = CodeHighestModSeq(c.xint64())
	case "MODIFIED":
		c.xspace()
		modified := c.xuidset()
		codeArg = CodeModified(NumSet{Ranges: modified})
	}
	return W, codeArg
}

func (c *Conn) xbyte() byte {
	b, err := c.readbyte()
	c.xcheckf(err, "read byte")
	return b
}

// take until b is seen. don't take b itself.
func (c *Conn) xtakeuntil(b byte) string {
	var s string
	for {
		x, err := c.readbyte()
		c.xcheckf(err, "read byte")
		if x == b {
			c.unreadbyte()
			return s
		}
		s += string(rune(x))
	}
}

func (c *Conn) xdigits() string {
	var s string
	for {
		b, err := c.readbyte()
		if err == nil && (b >= '0' && b <= '9') {
			s += string(rune(b))
			continue
		}
		c.unreadbyte()
		return s
	}
}

func (c *Conn) xint32() int32 {
	s := c.xdigits()
	num, err := strconv.ParseInt(s, 10, 32)
	c.xcheckf(err, "parsing int32")
	return int32(num)
}

func (c *Conn) xint64() int64 {
	s := c.xdigits()
	num, err := strconv.ParseInt(s, 10, 63)
	c.xcheckf(err, "parsing int64")
	return num
}

func (c *Conn) xuint32() uint32 {
	s := c.xdigits()
	num, err := strconv.ParseUint(s, 10, 32)
	c.xcheckf(err, "parsing uint32")
	return uint32(num)
}

func (c *Conn) xnzuint32() uint32 {
	v := c.xuint32()
	if v == 0 {
		c.xerrorf("got 0, expected nonzero uint")
	}
	return v
}

// todo: replace with proper parsing.
func (c *Conn) xnonspace() string {
	var s string
	for !c.peek(' ') && !c.peek('\r') && !c.peek('\n') {
		s += string(rune(c.xbyte()))
	}
	if s == "" {
		c.xerrorf("expected non-space")
	}
	return s
}

// todo: replace with proper parsing
func (c *Conn) xword() string {
	return c.xatom()
}

// "*" SP is already consumed
// ../rfc/9051:6868
func (c *Conn) xuntagged() Untagged {
	w := c.xnonspace()
	W := strings.ToUpper(w)
	switch W {
	case "PREAUTH":
		c.xspace()
		r := UntaggedPreauth(c.xrespText())
		c.xcrlf()
		return r

	case "BYE":
		c.xspace()
		r := UntaggedBye(c.xrespText())
		c.xcrlf()
		return r

	case "OK", "NO", "BAD":
		c.xspace()
		r := UntaggedResult(c.xresult(Status(W)))
		c.xcrlf()
		return r

	case "CAPABILITY":
		// ../rfc/9051:6427
		var caps []string
		for c.take(' ') {
			caps = append(caps, c.xnonspace())
		}
		c.CapAvailable = map[Capability]struct{}{}
		for _, cap := range caps {
			c.CapAvailable[Capability(cap)] = struct{}{}
		}
		r := UntaggedCapability(caps)
		c.xcrlf()
		return r

	case "ENABLED":
		// ../rfc/9051:6520
		var caps []string
		for c.take(' ') {
			caps = append(caps, c.xnonspace())
		}
		for _, cap := range caps {
			c.CapEnabled[Capability(cap)] = struct{}{}
		}
		r := UntaggedEnabled(caps)
		c.xcrlf()
		return r

	case "FLAGS":
		c.xspace()
		r := UntaggedFlags(c.xflagList())
		c.xcrlf()
		return r

	case "LIST":
		c.xspace()
		r := c.xmailboxList()
		c.xcrlf()
		return r

	case "STATUS":
		// ../rfc/9051:6681
		c.xspace()
		mailbox := c.xastring()
		c.xspace()
		c.xtake("(")
		attrs := map[string]int64{}
		for !c.take(')') {
			if len(attrs) > 0 {
				c.xspace()
			}
			s := c.xword()
			c.xspace()
			S := strings.ToUpper(s)
			var num int64
			// ../rfc/9051:7059
			switch S {
			case "MESSAGES":
				num = int64(c.xuint32())
			case "UIDNEXT":
				num = int64(c.xnzuint32())
			case "UIDVALIDITY":
				num = int64(c.xnzuint32())
			case "UNSEEN":
				num = int64(c.xuint32())
			case "DELETED":
				num = int64(c.xuint32())
			case "SIZE":
				num = c.xint64()
			case "RECENT":
				c.xneedDisabled("RECENT status flag", CapIMAP4rev2)
				num = int64(c.xuint32())
			case "APPENDLIMIT":
				if c.peek('n') || c.peek('N') {
					c.xtake("nil")
				} else {
					num = c.xint64()
				}
			case "HIGHESTMODSEQ":
				num = c.xint64()
			default:
				c.xerrorf("status: unknown attribute %q", s)
			}
			if _, ok := attrs[S]; ok {
				c.xerrorf("status: duplicate attribute %q", s)
			}
			attrs[S] = num
		}
		r := UntaggedStatus{mailbox, attrs}
		c.xcrlf()
		return r

	case "NAMESPACE":
		// ../rfc/9051:6778
		c.xspace()
		personal := c.xnamespace()
		c.xspace()
		other := c.xnamespace()
		c.xspace()
		shared := c.xnamespace()
		r := UntaggedNamespace{personal, other, shared}
		c.xcrlf()
		return r

	case "SEARCH":
		// ../rfc/9051:6809
		c.xneedDisabled("untagged SEARCH response", CapIMAP4rev2)
		var nums []uint32
		for c.take(' ') {
			// ../rfc/7162:2557
			if c.take('(') {
				c.xtake("MODSEQ")
				c.xspace()
				modseq := c.xint64()
				c.xtake(")")
				c.xcrlf()
				return UntaggedSearchModSeq{nums, modseq}
			}
			nums = append(nums, c.xnzuint32())
		}
		r := UntaggedSearch(nums)
		c.xcrlf()
		return r

	case "ESEARCH":
		r := c.xesearchResponse()
		c.xcrlf()
		return r

	case "LSUB":
		c.xneedDisabled("untagged LSUB response", CapIMAP4rev2)
		r := c.xlsub()
		c.xcrlf()
		return r

	case "ID":
		// ../rfc/2971:243
		c.xspace()
		var params map[string]string
		if c.take('(') {
			params = map[string]string{}
			for !c.take(')') {
				if len(params) > 0 {
					c.xspace()
				}
				k := c.xstring()
				c.xspace()
				v := c.xnilString()
				if _, ok := params[k]; ok {
					c.xerrorf("duplicate key %q", k)
				}
				params[k] = v
			}
		} else {
			c.xtake("NIL")
		}
		c.xcrlf()
		return UntaggedID(params)

	// ../rfc/7162:2623
	case "VANISHED":
		c.xspace()
		var earlier bool
		if c.take('(') {
			c.xtake("EARLIER")
			c.xtake(")")
			c.xspace()
			earlier = true
		}
		uids := c.xuidset()
		c.xcrlf()
		return UntaggedVanished{earlier, NumSet{Ranges: uids}}

	default:
		v, err := strconv.ParseUint(w, 10, 32)
		if err == nil {
			num := uint32(v)
			c.xspace()
			w = c.xword()
			W = strings.ToUpper(w)
			switch W {
			case "FETCH":
				if num == 0 {
					c.xerrorf("invalid zero number for untagged fetch response")
				}
				c.xspace()
				r := c.xfetch(num)
				c.xcrlf()
				return r

			case "EXPUNGE":
				if num == 0 {
					c.xerrorf("invalid zero number for untagged expunge response")
				}
				c.xcrlf()
				return UntaggedExpunge(num)

			case "EXISTS":
				c.xcrlf()
				return UntaggedExists(num)

			case "RECENT":
				c.xneedDisabled("should not send RECENT in IMAP4rev2", CapIMAP4rev2)
				c.xcrlf()
				return UntaggedRecent(num)

			default:
				c.xerrorf("unknown untagged numbered response %q", w)
				panic("not reached")
			}
		}
		c.xerrorf("unknown untagged response %q", w)
	}
	panic("not reached")
}

// ../rfc/3501:4864 ../rfc/9051:6742
// Already parsed: "*" SP nznumber SP "FETCH" SP
func (c *Conn) xfetch(num uint32) UntaggedFetch {
	c.xtake("(")
	attrs := []FetchAttr{c.xmsgatt1()}
	for c.take(' ') {
		attrs = append(attrs, c.xmsgatt1())
	}
	c.xtake(")")
	return UntaggedFetch{num, attrs}
}

// ../rfc/9051:6746
func (c *Conn) xmsgatt1() FetchAttr {
	f := ""
	for {
		b := c.xbyte()
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' {
			f += string(rune(b))
			continue
		}
		c.unreadbyte()
		break
	}

	F := strings.ToUpper(f)
	switch F {
	case "FLAGS":
		c.xspace()
		c.xtake("(")
		var flags []string
		if !c.take(')') {
			flags = []string{c.xflag()}
			for c.take(' ') {
				flags = append(flags, c.xflag())
			}
			c.xtake(")")
		}
		return FetchFlags(flags)

	case "ENVELOPE":
		c.xspace()
		return FetchEnvelope(c.xenvelope())

	case "INTERNALDATE":
		c.xspace()
		return FetchInternalDate(c.xquoted()) // todo: parsed time

	case "RFC822.SIZE":
		c.xspace()
		return FetchRFC822Size(c.xint64())

	case "RFC822":
		c.xspace()
		s := c.xnilString()
		return FetchRFC822(s)

	case "RFC822.HEADER":
		c.xspace()
		s := c.xnilString()
		return FetchRFC822Header(s)

	case "RFC822.TEXT":
		c.xspace()
		s := c.xnilString()
		return FetchRFC822Text(s)

	case "BODY":
		if c.take(' ') {
			return FetchBodystructure{F, c.xbodystructure()}
		}
		c.record = true
		section := c.xsection()
		var offset int32
		if c.take('<') {
			offset = c.xint32()
			c.xtake(">")
		}
		F += c.recorded()
		c.xspace()
		body := c.xnilString()
		return FetchBody{F, section, offset, body}

	case "BODYSTRUCTURE":
		c.xspace()
		return FetchBodystructure{F, c.xbodystructure()}

	case "BINARY":
		c.record = true
		nums := c.xsectionBinary()
		F += c.recorded()
		c.xspace()
		buf := c.xnilStringLiteral8()
		return FetchBinary{F, nums, string(buf)}

	case "BINARY.SIZE":
		c.record = true
		nums := c.xsectionBinary()
		F += c.recorded()
		c.xspace()
		size := c.xint64()
		return FetchBinarySize{F, nums, size}

	case "UID":
		c.xspace()
		return FetchUID(c.xuint32())

	case "MODSEQ":
		// ../rfc/7162:2488
		c.xspace()
		c.xtake("(")
		modseq := c.xint64()
		c.xtake(")")
		return FetchModSeq(modseq)
	}
	c.xerrorf("unknown fetch attribute %q", f)
	panic("not reached")
}

func (c *Conn) xnilString() string {
	if c.peek('"') {
		return c.xquoted()
	} else if c.peek('{') {
		return string(c.xliteral())
	} else {
		c.xtake("NIL")
		return ""
	}
}

func (c *Conn) xstring() string {
	if c.peek('"') {
		return c.xquoted()
	}
	return string(c.xliteral())
}

func (c *Conn) xastring() string {
	if c.peek('"') {
		return c.xquoted()
	} else if c.peek('{') {
		return string(c.xliteral())
	}
	return c.xatom()
}

func (c *Conn) xatom() string {
	var s string
	for {
		b, err := c.readbyte()
		c.xcheckf(err, "read byte for flag")
		if b <= ' ' || strings.IndexByte("(){%*\"\\]", b) >= 0 {
			c.r.UnreadByte()
			if s == "" {
				c.xerrorf("expected atom")
			}
			return s
		}
		s += string(rune(b))
	}
}

// ../rfc/9051:6856 ../rfc/6855:153
func (c *Conn) xquoted() string {
	c.xtake(`"`)
	s := ""
	for !c.take('"') {
		r, err := c.readrune()
		c.xcheckf(err, "reading rune in quoted string")
		if r == '\\' {
			r, err = c.readrune()
			c.xcheckf(err, "reading escaped char in quoted string")
			if r != '\\' && r != '"' {
				c.xerrorf("quoted char not backslash or dquote: %c", r)
			}
		}
		// todo: probably refuse some more chars. like \0 and all ctl and backspace.
		s += string(r)
	}
	return s
}

func (c *Conn) xliteral() []byte {
	c.xtake("{")
	size := c.xint64()
	sync := c.take('+')
	c.xtake("}")
	c.xcrlf()
	if size > 1<<20 {
		c.xerrorf("refusing to read more than 1MB: %d", size)
	}
	if sync {
		_, err := fmt.Fprintf(c.conn, "+ ok\r\n")
		c.xcheckf(err, "write continuation")
	}
	buf := make([]byte, int(size))
	_, err := io.ReadFull(c.r, buf)
	c.xcheckf(err, "reading data for literal")
	return buf
}

// ../rfc/9051:6565
// todo: stricter
func (c *Conn) xflag0(allowPerm bool) string {
	s := ""
	if c.take('\\') {
		s = `\`
		if allowPerm && c.take('*') {
			return `\*`
		}
	} else if c.take('$') {
		s = "$"
	}
	s += c.xatom()
	return s
}

func (c *Conn) xflag() string {
	return c.xflag0(false)
}

func (c *Conn) xflagPerm() string {
	return c.xflag0(true)
}

func (c *Conn) xsection() string {
	c.xtake("[")
	s := c.xtakeuntil(']')
	c.xtake("]")
	return s
}

func (c *Conn) xsectionBinary() []uint32 {
	c.xtake("[")
	var nums []uint32
	for !c.take(']') {
		if len(nums) > 0 {
			c.xtake(".")
		}
		nums = append(nums, c.xnzuint32())
	}
	return nums
}

func (c *Conn) xnilStringLiteral8() []byte {
	// todo: should make difference for literal8 and literal from string, which bytes are allowed
	if c.take('~') || c.peek('{') {
		return c.xliteral()
	}
	return []byte(c.xnilString())
}

// ../rfc/9051:6355
func (c *Conn) xbodystructure() any {
	c.xtake("(")
	if c.peek('(') {
		// ../rfc/9051:6411
		parts := []any{c.xbodystructure()}
		for c.peek('(') {
			parts = append(parts, c.xbodystructure())
		}
		c.xspace()
		mediaSubtype := c.xstring()
		// todo: parse optional body-ext-mpart
		c.xtake(")")
		return BodyTypeMpart{parts, mediaSubtype}
	}

	mediaType := c.xstring()
	c.xspace()
	mediaSubtype := c.xstring()
	c.xspace()
	bodyFields := c.xbodyFields()
	if c.take(' ') {
		if c.peek('(') {
			// ../rfc/9051:6415
			envelope := c.xenvelope()
			c.xspace()
			bodyStructure := c.xbodystructure()
			c.xspace()
			lines := c.xint64()
			c.xtake(")")
			return BodyTypeMsg{mediaType, mediaSubtype, bodyFields, envelope, bodyStructure, lines}
		}
		// ../rfc/9051:6418
		lines := c.xint64()
		c.xtake(")")
		return BodyTypeText{mediaType, mediaSubtype, bodyFields, lines}
	}
	// ../rfc/9051:6407
	c.xtake(")")
	return BodyTypeBasic{mediaType, mediaSubtype, bodyFields}

	// todo: verify the media(sub)type is valid for returned data.
}

// ../rfc/9051:6376
func (c *Conn) xbodyFields() BodyFields {
	params := c.xbodyFldParam()
	c.xspace()
	contentID := c.xnilString()
	c.xspace()
	contentDescr := c.xnilString()
	c.xspace()
	cte := c.xnilString()
	c.xspace()
	octets := c.xint32()
	return BodyFields{params, contentID, contentDescr, cte, octets}
}

// ../rfc/9051:6401
func (c *Conn) xbodyFldParam() [][2]string {
	if c.take('(') {
		k := c.xstring()
		c.xspace()
		v := c.xstring()
		l := [][2]string{{k, v}}
		for c.take(' ') {
			k = c.xstring()
			c.xspace()
			v = c.xstring()
			l = append(l, [2]string{k, v})
		}
		c.xtake(")")
		return l
	}
	c.xtake("NIL")
	return nil
}

// ../rfc/9051:6522
func (c *Conn) xenvelope() Envelope {
	c.xtake("(")
	date := c.xnilString()
	c.xspace()
	subject := c.xnilString()
	c.xspace()
	from := c.xaddresses()
	c.xspace()
	sender := c.xaddresses()
	c.xspace()
	replyTo := c.xaddresses()
	c.xspace()
	to := c.xaddresses()
	c.xspace()
	cc := c.xaddresses()
	c.xspace()
	bcc := c.xaddresses()
	c.xspace()
	inReplyTo := c.xnilString()
	c.xspace()
	messageID := c.xnilString()
	c.xtake(")")
	return Envelope{date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID}
}

// ../rfc/9051:6526
func (c *Conn) xaddresses() []Address {
	if !c.take('(') {
		c.xtake("NIL")
		return nil
	}
	l := []Address{c.xaddress()}
	for !c.take(')') {
		l = append(l, c.xaddress())
	}
	return l
}

// ../rfc/9051:6303
func (c *Conn) xaddress() Address {
	c.xtake("(")
	name := c.xnilString()
	c.xspace()
	adl := c.xnilString()
	c.xspace()
	mailbox := c.xnilString()
	c.xspace()
	host := c.xnilString()
	c.xtake(")")
	return Address{name, adl, mailbox, host}
}

// ../rfc/9051:6584
func (c *Conn) xflagList() []string {
	c.xtake("(")
	var l []string
	if !c.take(')') {
		l = []string{c.xflag()}
		for c.take(' ') {
			l = append(l, c.xflag())
		}
		c.xtake(")")
	}
	return l
}

// ../rfc/9051:6690
func (c *Conn) xmailboxList() UntaggedList {
	c.xtake("(")
	var flags []string
	if !c.peek(')') {
		flags = append(flags, c.xflag())
		for c.take(' ') {
			flags = append(flags, c.xflag())
		}
	}
	c.xtake(")")
	c.xspace()
	var quoted string
	var b byte
	if c.peek('"') {
		quoted = c.xquoted()
		if len(quoted) != 1 {
			c.xerrorf("mailbox-list has multichar quoted part: %q", quoted)
		}
		b = byte(quoted[0])
	} else if !c.peek(' ') {
		c.xtake("NIL")
	}
	c.xspace()
	mailbox := c.xastring()
	ul := UntaggedList{flags, b, mailbox, nil, ""}
	if c.take(' ') {
		c.xtake("(")
		if !c.peek(')') {
			c.xmboxListExtendedItem(&ul)
			for c.take(' ') {
				c.xmboxListExtendedItem(&ul)
			}
		}
		c.xtake(")")
	}
	return ul
}

// ../rfc/9051:6699
func (c *Conn) xmboxListExtendedItem(ul *UntaggedList) {
	tag := c.xastring()
	c.xspace()
	if strings.ToUpper(tag) == "OLDNAME" {
		// ../rfc/9051:6811
		c.xtake("(")
		name := c.xastring()
		c.xtake(")")
		ul.OldName = name
		return
	}
	val := c.xtaggedExtVal()
	ul.Extended = append(ul.Extended, MboxListExtendedItem{tag, val})
}

// ../rfc/9051:7111
func (c *Conn) xtaggedExtVal() TaggedExtVal {
	if c.take('(') {
		var r TaggedExtVal
		if !c.take(')') {
			comp := c.xtaggedExtComp()
			r.Comp = &comp
			c.xtake(")")
		}
		return r
	}
	// We cannot just parse sequence-set, because we also have to accept number/number64. So first look for a number. If it is not, we continue parsing the rest of the sequence set.
	b, err := c.readbyte()
	c.xcheckf(err, "read byte for tagged-ext-val")
	if b < '0' || b > '9' {
		c.unreadbyte()
		ss := c.xsequenceSet()
		return TaggedExtVal{SeqSet: &ss}
	}
	s := c.xdigits()
	num, err := strconv.ParseInt(s, 10, 63)
	c.xcheckf(err, "parsing int")
	if !c.peek(':') && !c.peek(',') {
		// not a larger sequence-set
		return TaggedExtVal{Number: &num}
	}
	var sr NumRange
	sr.First = uint32(num)
	if c.take(':') {
		var num uint32
		if !c.take('*') {
			num = c.xnzuint32()
		}
		sr.Last = &num
	}
	ss := c.xsequenceSet()
	ss.Ranges = append([]NumRange{sr}, ss.Ranges...)
	return TaggedExtVal{SeqSet: &ss}
}

// ../rfc/9051:7034
func (c *Conn) xsequenceSet() NumSet {
	if c.take('$') {
		return NumSet{SearchResult: true}
	}
	var ss NumSet
	for {
		var sr NumRange
		if !c.take('*') {
			sr.First = c.xnzuint32()
		}
		if c.take(':') {
			var num uint32
			if !c.take('*') {
				num = c.xnzuint32()
			}
			sr.Last = &num
		}
		ss.Ranges = append(ss.Ranges, sr)
		if !c.take(',') {
			break
		}
	}
	return ss
}

// ../rfc/9051:7097
func (c *Conn) xtaggedExtComp() TaggedExtComp {
	if c.take('(') {
		r := c.xtaggedExtComp()
		c.xtake(")")
		return TaggedExtComp{Comps: []TaggedExtComp{r}}
	}
	s := c.xastring()
	if !c.peek(' ') {
		return TaggedExtComp{String: s}
	}
	l := []TaggedExtComp{{String: s}}
	for c.take(' ') {
		l = append(l, c.xtaggedExtComp())
	}
	return TaggedExtComp{Comps: l}
}

// ../rfc/9051:6765
func (c *Conn) xnamespace() []NamespaceDescr {
	if !c.take('(') {
		c.xtake("NIL")
		return nil
	}

	l := []NamespaceDescr{c.xnamespaceDescr()}
	for !c.take(')') {
		l = append(l, c.xnamespaceDescr())
	}
	return l
}

// ../rfc/9051:6769
func (c *Conn) xnamespaceDescr() NamespaceDescr {
	c.xtake("(")
	prefix := c.xstring()
	c.xspace()
	var b byte
	if c.peek('"') {
		s := c.xquoted()
		if len(s) != 1 {
			c.xerrorf("namespace-descr: expected single char, got %q", s)
		}
		b = byte(s[0])
	} else {
		c.xtake("NIL")
	}
	var exts []NamespaceExtension
	for !c.take(')') {
		c.xspace()
		key := c.xstring()
		c.xspace()
		c.xtake("(")
		values := []string{c.xstring()}
		for c.take(' ') {
			values = append(values, c.xstring())
		}
		c.xtake(")")
		exts = append(exts, NamespaceExtension{key, values})
	}
	return NamespaceDescr{prefix, b, exts}
}

// require all of caps to be disabled.
func (c *Conn) xneedDisabled(msg string, caps ...Capability) {
	for _, cap := range caps {
		if _, ok := c.CapEnabled[cap]; ok {
			c.xerrorf("%s: invalid because of enabled capability %q", msg, cap)
		}
	}
}

// ../rfc/9051:6546
// Already consumed: "ESEARCH"
func (c *Conn) xesearchResponse() (r UntaggedEsearch) {

	if !c.take(' ') {
		return
	}
	if c.take('(') {
		// ../rfc/9051:6921
		c.xtake("TAG")
		c.xspace()
		r.Correlator = c.xastring()
		c.xtake(")")
	}
	if !c.take(' ') {
		return
	}
	w := c.xnonspace()
	W := strings.ToUpper(w)
	if W == "UID" {
		r.UID = true
		if !c.take(' ') {
			return
		}
		w = c.xnonspace()
		W = strings.ToUpper(w)
	}
	for {
		// ../rfc/9051:6957
		switch W {
		case "MIN":
			if r.Min != 0 {
				c.xerrorf("duplicate MIN in ESEARCH")
			}
			c.xspace()
			num := c.xnzuint32()
			r.Min = num

		case "MAX":
			if r.Max != 0 {
				c.xerrorf("duplicate MAX in ESEARCH")
			}
			c.xspace()
			num := c.xnzuint32()
			r.Max = num

		case "ALL":
			if !r.All.IsZero() {
				c.xerrorf("duplicate ALL in ESEARCH")
			}
			c.xspace()
			ss := c.xsequenceSet()
			if ss.SearchResult {
				c.xerrorf("$ for last not valid in ESEARCH")
			}
			r.All = ss

		case "COUNT":
			if r.Count != nil {
				c.xerrorf("duplicate COUNT in ESEARCH")
			}
			c.xspace()
			num := c.xuint32()
			r.Count = &num

		// ../rfc/7162:1211 ../rfc/4731:273
		case "MODSEQ":
			c.xspace()
			r.ModSeq = c.xint64()

		default:
			// Validate ../rfc/9051:7090
			for i, b := range []byte(w) {
				if !(b >= 'A' && b <= 'Z' || strings.IndexByte("-_.", b) >= 0 || i > 0 && strings.IndexByte("0123456789:", b) >= 0) {
					c.xerrorf("invalid tag %q", w)
				}
			}
			c.xspace()
			ext := EsearchDataExt{w, c.xtaggedExtVal()}
			r.Exts = append(r.Exts, ext)
		}

		if !c.take(' ') {
			break
		}
		w = c.xnonspace() // todo: this is too loose
		W = strings.ToUpper(w)
	}
	return
}

// ../rfc/9051:6441
func (c *Conn) xcharset() string {
	if c.peek('"') {
		return c.xquoted()
	}
	return c.xatom()
}

// ../rfc/9051:7133
func (c *Conn) xuidset() []NumRange {
	ranges := []NumRange{c.xuidrange()}
	for c.take(',') {
		ranges = append(ranges, c.xuidrange())
	}
	return ranges
}

func (c *Conn) xuidrange() NumRange {
	uid := c.xnzuint32()
	var end *uint32
	if c.take(':') {
		x := c.xnzuint32()
		end = &x
	}
	return NumRange{uid, end}
}

// ../rfc/3501:4833
func (c *Conn) xlsub() UntaggedLsub {
	c.xspace()
	c.xtake("(")
	r := UntaggedLsub{}
	for !c.take(')') {
		if len(r.Flags) > 0 {
			c.xspace()
		}
		r.Flags = append(r.Flags, c.xflag())
	}
	c.xspace()
	if c.peek('"') {
		s := c.xquoted()
		if !c.peek(' ') {
			r.Mailbox = s
			return r
		}
		if len(s) != 1 {
			// todo: check valid char
			c.xerrorf("invalid separator %q", s)
		}
		r.Separator = byte(s[0])
	}
	c.xspace()
	r.Mailbox = c.xastring()
	return r
}
