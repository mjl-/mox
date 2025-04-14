package imapclient

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/mlog"
)

// todo: stricter parsing. xnonspace() and xword() should be replaced by proper parsers

// Keep the parsing method names and the types similar to the ABNF names in the RFCs.

func (p *Proto) recorded() string {
	s := string(p.recordBuf)
	p.recordBuf = nil
	p.record = false
	return s
}

func (p *Proto) recordAdd(buf []byte) {
	if p.record {
		p.recordBuf = append(p.recordBuf, buf...)
	}
}

func (p *Proto) xtake(s string) {
	buf := make([]byte, len(s))
	_, err := io.ReadFull(p.br, buf)
	p.xcheckf(err, "taking %q", s)
	if !strings.EqualFold(string(buf), s) {
		p.xerrorf("got %q, expected %q", buf, s)
	}
	p.recordAdd(buf)
}

func (p *Proto) readbyte() (byte, error) {
	b, err := p.br.ReadByte()
	if err == nil {
		p.recordAdd([]byte{b})
	}
	return b, err
}

func (p *Proto) xunreadbyte() {
	if p.record {
		p.recordBuf = p.recordBuf[:len(p.recordBuf)-1]
	}
	err := p.br.UnreadByte()
	p.xcheckf(err, "unread byte")
}

func (p *Proto) readrune() (rune, error) {
	x, _, err := p.br.ReadRune()
	if err == nil {
		p.recordAdd([]byte(string(x)))
	}
	return x, err
}

func (p *Proto) space() bool {
	return p.take(' ')
}

func (p *Proto) xspace() {
	p.xtake(" ")
}

func (p *Proto) xcrlf() {
	p.xtake("\r\n")
}

func (p *Proto) peek(exp byte) bool {
	b, err := p.readbyte()
	if err == nil {
		p.xunreadbyte()
	}
	return err == nil && strings.EqualFold(string(rune(b)), string(rune(exp)))
}

func (p *Proto) peekstring() bool {
	return p.peek('"') || p.peek('{')
}

func (p *Proto) take(exp byte) bool {
	if p.peek(exp) {
		_, _ = p.readbyte()
		return true
	}
	return false
}

func (p *Proto) xstatus() Status {
	w := p.xword()
	W := strings.ToUpper(w)
	switch W {
	case "OK":
		return OK
	case "NO":
		return NO
	case "BAD":
		return BAD
	}
	p.xerrorf("expected status, got %q", w)
	panic("not reached")
}

// Already consumed: tag SP status SP
func (p *Proto) xresult(status Status) Result {
	code, text := p.xrespText()
	return Result{status, code, text}
}

func (p *Proto) xrespText() (code Code, text string) {
	if p.take('[') {
		code = p.xrespCode()
		p.xtake("]")
		p.xspace()
	}
	for !p.peek('\r') {
		text += string(rune(p.xbyte()))
	}
	return
}

// ../rfc/9051:6895
func (p *Proto) xrespCode() Code {
	w := ""
	for !p.peek(' ') && !p.peek(']') {
		w += string(rune(p.xbyte()))
	}
	W := strings.ToUpper(w)

	switch W {
	case "BADCHARSET":
		var l []string // Must be nil initially.
		if p.space() {
			p.xtake("(")
			l = []string{p.xcharset()}
			for p.space() {
				l = append(l, p.xcharset())
			}
			p.xtake(")")
		}
		return CodeBadCharset(l)
	case "CAPABILITY":
		p.xtake(" ")
		caps := []Capability{}
		for {
			s := p.xatom()
			s = strings.ToUpper(s)
			caps = append(caps, Capability(s))
			if !p.space() {
				break
			}
		}
		return CodeCapability(caps)
	case "PERMANENTFLAGS":
		l := []string{} // Must be non-nil.
		if p.space() {
			p.xtake("(")
			l = []string{p.xflagPerm()}
			for p.space() {
				l = append(l, p.xflagPerm())
			}
			p.xtake(")")
		}
		return CodePermanentFlags(l)
	case "UIDNEXT":
		p.xspace()
		return CodeUIDNext(p.xnzuint32())
	case "UIDVALIDITY":
		p.xspace()
		return CodeUIDValidity(p.xnzuint32())
	case "UNSEEN":
		p.xspace()
		return CodeUnseen(p.xnzuint32())
	case "APPENDUID":
		p.xspace()
		destUIDValidity := p.xnzuint32()
		p.xspace()
		uids := p.xuidrange()
		return CodeAppendUID{destUIDValidity, uids}
	case "COPYUID":
		p.xspace()
		destUIDValidity := p.xnzuint32()
		p.xspace()
		from := p.xuidset()
		p.xspace()
		to := p.xuidset()
		return CodeCopyUID{destUIDValidity, from, to}
	case "HIGHESTMODSEQ":
		p.xspace()
		return CodeHighestModSeq(p.xint64())
	case "MODIFIED":
		p.xspace()
		modified := p.xuidset()
		return CodeModified(NumSet{Ranges: modified})
	case "INPROGRESS":
		// ../rfc/9585:238
		var tag string
		var current, goal *uint32
		if p.space() {
			p.xtake("(")
			tag = p.xquoted()
			p.xspace()
			if p.peek('n') || p.peek('N') {
				p.xtake("nil")
			} else {
				v := p.xuint32()
				current = &v
			}
			p.xspace()
			if p.peek('n') || p.peek('N') {
				p.xtake("nil")
			} else {
				v := p.xnzuint32()
				goal = &v
			}
			p.xtake(")")
		}
		return CodeInProgress{tag, current, goal}
	case "BADEVENT":
		// ../rfc/5465:1033
		p.xspace()
		p.xtake("(")
		var l []string
		for {
			s := p.xatom()
			l = append(l, s)
			if !p.space() {
				break
			}
		}
		p.xtake(")")
		return CodeBadEvent(l)

	case "METADATA":
		p.xspace()
		if !p.take('(') {
			p.xtake("LONGENTRIES")
			p.xspace()
			num := p.xuint32()
			return CodeMetadataLongEntries(num)
		}
		w := strings.ToUpper(p.xatom())
		switch w {
		case "MAXSIZE":
			p.xspace()
			num := p.xuint32()
			p.xtake(")")
			return CodeMetadataMaxSize(num)
		case "TOOMANY":
			p.xtake(")")
			return CodeMetadataTooMany{}
		case "NOPRIVATE":
			p.xtake(")")
			return CodeMetadataNoPrivate{}
		}
		p.xerrorf("parsing METADATA response code, got %q, expected one of MAXSIZE, TOOMANY, NOPRIVATE", w)
		panic("not reached")

	// Known codes without parameters.
	case "ALERT",
		"PARSE",
		"READ-ONLY",
		"READ-WRITE",
		"TRYCREATE",
		"UIDNOTSTICKY",
		"UNAVAILABLE",
		"AUTHENTICATIONFAILED",
		"AUTHORIZATIONFAILED",
		"EXPIRED",
		"PRIVACYREQUIRED",
		"CONTACTADMIN",
		"NOPERM",
		"INUSE",
		"EXPUNGEISSUED",
		"CORRUPTION",
		"SERVERBUG",
		"CLIENTBUG",
		"CANNOT",
		"LIMIT",
		"ALREADYEXISTS",
		"NONEXISTENT",
		"NOTSAVED",
		"HASCHILDREN",
		"CLOSED",
		"UNKNOWN-CTE",
		"OVERQUOTA",            // ../rfc/9208:472
		"COMPRESSIONACTIVE",    // ../rfc/4978:143
		"NOTIFICATIONOVERFLOW", // ../rfc/5465:1023
		"UIDREQUIRED":          // ../rfc/9586:136
		return CodeWord(W)

	default:
		var args []string
		for p.space() {
			arg := ""
			for !p.peek(' ') && !p.peek(']') {
				arg += string(rune(p.xbyte()))
			}
			args = append(args, arg)
		}
		if len(args) == 0 {
			return CodeWord(W)
		}
		return CodeParams{W, args}
	}
}

func (p *Proto) xbyte() byte {
	b, err := p.readbyte()
	p.xcheckf(err, "read byte")
	return b
}

// take until b is seen. don't take b itself.
func (p *Proto) xtakeuntil(b byte) string {
	var s string
	for {
		x, err := p.readbyte()
		p.xcheckf(err, "read byte")
		if x == b {
			p.xunreadbyte()
			return s
		}
		s += string(rune(x))
	}
}

func (p *Proto) xdigits() string {
	var s string
	for {
		b, err := p.readbyte()
		if err == nil && (b >= '0' && b <= '9') {
			s += string(rune(b))
			continue
		}
		p.xunreadbyte()
		return s
	}
}

func (p *Proto) peekdigit() bool {
	if b, err := p.readbyte(); err == nil {
		p.xunreadbyte()
		return b >= '0' && b <= '9'
	}
	return false
}

func (p *Proto) xint32() int32 {
	s := p.xdigits()
	num, err := strconv.ParseInt(s, 10, 32)
	p.xcheckf(err, "parsing int32")
	return int32(num)
}

func (p *Proto) xint64() int64 {
	s := p.xdigits()
	num, err := strconv.ParseInt(s, 10, 63)
	p.xcheckf(err, "parsing int64")
	return num
}

func (p *Proto) xuint32() uint32 {
	s := p.xdigits()
	num, err := strconv.ParseUint(s, 10, 32)
	p.xcheckf(err, "parsing uint32")
	return uint32(num)
}

func (p *Proto) xnzuint32() uint32 {
	v := p.xuint32()
	if v == 0 {
		p.xerrorf("got 0, expected nonzero uint")
	}
	return v
}

// todo: replace with proper parsing.
func (p *Proto) xnonspace() string {
	var s string
	for !p.peek(' ') && !p.peek('\r') && !p.peek('\n') {
		s += string(rune(p.xbyte()))
	}
	if s == "" {
		p.xerrorf("expected non-space")
	}
	return s
}

// todo: replace with proper parsing
func (p *Proto) xword() string {
	return p.xatom()
}

// "*" SP is already consumed
// ../rfc/9051:6868
func (p *Proto) xuntagged() Untagged {
	w := p.xnonspace()
	W := strings.ToUpper(w)
	switch W {
	case "PREAUTH":
		p.xspace()
		code, text := p.xrespText()
		r := UntaggedPreauth{code, text}
		p.xcrlf()
		return r

	case "BYE":
		p.xspace()
		code, text := p.xrespText()
		r := UntaggedBye{code, text}
		p.xcrlf()
		return r

	case "OK", "NO", "BAD":
		p.xspace()
		r := UntaggedResult(p.xresult(Status(W)))
		p.xcrlf()
		return r

	case "CAPABILITY":
		// ../rfc/9051:6427
		var caps []Capability
		for p.space() {
			s := p.xnonspace()
			s = strings.ToUpper(s)
			cc := Capability(s)
			caps = append(caps, cc)
		}
		p.xcrlf()
		return UntaggedCapability(caps)

	case "ENABLED":
		// ../rfc/9051:6520
		var caps []Capability
		for p.space() {
			s := p.xnonspace()
			s = strings.ToUpper(s)
			cc := Capability(s)
			caps = append(caps, cc)
		}
		p.xcrlf()
		return UntaggedEnabled(caps)

	case "FLAGS":
		p.xspace()
		r := UntaggedFlags(p.xflagList())
		p.xcrlf()
		return r

	case "LIST":
		p.xspace()
		r := p.xmailboxList()
		p.xcrlf()
		return r

	case "STATUS":
		// ../rfc/9051:6681
		p.xspace()
		mailbox := p.xastring()
		p.xspace()
		p.xtake("(")
		attrs := map[StatusAttr]int64{}
		for !p.take(')') {
			if len(attrs) > 0 {
				p.xspace()
			}
			s := p.xatom()
			p.xspace()
			S := StatusAttr(strings.ToUpper(s))
			var num int64
			// ../rfc/9051:7059
			switch S {
			case "MESSAGES":
				num = int64(p.xuint32())
			case "UIDNEXT":
				num = int64(p.xnzuint32())
			case "UIDVALIDITY":
				num = int64(p.xnzuint32())
			case "UNSEEN":
				num = int64(p.xuint32())
			case "DELETED":
				num = int64(p.xuint32())
			case "SIZE":
				num = p.xint64()
			case "RECENT":
				num = int64(p.xuint32())
			case "APPENDLIMIT":
				if p.peek('n') || p.peek('N') {
					p.xtake("nil")
				} else {
					num = p.xint64()
				}
			case "HIGHESTMODSEQ":
				num = p.xint64()
			case "DELETED-STORAGE":
				num = p.xint64()
			default:
				p.xerrorf("status: unknown attribute %q", s)
			}
			if _, ok := attrs[S]; ok {
				p.xerrorf("status: duplicate attribute %q", s)
			}
			attrs[S] = num
		}
		r := UntaggedStatus{mailbox, attrs}
		p.xcrlf()
		return r

	case "METADATA":
		// ../rfc/5464:807
		p.xspace()
		mailbox := p.xastring()
		p.xspace()
		if !p.take('(') {
			// Unsolicited form, with only annotation keys, not values.
			var keys []string
			for {
				key := p.xastring()
				keys = append(keys, key)
				if !p.space() {
					break
				}
			}
			p.xcrlf()
			return UntaggedMetadataKeys{mailbox, keys}
		}

		// Form with values, in response to GETMETADATA command.
		r := UntaggedMetadataAnnotations{Mailbox: mailbox}
		for {
			key := p.xastring()
			p.xspace()
			var value []byte
			var isString bool
			if p.take('~') {
				value = p.xliteral()
			} else if p.peek('"') {
				value = []byte(p.xstring())
				isString = true
				// note: the abnf also allows nstring, but that only makes sense when the
				// production rule is used in the setmetadata command. ../rfc/5464:831
			} else {
				// For response to extended list.
				p.xtake("nil")
			}
			r.Annotations = append(r.Annotations, Annotation{key, isString, value})

			if p.take(')') {
				break
			}
			p.xspace()
		}
		p.xcrlf()
		return r

	case "NAMESPACE":
		// ../rfc/9051:6778
		p.xspace()
		personal := p.xnamespace()
		p.xspace()
		other := p.xnamespace()
		p.xspace()
		shared := p.xnamespace()
		r := UntaggedNamespace{personal, other, shared}
		p.xcrlf()
		return r

	case "SEARCH":
		// ../rfc/9051:6809
		var nums []uint32
		for p.space() {
			// ../rfc/7162:2557
			if p.take('(') {
				p.xtake("MODSEQ")
				p.xspace()
				modseq := p.xint64()
				p.xtake(")")
				p.xcrlf()
				return UntaggedSearchModSeq{nums, modseq}
			}
			nums = append(nums, p.xnzuint32())
		}
		r := UntaggedSearch(nums)
		p.xcrlf()
		return r

	case "ESEARCH":
		r := p.xesearchResponse()
		p.xcrlf()
		return r

	case "LSUB":
		r := p.xlsub()
		p.xcrlf()
		return r

	case "ID":
		// ../rfc/2971:243
		p.xspace()
		var params map[string]string
		if p.take('(') {
			params = map[string]string{}
			for !p.take(')') {
				if len(params) > 0 {
					p.xspace()
				}
				k := p.xstring()
				p.xspace()
				v := p.xnilString()
				if _, ok := params[k]; ok {
					p.xerrorf("duplicate key %q", k)
				}
				params[k] = v
			}
		} else {
			p.xtake("nil")
		}
		p.xcrlf()
		return UntaggedID(params)

	// ../rfc/7162:2623
	case "VANISHED":
		p.xspace()
		var earlier bool
		if p.take('(') {
			p.xtake("EARLIER")
			p.xtake(")")
			p.xspace()
			earlier = true
		}
		uids := p.xuidset()
		p.xcrlf()
		return UntaggedVanished{earlier, NumSet{Ranges: uids}}

	// ../rfc/9208:668 ../2087:242
	case "QUOTAROOT":
		p.xspace()
		p.xastring()
		var roots []string
		for p.space() {
			root := p.xastring()
			roots = append(roots, root)
		}
		p.xcrlf()
		return UntaggedQuotaroot(roots)

	// ../rfc/9208:666 ../rfc/2087:239
	case "QUOTA":
		p.xspace()
		root := p.xastring()
		p.xspace()
		p.xtake("(")

		xresource := func() QuotaResource {
			name := p.xatom()
			p.xspace()
			usage := p.xint64()
			p.xspace()
			limit := p.xint64()
			return QuotaResource{QuotaResourceName(strings.ToUpper(name)), usage, limit}
		}

		seen := map[QuotaResourceName]bool{}
		l := []QuotaResource{xresource()}
		seen[l[0].Name] = true
		for p.space() {
			res := xresource()
			if seen[res.Name] {
				p.xerrorf("duplicate resource name %q", res.Name)
			}
			seen[res.Name] = true
			l = append(l, res)
		}
		p.xtake(")")
		p.xcrlf()
		return UntaggedQuota{root, l}

	default:
		v, err := strconv.ParseUint(w, 10, 32)
		if err == nil {
			num := uint32(v)
			p.xspace()
			w = p.xword()
			W = strings.ToUpper(w)
			switch W {
			case "FETCH", "UIDFETCH":
				if num == 0 {
					p.xerrorf("invalid zero number for untagged fetch response")
				}
				p.xspace()
				attrs := p.xfetch()
				p.xcrlf()
				if W == "UIDFETCH" {
					return UntaggedUIDFetch{num, attrs}
				}
				return UntaggedFetch{num, attrs}

			case "EXPUNGE":
				if num == 0 {
					p.xerrorf("invalid zero number for untagged expunge response")
				}
				p.xcrlf()
				return UntaggedExpunge(num)

			case "EXISTS":
				p.xcrlf()
				return UntaggedExists(num)

			case "RECENT":
				p.xcrlf()
				return UntaggedRecent(num)

			default:
				p.xerrorf("unknown untagged numbered response %q", w)
				panic("not reached")
			}
		}
		p.xerrorf("unknown untagged response %q", w)
	}
	panic("not reached")
}

// ../rfc/3501:4864 ../rfc/9051:6742
// Already parsed: "*" SP nznumber SP "FETCH" SP
func (p *Proto) xfetch() []FetchAttr {
	p.xtake("(")
	attrs := []FetchAttr{p.xmsgatt1()}
	for p.space() {
		attrs = append(attrs, p.xmsgatt1())
	}
	p.xtake(")")
	return attrs
}

// ../rfc/9051:6746
func (p *Proto) xmsgatt1() FetchAttr {
	f := ""
	for {
		b := p.xbyte()
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' {
			f += string(rune(b))
			continue
		}
		p.xunreadbyte()
		break
	}

	F := strings.ToUpper(f)
	switch F {
	case "FLAGS":
		p.xspace()
		p.xtake("(")
		var flags []string
		if !p.take(')') {
			flags = []string{p.xflag()}
			for p.space() {
				flags = append(flags, p.xflag())
			}
			p.xtake(")")
		}
		return FetchFlags(flags)

	case "ENVELOPE":
		p.xspace()
		return FetchEnvelope(p.xenvelope())

	case "INTERNALDATE":
		p.xspace()
		s := p.xquoted()
		v, err := time.Parse("_2-Jan-2006 15:04:05 -0700", s)
		p.xcheckf(err, "parsing internaldate")
		return FetchInternalDate{v}

	case "SAVEDATE":
		p.xspace()
		var t *time.Time
		if p.peek('"') {
			s := p.xquoted()
			v, err := time.Parse("_2-Jan-2006 15:04:05 -0700", s)
			p.xcheckf(err, "parsing savedate")
			t = &v
		} else {
			p.xtake("nil")
		}
		return FetchSaveDate{t}

	case "RFC822.SIZE":
		p.xspace()
		return FetchRFC822Size(p.xint64())

	case "RFC822":
		p.xspace()
		s := p.xnilString()
		return FetchRFC822(s)

	case "RFC822.HEADER":
		p.xspace()
		s := p.xnilString()
		return FetchRFC822Header(s)

	case "RFC822.TEXT":
		p.xspace()
		s := p.xnilString()
		return FetchRFC822Text(s)

	case "BODY":
		if p.space() {
			return FetchBodystructure{F, p.xbodystructure(false)}
		}
		p.record = true
		section := p.xsection()
		var offset int32
		if p.take('<') {
			offset = p.xint32()
			p.xtake(">")
		}
		F += p.recorded()
		p.xspace()
		body := p.xnilString()
		return FetchBody{F, section, offset, body}

	case "BODYSTRUCTURE":
		p.xspace()
		return FetchBodystructure{F, p.xbodystructure(true)}

	case "BINARY":
		p.record = true
		nums := p.xsectionBinary()
		F += p.recorded()
		p.xspace()
		buf := p.xnilStringLiteral8()
		return FetchBinary{F, nums, string(buf)}

	case "BINARY.SIZE":
		p.record = true
		nums := p.xsectionBinary()
		F += p.recorded()
		p.xspace()
		size := p.xint64()
		return FetchBinarySize{F, nums, size}

	case "UID":
		p.xspace()
		return FetchUID(p.xuint32())

	case "MODSEQ":
		// ../rfc/7162:2488
		p.xspace()
		p.xtake("(")
		modseq := p.xint64()
		p.xtake(")")
		return FetchModSeq(modseq)

	case "PREVIEW":
		// ../rfc/8970:348
		p.xspace()
		var preview *string
		if p.peek('n') || p.peek('N') {
			p.xtake("nil")
		} else {
			s := p.xstring()
			preview = &s
		}
		return FetchPreview{preview}
	}
	p.xerrorf("unknown fetch attribute %q", f)
	panic("not reached")
}

func (p *Proto) xnilString() string {
	if p.peek('"') {
		return p.xquoted()
	} else if p.peek('{') {
		return string(p.xliteral())
	} else {
		p.xtake("nil")
		return ""
	}
}

func ptr[T any](v T) *T {
	return &v
}

func (p *Proto) xnilptrString() *string {
	if p.peek('"') {
		return ptr(p.xquoted())
	} else if p.peek('{') {
		return ptr(string(p.xliteral()))
	} else {
		p.xtake("nil")
		return nil
	}
}

func (p *Proto) xstring() string {
	if p.peek('"') {
		return p.xquoted()
	}
	return string(p.xliteral())
}

func (p *Proto) xastring() string {
	if p.peek('"') {
		return p.xquoted()
	} else if p.peek('{') {
		return string(p.xliteral())
	}
	return p.xatom()
}

func (p *Proto) xatom() string {
	var s string
	for {
		b, err := p.readbyte()
		p.xcheckf(err, "read byte for atom")
		if b <= ' ' || strings.IndexByte("(){%*\"\\]", b) >= 0 {
			p.xunreadbyte()
			if s == "" {
				p.xerrorf("expected atom")
			}
			return s
		}
		s += string(rune(b))
	}
}

// ../rfc/9051:6856 ../rfc/6855:153
func (p *Proto) xquoted() string {
	p.xtake(`"`)
	s := ""
	for !p.take('"') {
		r, err := p.readrune()
		p.xcheckf(err, "reading rune in quoted string")
		if r == '\\' {
			r, err = p.readrune()
			p.xcheckf(err, "reading escaped char in quoted string")
			if r != '\\' && r != '"' {
				p.xerrorf("quoted char not backslash or dquote: %c", r)
			}
		}
		// todo: probably refuse some more chars. like \0 and all ctl and backspace.
		s += string(r)
	}
	return s
}

func (p *Proto) xliteral() []byte {
	p.xtake("{")
	size := p.xint64()
	sync := p.take('+')
	p.xtake("}")
	p.xcrlf()
	// todo: for some literals, read as tracedata
	if size > 1<<20 {
		p.xerrorf("refusing to read more than 1MB: %d", size)
	}
	if sync {
		if p.xbw == nil {
			p.xerrorf("cannot parse literals without connection")
		}
		fmt.Fprintf(p.xbw, "+ ok\r\n")
		p.xflush()
	}
	buf := make([]byte, int(size))
	defer p.xtraceread(mlog.LevelTracedata)()
	_, err := io.ReadFull(p.br, buf)
	p.xcheckf(err, "reading data for literal")
	p.xtraceread(mlog.LevelTrace)
	return buf
}

// ../rfc/9051:6565
// todo: stricter
func (p *Proto) xflag0(allowPerm bool) string {
	s := ""
	if p.take('\\') {
		s = `\`
		if allowPerm && p.take('*') {
			return `\*`
		}
	} else if p.take('$') {
		s = "$"
	}
	s += p.xatom()
	return s
}

func (p *Proto) xflag() string {
	return p.xflag0(false)
}

func (p *Proto) xflagPerm() string {
	return p.xflag0(true)
}

func (p *Proto) xsection() string {
	p.xtake("[")
	s := p.xtakeuntil(']')
	p.xtake("]")
	return s
}

func (p *Proto) xsectionBinary() []uint32 {
	p.xtake("[")
	var nums []uint32
	for !p.take(']') {
		if len(nums) > 0 {
			p.xtake(".")
		}
		nums = append(nums, p.xnzuint32())
	}
	return nums
}

func (p *Proto) xnilStringLiteral8() []byte {
	// todo: should make difference for literal8 and literal from string, which bytes are allowed
	if p.take('~') || p.peek('{') {
		return p.xliteral()
	}
	return []byte(p.xnilString())
}

// ../rfc/9051:6355
func (p *Proto) xbodystructure(extensibleForm bool) any {
	p.xtake("(")
	if p.peek('(') {
		// ../rfc/9051:6411
		parts := []any{p.xbodystructure(extensibleForm)}
		for p.peek('(') {
			parts = append(parts, p.xbodystructure(extensibleForm))
		}
		p.xspace()
		mediaSubtype := p.xstring()
		var ext *BodyExtensionMpart
		if extensibleForm && p.space() {
			ext = p.xbodyExtMpart()
		}
		p.xtake(")")
		return BodyTypeMpart{parts, mediaSubtype, ext}
	}

	// todo: verify the media(sub)type is valid for returned data.

	var ext *BodyExtension1Part
	mediaType := p.xstring()
	p.xspace()
	mediaSubtype := p.xstring()
	p.xspace()
	bodyFields := p.xbodyFields()
	if !p.space() {
		// Basic type without extension.
		p.xtake(")")
		return BodyTypeBasic{mediaType, mediaSubtype, bodyFields, nil}
	}
	if p.peek('(') {
		// ../rfc/9051:6415
		envelope := p.xenvelope()
		p.xspace()
		bodyStructure := p.xbodystructure(extensibleForm)
		p.xspace()
		lines := p.xint64()
		if extensibleForm && p.space() {
			ext = p.xbodyExt1Part()
		}
		p.xtake(")")
		return BodyTypeMsg{mediaType, mediaSubtype, bodyFields, envelope, bodyStructure, lines, ext}
	}
	if !strings.EqualFold(mediaType, "text") {
		if !extensibleForm {
			p.xerrorf("body result, basic type, with disallowed extensible form")
		}
		ext = p.xbodyExt1Part()
		// ../rfc/9051:6407
		p.xtake(")")
		return BodyTypeBasic{mediaType, mediaSubtype, bodyFields, ext}
	}
	// ../rfc/9051:6418
	lines := p.xint64()
	if extensibleForm && p.space() {
		ext = p.xbodyExt1Part()
	}
	p.xtake(")")
	return BodyTypeText{mediaType, mediaSubtype, bodyFields, lines, ext}
}

// ../rfc/9051:6376 ../rfc/3501:4604
func (p *Proto) xbodyFields() BodyFields {
	params := p.xbodyFldParam()
	p.xspace()
	contentID := p.xnilString()
	p.xspace()
	contentDescr := p.xnilString()
	p.xspace()
	cte := p.xnilString()
	p.xspace()
	octets := p.xint32()
	return BodyFields{params, contentID, contentDescr, cte, octets}
}

// ../rfc/9051:6371 ../rfc/3501:4599
func (p *Proto) xbodyExtMpart() (ext *BodyExtensionMpart) {
	ext = &BodyExtensionMpart{}
	ext.Params = p.xbodyFldParam()
	if !p.space() {
		return
	}
	disp, dispParams := p.xbodyFldDsp()
	ext.Disposition, ext.DispositionParams = &disp, &dispParams
	if !p.space() {
		return
	}
	ext.Language = ptr(p.xbodyFldLang())
	if !p.space() {
		return
	}
	ext.Location = ptr(p.xbodyFldLoc())
	for p.space() {
		ext.More = append(ext.More, p.xbodyExtension())
	}
	return
}

// ../rfc/9051:6366 ../rfc/3501:4584
func (p *Proto) xbodyExt1Part() (ext *BodyExtension1Part) {
	ext = &BodyExtension1Part{}
	ext.MD5 = p.xnilptrString()
	if !p.space() {
		return
	}
	disp, dispParams := p.xbodyFldDsp()
	ext.Disposition, ext.DispositionParams = &disp, &dispParams
	if !p.space() {
		return
	}
	ext.Language = ptr(p.xbodyFldLang())
	if !p.space() {
		return
	}
	ext.Location = ptr(p.xbodyFldLoc())
	for p.space() {
		ext.More = append(ext.More, p.xbodyExtension())
	}
	return
}

// ../rfc/9051:6401 ../rfc/3501:4626
func (p *Proto) xbodyFldParam() [][2]string {
	if p.take('(') {
		k := p.xstring()
		p.xspace()
		v := p.xstring()
		l := [][2]string{{k, v}}
		for p.space() {
			k = p.xstring()
			p.xspace()
			v = p.xstring()
			l = append(l, [2]string{k, v})
		}
		p.xtake(")")
		return l
	}
	p.xtake("nil")
	return nil
}

// ../rfc/9051:6381 ../rfc/3501:4609
func (p *Proto) xbodyFldDsp() (*string, [][2]string) {
	if !p.take('(') {
		p.xtake("nil")
		return nil, nil
	}
	disposition := p.xstring()
	p.xspace()
	param := p.xbodyFldParam()
	p.xtake(")")
	return ptr(disposition), param
}

// ../rfc/9051:6391 ../rfc/3501:4616
func (p *Proto) xbodyFldLang() (lang []string) {
	if p.take('(') {
		lang = []string{p.xstring()}
		for p.space() {
			lang = append(lang, p.xstring())
		}
		p.xtake(")")
		return lang
	}
	if p.peekstring() {
		return []string{p.xstring()}
	}
	p.xtake("nil")
	return nil
}

// ../rfc/9051:6393 ../rfc/3501:4618
func (p *Proto) xbodyFldLoc() *string {
	return p.xnilptrString()
}

// ../rfc/9051:6357 ../rfc/3501:4575
func (p *Proto) xbodyExtension() (ext BodyExtension) {
	if p.take('(') {
		for {
			ext.More = append(ext.More, p.xbodyExtension())
			if !p.space() {
				break
			}
		}
		p.xtake(")")
	} else if p.peekdigit() {
		num := p.xint64()
		ext.Number = &num
	} else if p.peekstring() {
		str := p.xstring()
		ext.String = &str
	} else {
		p.xtake("nil")
	}
	return ext
}

// ../rfc/9051:6522
func (p *Proto) xenvelope() Envelope {
	p.xtake("(")
	date := p.xnilString()
	p.xspace()
	subject := p.xnilString()
	p.xspace()
	from := p.xaddresses()
	p.xspace()
	sender := p.xaddresses()
	p.xspace()
	replyTo := p.xaddresses()
	p.xspace()
	to := p.xaddresses()
	p.xspace()
	cc := p.xaddresses()
	p.xspace()
	bcc := p.xaddresses()
	p.xspace()
	inReplyTo := p.xnilString()
	p.xspace()
	messageID := p.xnilString()
	p.xtake(")")
	return Envelope{date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID}
}

// ../rfc/9051:6526
func (p *Proto) xaddresses() []Address {
	if !p.take('(') {
		p.xtake("nil")
		return nil
	}
	l := []Address{p.xaddress()}
	for !p.take(')') {
		l = append(l, p.xaddress())
	}
	return l
}

// ../rfc/9051:6303
func (p *Proto) xaddress() Address {
	p.xtake("(")
	name := p.xnilString()
	p.xspace()
	adl := p.xnilString()
	p.xspace()
	mailbox := p.xnilString()
	p.xspace()
	host := p.xnilString()
	p.xtake(")")
	return Address{name, adl, mailbox, host}
}

// ../rfc/9051:6584
func (p *Proto) xflagList() []string {
	p.xtake("(")
	var l []string
	if !p.take(')') {
		l = []string{p.xflag()}
		for p.space() {
			l = append(l, p.xflag())
		}
		p.xtake(")")
	}
	return l
}

// ../rfc/9051:6690
func (p *Proto) xmailboxList() UntaggedList {
	p.xtake("(")
	var flags []string
	if !p.peek(')') {
		flags = append(flags, p.xflag())
		for p.space() {
			flags = append(flags, p.xflag())
		}
	}
	p.xtake(")")
	p.xspace()
	var quoted string
	var b byte
	if p.peek('"') {
		quoted = p.xquoted()
		if len(quoted) != 1 {
			p.xerrorf("mailbox-list has multichar quoted part: %q", quoted)
		}
		b = byte(quoted[0])
	} else if !p.peek(' ') {
		p.xtake("nil")
	}
	p.xspace()
	mailbox := p.xastring()
	ul := UntaggedList{flags, b, mailbox, nil, ""}
	if p.space() {
		p.xtake("(")
		if !p.peek(')') {
			p.xmboxListExtendedItem(&ul)
			for p.space() {
				p.xmboxListExtendedItem(&ul)
			}
		}
		p.xtake(")")
	}
	return ul
}

// ../rfc/9051:6699
func (p *Proto) xmboxListExtendedItem(ul *UntaggedList) {
	tag := p.xastring()
	p.xspace()
	if strings.ToUpper(tag) == "OLDNAME" {
		// ../rfc/9051:6811
		p.xtake("(")
		name := p.xastring()
		p.xtake(")")
		ul.OldName = name
		return
	}
	val := p.xtaggedExtVal()
	ul.Extended = append(ul.Extended, MboxListExtendedItem{tag, val})
}

// ../rfc/9051:7111
func (p *Proto) xtaggedExtVal() TaggedExtVal {
	if p.take('(') {
		var r TaggedExtVal
		if !p.take(')') {
			comp := p.xtaggedExtComp()
			r.Comp = &comp
			p.xtake(")")
		}
		return r
	}
	// We cannot just parse sequence-set, because we also have to accept number/number64. So first look for a number. If it is not, we continue parsing the rest of the sequence set.
	b, err := p.readbyte()
	p.xcheckf(err, "read byte for tagged-ext-val")
	if b < '0' || b > '9' {
		p.xunreadbyte()
		ss := p.xsequenceSet()
		return TaggedExtVal{SeqSet: &ss}
	}
	s := p.xdigits()
	num, err := strconv.ParseInt(s, 10, 63)
	p.xcheckf(err, "parsing int")
	if !p.peek(':') && !p.peek(',') {
		// not a larger sequence-set
		return TaggedExtVal{Number: &num}
	}
	var sr NumRange
	sr.First = uint32(num)
	if p.take(':') {
		var num uint32
		if !p.take('*') {
			num = p.xnzuint32()
		}
		sr.Last = &num
	}
	ss := p.xsequenceSet()
	ss.Ranges = append([]NumRange{sr}, ss.Ranges...)
	return TaggedExtVal{SeqSet: &ss}
}

// ../rfc/9051:7034
func (p *Proto) xsequenceSet() NumSet {
	if p.take('$') {
		return NumSet{SearchResult: true}
	}
	var ss NumSet
	for {
		var sr NumRange
		if !p.take('*') {
			sr.First = p.xnzuint32()
		}
		if p.take(':') {
			var num uint32
			if !p.take('*') {
				num = p.xnzuint32()
			}
			sr.Last = &num
		}
		ss.Ranges = append(ss.Ranges, sr)
		if !p.take(',') {
			break
		}
	}
	return ss
}

// ../rfc/9051:7097
func (p *Proto) xtaggedExtComp() TaggedExtComp {
	if p.take('(') {
		r := p.xtaggedExtComp()
		p.xtake(")")
		return TaggedExtComp{Comps: []TaggedExtComp{r}}
	}
	s := p.xastring()
	if !p.peek(' ') {
		return TaggedExtComp{String: s}
	}
	l := []TaggedExtComp{{String: s}}
	for p.space() {
		l = append(l, p.xtaggedExtComp())
	}
	return TaggedExtComp{Comps: l}
}

// ../rfc/9051:6765
func (p *Proto) xnamespace() []NamespaceDescr {
	if !p.take('(') {
		p.xtake("nil")
		return nil
	}

	l := []NamespaceDescr{p.xnamespaceDescr()}
	for !p.take(')') {
		l = append(l, p.xnamespaceDescr())
	}
	return l
}

// ../rfc/9051:6769
func (p *Proto) xnamespaceDescr() NamespaceDescr {
	p.xtake("(")
	prefix := p.xstring()
	p.xspace()
	var b byte
	if p.peek('"') {
		s := p.xquoted()
		if len(s) != 1 {
			p.xerrorf("namespace-descr: expected single char, got %q", s)
		}
		b = byte(s[0])
	} else {
		p.xtake("nil")
	}
	var exts []NamespaceExtension
	for !p.take(')') {
		p.xspace()
		key := p.xstring()
		p.xspace()
		p.xtake("(")
		values := []string{p.xstring()}
		for p.space() {
			values = append(values, p.xstring())
		}
		p.xtake(")")
		exts = append(exts, NamespaceExtension{key, values})
	}
	return NamespaceDescr{prefix, b, exts}
}

// ../rfc/9051:6546
// Already consumed: "ESEARCH"
func (p *Proto) xesearchResponse() (r UntaggedEsearch) {
	if !p.space() {
		return
	}

	if p.take('(') {
		// ../rfc/9051:6921 ../rfc/7377:465
		seen := map[string]bool{}
		for {
			var kind string
			if p.peek('t') || p.peek('T') {
				kind = "TAG"
				p.xtake(kind)
				p.xspace()
				r.Tag = p.xastring()
			} else if p.peek('m') || p.peek('M') {
				kind = "MAILBOX"
				p.xtake(kind)
				p.xspace()
				r.Mailbox = p.xastring()
				if r.Mailbox == "" {
					p.xerrorf("invalid empty mailbox in search correlator")
				}
			} else if p.peek('u') || p.peek('U') {
				kind = "UIDVALIDITY"
				p.xtake(kind)
				p.xspace()
				r.UIDValidity = p.xnzuint32()
			} else {
				p.xerrorf("expected tag/correlator, mailbox or uidvalidity")
			}

			if seen[kind] {
				p.xerrorf("duplicate search correlator %q", kind)
			}
			seen[kind] = true

			if !p.take(' ') {
				break
			}
		}

		if r.Tag == "" {
			p.xerrorf("missing tag search correlator")
		}
		if (r.Mailbox != "") != (r.UIDValidity != 0) {
			p.xerrorf("mailbox and uidvalidity correlators must both be absent or both be present")
		}

		p.xtake(")")
	}
	if !p.space() {
		return
	}
	w := p.xnonspace()
	W := strings.ToUpper(w)
	if W == "UID" {
		r.UID = true
		if !p.space() {
			return
		}
		w = p.xnonspace()
		W = strings.ToUpper(w)
	}
	for {
		// ../rfc/9051:6957
		switch W {
		case "MIN":
			if r.Min != 0 {
				p.xerrorf("duplicate MIN in ESEARCH")
			}
			p.xspace()
			num := p.xnzuint32()
			r.Min = num

		case "MAX":
			if r.Max != 0 {
				p.xerrorf("duplicate MAX in ESEARCH")
			}
			p.xspace()
			num := p.xnzuint32()
			r.Max = num

		case "ALL":
			if !r.All.IsZero() {
				p.xerrorf("duplicate ALL in ESEARCH")
			}
			p.xspace()
			ss := p.xsequenceSet()
			if ss.SearchResult {
				p.xerrorf("$ for last not valid in ESEARCH")
			}
			r.All = ss

		case "COUNT":
			if r.Count != nil {
				p.xerrorf("duplicate COUNT in ESEARCH")
			}
			p.xspace()
			num := p.xuint32()
			r.Count = &num

		// ../rfc/7162:1211 ../rfc/4731:273
		case "MODSEQ":
			p.xspace()
			r.ModSeq = p.xint64()

		default:
			// Validate ../rfc/9051:7090
			for i, b := range []byte(w) {
				if !(b >= 'A' && b <= 'Z' || strings.IndexByte("-_.", b) >= 0 || i > 0 && strings.IndexByte("0123456789:", b) >= 0) {
					p.xerrorf("invalid tag %q", w)
				}
			}
			p.xspace()
			ext := EsearchDataExt{w, p.xtaggedExtVal()}
			r.Exts = append(r.Exts, ext)
		}

		if !p.space() {
			break
		}
		w = p.xnonspace() // todo: this is too loose
		W = strings.ToUpper(w)
	}
	return
}

// ../rfc/9051:6441
func (p *Proto) xcharset() string {
	if p.peek('"') {
		return p.xquoted()
	}
	return p.xatom()
}

// ../rfc/9051:7133
func (p *Proto) xuidset() []NumRange {
	ranges := []NumRange{p.xuidrange()}
	for p.take(',') {
		ranges = append(ranges, p.xuidrange())
	}
	return ranges
}

func (p *Proto) xuidrange() NumRange {
	uid := p.xnzuint32()
	var end *uint32
	if p.take(':') {
		x := p.xnzuint32()
		end = &x
	}
	return NumRange{uid, end}
}

// ../rfc/3501:4833
func (p *Proto) xlsub() UntaggedLsub {
	p.xspace()
	p.xtake("(")
	r := UntaggedLsub{}
	for !p.take(')') {
		if len(r.Flags) > 0 {
			p.xspace()
		}
		r.Flags = append(r.Flags, p.xflag())
	}
	p.xspace()
	if p.peek('"') {
		s := p.xquoted()
		if !p.peek(' ') {
			r.Mailbox = s
			return r
		}
		if len(s) != 1 {
			// todo: check valid char
			p.xerrorf("invalid separator %q", s)
		}
		r.Separator = byte(s[0])
	}
	p.xspace()
	r.Mailbox = p.xastring()
	return r
}
