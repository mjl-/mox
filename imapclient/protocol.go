package imapclient

import (
	"bufio"
	"fmt"
	"strings"
)

// Capability is a known string for with the ENABLED and CAPABILITY command.
type Capability string

const (
	CapIMAP4rev1     Capability = "IMAP4rev1"
	CapIMAP4rev2     Capability = "IMAP4rev2"
	CapLoginDisabled Capability = "LOGINDISABLED"
	CapStarttls      Capability = "STARTTLS"
	CapAuthPlain     Capability = "AUTH=PLAIN"
	CapLiteralPlus   Capability = "LITERAL+"
	CapLiteralMinus  Capability = "LITERAL-"
	CapIdle          Capability = "IDLE"
	CapNamespace     Capability = "NAMESPACE"
	CapBinary        Capability = "BINARY"
	CapUnselect      Capability = "UNSELECT"
	CapUidplus       Capability = "UIDPLUS"
	CapEsearch       Capability = "ESEARCH"
	CapEnable        Capability = "ENABLE"
	CapSave          Capability = "SAVE"
	CapListExtended  Capability = "LIST-EXTENDED"
	CapSpecialUse    Capability = "SPECIAL-USE"
	CapMove          Capability = "MOVE"
	CapUTF8Only      Capability = "UTF8=ONLY"
	CapUTF8Accept    Capability = "UTF8=ACCEPT"
	CapID            Capability = "ID" // ../rfc/2971:80
)

// Status is the tagged final result of a command.
type Status string

const (
	BAD Status = "BAD" // Syntax error.
	NO  Status = "NO"  // Command failed.
	OK  Status = "OK"  // Command succeeded.
)

// Result is the final response for a command, indicating success or failure.
type Result struct {
	Status Status
	RespText
}

// CodeArg represents a response code with arguments, i.e. the data between [] in the response line.
type CodeArg interface {
	CodeString() string
}

// CodeOther is a valid but unrecognized response code.
type CodeOther struct {
	Code string
	Args []string
}

func (c CodeOther) CodeString() string {
	return c.Code + " " + strings.Join(c.Args, " ")
}

// CodeWords is a code with space-separated string parameters. E.g. CAPABILITY.
type CodeWords struct {
	Code string
	Args []string
}

func (c CodeWords) CodeString() string {
	s := c.Code
	for _, w := range c.Args {
		s += " " + w
	}
	return s
}

// CodeList is a code with a list with space-separated strings as parameters. E.g. BADCHARSET, PERMANENTFLAGS.
type CodeList struct {
	Code string
	Args []string // If nil, no list was present. List can also be empty.
}

func (c CodeList) CodeString() string {
	s := c.Code
	if c.Args == nil {
		return s
	}
	return s + "(" + strings.Join(c.Args, " ") + ")"
}

// CodeUint is a code with a uint32 parameter, e.g. UIDNEXT and UIDVALIDITY.
type CodeUint struct {
	Code string
	Num  uint32
}

func (c CodeUint) CodeString() string {
	return fmt.Sprintf("%s %d", c.Code, c.Num)
}

// "APPENDUID" response code.
type CodeAppendUID struct {
	UIDValidity uint32
	UID         uint32
}

func (c CodeAppendUID) CodeString() string {
	return fmt.Sprintf("APPENDUID %d %d", c.UIDValidity, c.UID)
}

// "COPYUID" response code.
type CodeCopyUID struct {
	DestUIDValidity uint32
	From            []NumRange
	To              []NumRange
}

func (c CodeCopyUID) CodeString() string {
	str := func(l []NumRange) string {
		s := ""
		for i, e := range l {
			if i > 0 {
				s += ","
			}
			s += fmt.Sprintf("%d", e.First)
			if e.Last != nil {
				s += fmt.Sprintf(":%d", *e.Last)
			}
		}
		return s
	}
	return fmt.Sprintf("COPYUID %d %s %s", c.DestUIDValidity, str(c.From), str(c.To))
}

// For CONDSTORE.
type CodeModified NumSet

func (c CodeModified) CodeString() string {
	return fmt.Sprintf("MODIFIED %s", NumSet(c).String())
}

// For CONDSTORE.
type CodeHighestModSeq int64

func (c CodeHighestModSeq) CodeString() string {
	return fmt.Sprintf("HIGHESTMODSEQ %d", c)
}

// RespText represents a response line minus the leading tag.
type RespText struct {
	Code    string  // The first word between [] after the status.
	CodeArg CodeArg // Set if code has a parameter.
	More    string  // Any remaining text.
}

// atom or string.
func astring(s string) string {
	if len(s) == 0 {
		return stringx(s)
	}
	for _, c := range s {
		if c <= ' ' || c >= 0x7f || c == '(' || c == ')' || c == '{' || c == '%' || c == '*' || c == '"' || c == '\\' {
			return stringx(s)
		}
	}
	return s
}

// imap "string", i.e. double-quoted string or syncliteral.
func stringx(s string) string {
	r := `"`
	for _, c := range s {
		if c == '\x00' || c == '\r' || c == '\n' {
			return syncliteral(s)
		}
		if c == '\\' || c == '"' {
			r += `\`
		}
		r += string(c)
	}
	r += `"`
	return r
}

// sync literal, i.e. {<num>}\r\n<num bytes>.
func syncliteral(s string) string {
	return fmt.Sprintf("{%d}\r\n", len(s)) + s
}

// Untagged is a parsed untagged response. See types starting with Untagged.
// todo: make an interface that the untagged responses implement?
type Untagged any

type UntaggedBye RespText
type UntaggedPreauth RespText
type UntaggedExpunge uint32
type UntaggedExists uint32
type UntaggedRecent uint32
type UntaggedCapability []string
type UntaggedEnabled []string
type UntaggedResult Result
type UntaggedFlags []string
type UntaggedList struct {
	// ../rfc/9051:6690
	Flags     []string
	Separator byte // 0 for NIL
	Mailbox   string
	Extended  []MboxListExtendedItem
	OldName   string // If present, taken out of Extended.
}
type UntaggedFetch struct {
	Seq   uint32
	Attrs []FetchAttr
}
type UntaggedSearch []uint32

// ../rfc/7162:1101
type UntaggedSearchModSeq struct {
	Nums   []uint32
	ModSeq int64
}
type UntaggedStatus struct {
	Mailbox string
	Attrs   map[string]int64 // Upper case status attributes. ../rfc/9051:7059
}
type UntaggedNamespace struct {
	Personal, Other, Shared []NamespaceDescr
}
type UntaggedLsub struct {
	// ../rfc/3501:4833
	Flags     []string
	Separator byte
	Mailbox   string
}

// Fields are optional and zero if absent.
type UntaggedEsearch struct {
	// ../rfc/9051:6546
	Correlator string
	UID        bool
	Min        uint32
	Max        uint32
	All        NumSet
	Count      *uint32
	ModSeq     int64
	Exts       []EsearchDataExt
}

// UntaggedVanished is used in QRESYNC to send UIDs that have been removed.
type UntaggedVanished struct {
	Earlier bool
	UIDs    NumSet
}

// ../rfc/2971:184

type UntaggedID map[string]string

// Extended data in an ESEARCH response.
type EsearchDataExt struct {
	Tag   string
	Value TaggedExtVal
}

type NamespaceDescr struct {
	// ../rfc/9051:6769
	Prefix    string
	Separator byte // If 0 then separator was absent.
	Exts      []NamespaceExtension
}

type NamespaceExtension struct {
	// ../rfc/9051:6773
	Key    string
	Values []string
}

// FetchAttr represents a FETCH response attribute.
type FetchAttr interface {
	Attr() string // Name of attribute.
}

type NumSet struct {
	SearchResult bool // True if "$", in which case Ranges is irrelevant.
	Ranges       []NumRange
}

func (ns NumSet) IsZero() bool {
	return !ns.SearchResult && ns.Ranges == nil
}

func (ns NumSet) String() string {
	if ns.SearchResult {
		return "$"
	}
	var r string
	for i, x := range ns.Ranges {
		if i > 0 {
			r += ","
		}
		r += x.String()
	}
	return r
}

func ParseNumSet(s string) (ns NumSet, rerr error) {
	c := Conn{r: bufio.NewReader(strings.NewReader(s))}
	defer c.recover(&rerr)
	ns = c.xsequenceSet()
	return
}

// NumRange is a single number or range.
type NumRange struct {
	First uint32  // 0 for "*".
	Last  *uint32 // Nil if absent, 0 for "*".
}

func (nr NumRange) String() string {
	var r string
	if nr.First == 0 {
		r += "*"
	} else {
		r += fmt.Sprintf("%d", nr.First)
	}
	if nr.Last == nil {
		return r
	}
	r += ":"
	v := *nr.Last
	if v == 0 {
		r += "*"
	} else {
		r += fmt.Sprintf("%d", v)
	}
	return r
}

type TaggedExtComp struct {
	String string
	Comps  []TaggedExtComp // Used for both space-separated and ().
}

type TaggedExtVal struct {
	// ../rfc/9051:7111
	Number *int64
	SeqSet *NumSet
	Comp   *TaggedExtComp // If SimpleNumber and SimpleSeqSet is nil, this is a Comp. But Comp is optional and can also be nil. Not great.
}

type MboxListExtendedItem struct {
	// ../rfc/9051:6699
	Tag string
	Val TaggedExtVal
}

// "FLAGS" fetch response.
type FetchFlags []string

func (f FetchFlags) Attr() string { return "FLAGS" }

// "ENVELOPE" fetch response.
type FetchEnvelope Envelope

func (f FetchEnvelope) Attr() string { return "ENVELOPE" }

// Envelope holds the basic email message fields.
type Envelope struct {
	Date                               string
	Subject                            string
	From, Sender, ReplyTo, To, CC, BCC []Address
	InReplyTo, MessageID               string
}

// Address is an address field in an email message, e.g. To.
type Address struct {
	Name, Adl, Mailbox, Host string
}

// "INTERNALDATE" fetch response.
type FetchInternalDate string            // todo: parsed time
func (f FetchInternalDate) Attr() string { return "INTERNALDATE" }

// "RFC822.SIZE" fetch response.
type FetchRFC822Size int64

func (f FetchRFC822Size) Attr() string { return "RFC822.SIZE" }

// "RFC822" fetch response.
type FetchRFC822 string

func (f FetchRFC822) Attr() string { return "RFC822" }

// "RFC822.HEADER" fetch response.
type FetchRFC822Header string

func (f FetchRFC822Header) Attr() string { return "RFC822.HEADER" }

// "RFC82.TEXT" fetch response.
type FetchRFC822Text string

func (f FetchRFC822Text) Attr() string { return "RFC822.TEXT" }

// "BODYSTRUCTURE" fetch response.
type FetchBodystructure struct {
	// ../rfc/9051:6355
	RespAttr string
	Body     any // BodyType*
}

func (f FetchBodystructure) Attr() string { return f.RespAttr }

// "BODY" fetch response.
type FetchBody struct {
	// ../rfc/9051:6756 ../rfc/9051:6985
	RespAttr string
	Section  string // todo: parse more ../rfc/9051:6985
	Offset   int32
	Body     string
}

func (f FetchBody) Attr() string { return f.RespAttr }

// BodyFields is part of a FETCH BODY[] response.
type BodyFields struct {
	Params                       [][2]string
	ContentID, ContentDescr, CTE string
	Octets                       int32
}

// BodyTypeMpart represents the body structure a multipart message, with subparts and the multipart media subtype. Used in a FETCH response.
type BodyTypeMpart struct {
	// ../rfc/9051:6411
	Bodies       []any // BodyTypeBasic, BodyTypeMsg, BodyTypeText
	MediaSubtype string
}

// BodyTypeBasic represents basic information about a part, used in a FETCH response.
type BodyTypeBasic struct {
	// ../rfc/9051:6407
	MediaType, MediaSubtype string
	BodyFields              BodyFields
}

// BodyTypeMsg represents an email message as a body structure, used in a FETCH response.
type BodyTypeMsg struct {
	// ../rfc/9051:6415
	MediaType, MediaSubtype string
	BodyFields              BodyFields
	Envelope                Envelope
	Bodystructure           any // One of the BodyType*
	Lines                   int64
}

// BodyTypeText represents a text part as a body structure, used in a FETCH response.
type BodyTypeText struct {
	// ../rfc/9051:6418
	MediaType, MediaSubtype string
	BodyFields              BodyFields
	Lines                   int64
}

// "BINARY" fetch response.
type FetchBinary struct {
	RespAttr string
	Parts    []uint32 // Can be nil.
	Data     string
}

func (f FetchBinary) Attr() string { return f.RespAttr }

// "BINARY.SIZE" fetch response.
type FetchBinarySize struct {
	RespAttr string
	Parts    []uint32
	Size     int64
}

func (f FetchBinarySize) Attr() string { return f.RespAttr }

// "UID" fetch response.
type FetchUID uint32

func (f FetchUID) Attr() string { return "UID" }

// "MODSEQ" fetch response.
type FetchModSeq int64

func (f FetchModSeq) Attr() string { return "MODSEQ" }
