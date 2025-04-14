package imapclient

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Capability is a known string for with the ENABLED command and response and
// CAPABILITY responses. Servers could send unknown values. Always in upper case.
type Capability string

const (
	CapIMAP4rev1           Capability = "IMAP4REV1"               // ../rfc/3501:1310
	CapIMAP4rev2           Capability = "IMAP4REV2"               // ../rfc/9051:1219
	CapLoginDisabled       Capability = "LOGINDISABLED"           // ../rfc/3501:3792 ../rfc/9051:5436
	CapStartTLS            Capability = "STARTTLS"                // ../rfc/3501:1327 ../rfc/9051:1238
	CapAuthPlain           Capability = "AUTH=PLAIN"              // ../rfc/3501:1327 ../rfc/9051:1238
	CapAuthExternal        Capability = "AUTH=EXTERNAL"           // ../rfc/4422:1575
	CapAuthSCRAMSHA256Plus Capability = "AUTH=SCRAM-SHA-256-PLUS" // ../rfc/7677:80
	CapAuthSCRAMSHA256     Capability = "AUTH=SCRAM-SHA-256"
	CapAuthSCRAMSHA1Plus   Capability = "AUTH=SCRAM-SHA-1-PLUS" // ../rfc/5802:465
	CapAuthSCRAMSHA1       Capability = "AUTH=SCRAM-SHA-1"
	CapAuthCRAMMD5         Capability = "AUTH=CRAM-MD5" // ../rfc/2195:80
	CapLiteralPlus         Capability = "LITERAL+"      // ../rfc/2088:45
	CapLiteralMinus        Capability = "LITERAL-"      // ../rfc/7888:26 ../rfc/9051:847 Default since IMAP4rev2
	CapIdle                Capability = "IDLE"          // ../rfc/2177:69 ../rfc/9051:3542 Default since IMAP4rev2
	CapNamespace           Capability = "NAMESPACE"     // ../rfc/2342:130 ../rfc/9051:135 Default since IMAP4rev2
	CapBinary              Capability = "BINARY"        // ../rfc/3516:100
	CapUnselect            Capability = "UNSELECT"      // ../rfc/3691:78 ../rfc/9051:3667 Default since IMAP4rev2
	CapUidplus             Capability = "UIDPLUS"       // ../rfc/4315:36 ../rfc/9051:8015 Default since IMAP4rev2
	CapEsearch             Capability = "ESEARCH"       // ../rfc/4731:69 ../rfc/9051:8016 Default since IMAP4rev2
	CapEnable              Capability = "ENABLE"        // ../rfc/5161:52 ../rfc/9051:8016 Default since IMAP4rev2
	CapListExtended        Capability = "LIST-EXTENDED" // ../rfc/5258:150 ../rfc/9051:7987 Syntax except multiple mailboxes default since IMAP4rev2
	CapSpecialUse          Capability = "SPECIAL-USE"   // ../rfc/6154:156 ../rfc/9051:8021 Special-use attributes in LIST responses by default since IMAP4rev2
	CapMove                Capability = "MOVE"          // ../rfc/6851:87 ../rfc/9051:8018 Default since IMAP4rev2
	CapUTF8Only            Capability = "UTF8=ONLY"
	CapUTF8Accept          Capability = "UTF8=ACCEPT"
	CapCondstore           Capability = "CONDSTORE"          // ../rfc/7162:411
	CapQresync             Capability = "QRESYNC"            // ../rfc/7162:1376
	CapID                  Capability = "ID"                 // ../rfc/2971:80
	CapMetadata            Capability = "METADATA"           // ../rfc/5464:124
	CapMetadataServer      Capability = "METADATA-SERVER"    // ../rfc/5464:124
	CapSaveDate            Capability = "SAVEDATE"           // ../rfc/8514
	CapCreateSpecialUse    Capability = "CREATE-SPECIAL-USE" // ../rfc/6154:296
	CapCompressDeflate     Capability = "COMPRESS=DEFLATE"   // ../rfc/4978:65
	CapListMetadata        Capability = "LIST-METADATA"      // ../rfc/9590:73
	CapMultiAppend         Capability = "MULTIAPPEND"        // ../rfc/3502:33
	CapReplace             Capability = "REPLACE"            // ../rfc/8508:155
	CapPreview             Capability = "PREVIEW"            // ../rfc/8970:114
	CapMultiSearch         Capability = "MULTISEARCH"        // ../rfc/7377:187
	CapNotify              Capability = "NOTIFY"             // ../rfc/5465:195
	CapUIDOnly             Capability = "UIDONLY"            // ../rfc/9586:129
)

// Status is the tagged final result of a command.
type Status string

const (
	BAD Status = "BAD" // Syntax error.
	NO  Status = "NO"  // Command failed.
	OK  Status = "OK"  // Command succeeded.
)

// Response is a response to an IMAP command including any preceding untagged
// responses. Response implements the error interface through result.
//
// See [UntaggedResponseGet] and [UntaggedResponseList] to retrieve specific types
// of untagged responses.
type Response struct {
	Untagged []Untagged
	Result
}

var (
	ErrMissing  = errors.New("no response of type")        // Returned by UntaggedResponseGet.
	ErrMultiple = errors.New("multiple responses of type") // Idem.
)

// UntaggedResponseGet returns the single untagged response of type T. Only
// [ErrMissing] or [ErrMultiple] can be returned as error.
func UntaggedResponseGet[T Untagged](resp Response) (T, error) {
	var t T
	var have bool
	for _, e := range resp.Untagged {
		if tt, ok := e.(T); ok {
			if have {
				return t, ErrMultiple
			}
			t = tt
		}
	}
	if !have {
		return t, ErrMissing
	}
	return t, nil
}

// UntaggedResponseList returns all untagged responses of type T.
func UntaggedResponseList[T Untagged](resp Response) []T {
	var l []T
	for _, e := range resp.Untagged {
		if tt, ok := e.(T); ok {
			l = append(l, tt)
		}
	}
	return l
}

// Result is the final response for a command, indicating success or failure.
type Result struct {
	Status Status
	Code   Code   // Set if response code is present.
	Text   string // Any remaining text.
}

func (r Result) Error() string {
	s := fmt.Sprintf("IMAP result %s", r.Status)
	if r.Code != nil {
		s += "[" + r.Code.CodeString() + "]"
	}
	if r.Text != "" {
		s += " " + r.Text
	}
	return s
}

// Code represents a response code with optional arguments, i.e. the data between [] in the response line.
type Code interface {
	CodeString() string
}

// CodeWord is a response code without parameters, always in upper case.
type CodeWord string

func (c CodeWord) CodeString() string {
	return string(c)
}

// CodeOther is an unrecognized response code with parameters.
type CodeParams struct {
	Code string // Always in upper case.
	Args []string
}

func (c CodeParams) CodeString() string {
	return c.Code + " " + strings.Join(c.Args, " ")
}

// CodeCapability is a CAPABILITY response code with the capabilities supported by the server.
type CodeCapability []Capability

func (c CodeCapability) CodeString() string {
	var s string
	for _, c := range c {
		s += " " + string(c)
	}
	return "CAPABILITY" + s
}

type CodeBadCharset []string

func (c CodeBadCharset) CodeString() string {
	s := "BADCHARSET"
	if len(c) == 0 {
		return s
	}
	return s + " (" + strings.Join([]string(c), " ") + ")"
}

type CodePermanentFlags []string

func (c CodePermanentFlags) CodeString() string {
	return "PERMANENTFLAGS (" + strings.Join([]string(c), " ") + ")"
}

type CodeUIDNext uint32

func (c CodeUIDNext) CodeString() string {
	return fmt.Sprintf("UIDNEXT %d", c)
}

type CodeUIDValidity uint32

func (c CodeUIDValidity) CodeString() string {
	return fmt.Sprintf("UIDVALIDITY %d", c)
}

type CodeUnseen uint32

func (c CodeUnseen) CodeString() string {
	return fmt.Sprintf("UNSEEN %d", c)
}

// "APPENDUID" response code.
type CodeAppendUID struct {
	UIDValidity uint32
	UIDs        NumRange
}

func (c CodeAppendUID) CodeString() string {
	return fmt.Sprintf("APPENDUID %d %s", c.UIDValidity, c.UIDs.String())
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

// "INPROGRESS" response code.
type CodeInProgress struct {
	Tag     string // Nil is empty string.
	Current *uint32
	Goal    *uint32
}

func (c CodeInProgress) CodeString() string {
	// ABNF allows inprogress-tag/state with all nil values. Doesn't seem useful enough
	// to keep track of.
	if c.Tag == "" && c.Current == nil && c.Goal == nil {
		return "INPROGRESS"
	}

	// todo: quote tag properly
	current := "nil"
	goal := "nil"
	if c.Current != nil {
		current = fmt.Sprintf("%d", *c.Current)
	}
	if c.Goal != nil {
		goal = fmt.Sprintf("%d", *c.Goal)
	}
	return fmt.Sprintf("INPROGRESS (%q %s %s)", c.Tag, current, goal)
}

// "BADEVENT" response code, with the events that are supported, for the NOTIFY
// extension.
type CodeBadEvent []string

func (c CodeBadEvent) CodeString() string {
	return fmt.Sprintf("BADEVENT (%s)", strings.Join([]string(c), " "))
}

// "METADATA LONGENTRIES number" response for GETMETADATA command.
type CodeMetadataLongEntries uint32

func (c CodeMetadataLongEntries) CodeString() string {
	return fmt.Sprintf("METADATA LONGENTRIES %d", c)
}

// "METADATA (MAXSIZE number)" response for SETMETADATA command.
type CodeMetadataMaxSize uint32

func (c CodeMetadataMaxSize) CodeString() string {
	return fmt.Sprintf("METADATA (MAXSIZE %d)", c)
}

// "METADATA (TOOMANY)" response for SETMETADATA command.
type CodeMetadataTooMany struct{}

func (c CodeMetadataTooMany) CodeString() string {
	return "METADATA (TOOMANY)"
}

// "METADATA (NOPRIVATE)" response for SETMETADATA command.
type CodeMetadataNoPrivate struct{}

func (c CodeMetadataNoPrivate) CodeString() string {
	return "METADATA (NOPRIVATE)"
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

type UntaggedBye struct {
	Code Code   // Set if response code is present.
	Text string // Any remaining text.
}
type UntaggedPreauth struct {
	Code Code   // Set if response code is present.
	Text string // Any remaining text.
}
type UntaggedExpunge uint32
type UntaggedExists uint32
type UntaggedRecent uint32

// UntaggedCapability lists all capabilities the server implements.
type UntaggedCapability []Capability

// UntaggedEnabled indicates the capabilities that were enabled on the connection
// by the server, typically in response to an ENABLE command.
type UntaggedEnabled []Capability

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

// UntaggedUIDFetch is like UntaggedFetch, but with UIDs instead of message
// sequence numbers, and returned instead of regular fetch responses when UIDONLY
// is enabled.
type UntaggedUIDFetch struct {
	UID   uint32
	Attrs []FetchAttr
}
type UntaggedSearch []uint32

type UntaggedSearchModSeq struct {
	// ../rfc/7162:1101

	Nums   []uint32
	ModSeq int64
}
type UntaggedStatus struct {
	Mailbox string
	Attrs   map[StatusAttr]int64 // Upper case status attributes.
}

// Unsolicited response, indicating an annotation has changed.
type UntaggedMetadataKeys struct {
	// ../rfc/5464:716

	Mailbox string // Empty means not specific to mailbox.

	// Keys that have changed. To get values (or determine absence), the server must be
	// queried.
	Keys []string
}

// Annotation is a metadata server of mailbox annotation.
type Annotation struct {
	Key string
	// Nil is represented by IsString false and a nil Value.
	IsString bool
	Value    []byte
}

type UntaggedMetadataAnnotations struct {
	// ../rfc/5464:683

	Mailbox     string // Empty means not specific to mailbox.
	Annotations []Annotation
}

type StatusAttr string

// ../rfc/9051:7059 ../9208:712

const (
	StatusMessages       StatusAttr = "MESSAGES"
	StatusUIDNext        StatusAttr = "UIDNEXT"
	StatusUIDValidity    StatusAttr = "UIDVALIDITY"
	StatusUnseen         StatusAttr = "UNSEEN"
	StatusDeleted        StatusAttr = "DELETED"
	StatusSize           StatusAttr = "SIZE"
	StatusRecent         StatusAttr = "RECENT"
	StatusAppendLimit    StatusAttr = "APPENDLIMIT"
	StatusHighestModSeq  StatusAttr = "HIGHESTMODSEQ"
	StatusDeletedStorage StatusAttr = "DELETED-STORAGE"
)

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
	Tag         string // ../rfc/9051:6546
	Mailbox     string // For MULTISEARCH. ../rfc/7377:437
	UIDValidity uint32 // For MULTISEARCH, ../rfc/7377:438

	UID    bool
	Min    uint32
	Max    uint32
	All    NumSet
	Count  *uint32
	ModSeq int64
	Exts   []EsearchDataExt
}

// UntaggedVanished is used in QRESYNC to send UIDs that have been removed.
type UntaggedVanished struct {
	Earlier bool
	UIDs    NumSet
}

// UntaggedQuotaroot lists the roots for which quota can be present.
type UntaggedQuotaroot []string

// UntaggedQuota holds the quota for a quota root.
type UntaggedQuota struct {
	Root string

	// Always has at least one. Any QUOTA=RES-* capability not mentioned has no limit
	// or this quota root.
	Resources []QuotaResource
}

// Resource types ../rfc/9208:533

// QuotaResourceName is the name of a resource type. More can be defined in the
// future and encountered in the wild. Always in upper case.
type QuotaResourceName string

const (
	QuotaResourceStorage           = "STORAGE"
	QuotaResourceMesssage          = "MESSAGE"
	QuotaResourceMailbox           = "MAILBOX"
	QuotaResourceAnnotationStorage = "ANNOTATION-STORAGE"
)

type QuotaResource struct {
	Name  QuotaResourceName
	Usage int64 // Currently in use. Count or disk size in 1024 byte blocks.
	Limit int64 // Maximum allowed usage.
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
	Attr() string // Name of attribute in upper case, e.g. "UID".
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
	c := Proto{br: bufio.NewReader(strings.NewReader(s))}
	defer c.recover(&rerr)
	ns = c.xsequenceSet()
	return
}

func ParseUIDRange(s string) (nr NumRange, rerr error) {
	c := Proto{br: bufio.NewReader(strings.NewReader(s))}
	defer c.recover(&rerr)
	nr = c.xuidrange()
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
type FetchInternalDate struct {
	Date time.Time
}

func (f FetchInternalDate) Attr() string { return "INTERNALDATE" }

// "SAVEDATE" fetch response.
type FetchSaveDate struct {
	// ../rfc/8514:265

	SaveDate *time.Time // nil means absent for message.
}

func (f FetchSaveDate) Attr() string { return "SAVEDATE" }

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

// BodyTypeMpart represents the body structure a multipart message, with
// subparts and the multipart media subtype. Used in a FETCH response.
type BodyTypeMpart struct {
	// ../rfc/9051:6411

	Bodies       []any // BodyTypeBasic, BodyTypeMsg, BodyTypeText
	MediaSubtype string
	Ext          *BodyExtensionMpart
}

// BodyTypeBasic represents basic information about a part, used in a FETCH
// response.
type BodyTypeBasic struct {
	// ../rfc/9051:6407

	MediaType, MediaSubtype string
	BodyFields              BodyFields
	Ext                     *BodyExtension1Part
}

// BodyTypeMsg represents an email message as a body structure, used in a FETCH
// response.
type BodyTypeMsg struct {
	// ../rfc/9051:6415

	MediaType, MediaSubtype string
	BodyFields              BodyFields
	Envelope                Envelope
	Bodystructure           any // One of the BodyType*
	Lines                   int64
	Ext                     *BodyExtension1Part
}

// BodyTypeText represents a text part as a body structure, used in a FETCH
// response.
type BodyTypeText struct {
	// ../rfc/9051:6418

	MediaType, MediaSubtype string
	BodyFields              BodyFields
	Lines                   int64
	Ext                     *BodyExtension1Part
}

// BodyExtension1Part has the extensible form fields of a BODYSTRUCTURE for
// multiparts.
//
// Fields in this struct are optional in IMAP4, and can be NIL or contain a value.
// The first field is always present, otherwise the "parent" struct would have a
// nil *BodyExtensionMpart. The second and later fields are nil when absent. For
// non-reference types (e.g. strings), an IMAP4 NIL is represented as a pointer to
// (*T)(nil). For reference types (e.g. slices), an IMAP4 NIL is represented by a
// pointer to nil.
type BodyExtensionMpart struct {
	// ../rfc/9051:5986 ../rfc/3501:4161 ../rfc/9051:6371 ../rfc/3501:4599

	Params            [][2]string
	Disposition       **string
	DispositionParams *[][2]string
	Language          *[]string
	Location          **string
	More              []BodyExtension // Nil if absent.
}

// BodyExtension1Part has the extensible form fields of a BODYSTRUCTURE for
// non-multiparts.
//
// Fields in this struct are optional in IMAP4, and can be NIL or contain a value.
// The first field is always present, otherwise the "parent" struct would have a
// nil *BodyExtensionMpart. The second and later fields are nil when absent. For
// non-reference types (e.g. strings), an IMAP4 NIL is represented as a pointer to
// (*T)(nil). For reference types (e.g. slices), an IMAP4 NIL is represented by a
// pointer to nil.
type BodyExtension1Part struct {
	// ../rfc/9051:6023 ../rfc/3501:4191 ../rfc/9051:6366 ../rfc/3501:4584

	MD5               *string
	Disposition       **string
	DispositionParams *[][2]string
	Language          *[]string
	Location          **string
	More              []BodyExtension // Nil means absent.
}

// BodyExtension has the additional extension fields for future expansion of
// extensions.
type BodyExtension struct {
	String *string
	Number *int64
	More   []BodyExtension
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

// "PREVIEW" fetch response.
type FetchPreview struct {
	Preview *string
}

// ../rfc/8970:146

func (f FetchPreview) Attr() string { return "PREVIEW" }
