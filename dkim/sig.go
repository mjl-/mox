package dkim

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/smtp"
)

// Sig is a DKIM-Signature header.
//
// String values must be compared case insensitively.
type Sig struct {
	// Required fields.
	Version       int        // Version, 1. Field "v". Always the first field.
	AlgorithmSign string     // "rsa" or "ed25519". Field "a".
	AlgorithmHash string     // "sha256" or the deprecated "sha1" (deprecated). Field "a".
	Signature     []byte     // Field "b".
	BodyHash      []byte     // Field "bh".
	Domain        dns.Domain // Field "d".
	SignedHeaders []string   // Duplicates are meaningful. Field "h".
	Selector      dns.Domain // Selector, for looking DNS TXT record at <s>._domainkey.<domain>. Field "s".

	// Optional fields.
	// Canonicalization is the transformation of header and/or body before hashing. The
	// value is in original case, but must be compared case-insensitively. Normally two
	// slash-separated values: header canonicalization and body canonicalization. But
	// the "simple" means "simple/simple" and "relaxed" means "relaxed/simple". Field
	// "c".
	Canonicalization string
	Length           int64     // Body length to verify, default -1 for whole body. Field "l".
	Identity         *Identity // AUID (agent/user id). If nil and an identity is needed, should be treated as an Identity without localpart and Domain from d= field. Field "i".
	QueryMethods     []string  // For public key, currently known value is "dns/txt" (should be compared case-insensitively). If empty, dns/txt must be assumed. Field "q".
	SignTime         int64     // Unix epoch. -1 if unset. Field "t".
	ExpireTime       int64     // Unix epoch. -1 if unset. Field "x".
	CopiedHeaders    []string  // Copied header fields. Field "z".
}

// Identity is used for the optional i= field in a DKIM-Signature header. It uses
// the syntax of an email address, but does not necessarily represent one.
type Identity struct {
	Localpart *smtp.Localpart // Optional.
	Domain    dns.Domain
}

// String returns a value for use in the i= DKIM-Signature field.
func (i Identity) String() string {
	s := "@" + i.Domain.ASCII
	// We need localpart as pointer to indicate it is missing because localparts can be
	// "" which we store (decoded) as empty string and we need to differentiate.
	if i.Localpart != nil {
		s = i.Localpart.String() + s
	}
	return s
}

func newSigWithDefaults() *Sig {
	return &Sig{
		Canonicalization: "simple/simple",
		Length:           -1,
		SignTime:         -1,
		ExpireTime:       -1,
	}
}

// Algorithm returns an algorithm string for use in the "a" field. E.g.
// "ed25519-sha256".
func (s Sig) Algorithm() string {
	return s.AlgorithmSign + "-" + s.AlgorithmHash
}

// Header returns the DKIM-Signature header in string form, to be prepended to a
// message, including DKIM-Signature field name and trailing \r\n.
func (s *Sig) Header() (string, error) {
	// ../rfc/6376:1021
	// todo: make a higher-level writer that accepts pairs, and only folds to next line when needed.
	w := &message.HeaderWriter{}
	w.Addf("", "DKIM-Signature: v=%d;", s.Version)
	// Domain names must always be in ASCII. ../rfc/6376:1115 ../rfc/6376:1187 ../rfc/6376:1303
	w.Addf(" ", "d=%s;", s.Domain.ASCII)
	w.Addf(" ", "s=%s;", s.Selector.ASCII)
	if s.Identity != nil {
		w.Addf(" ", "i=%s;", s.Identity.String()) // todo: Is utf-8 ok here?
	}
	w.Addf(" ", "a=%s;", s.Algorithm())

	if s.Canonicalization != "" && !strings.EqualFold(s.Canonicalization, "simple") && !strings.EqualFold(s.Canonicalization, "simple/simple") {
		w.Addf(" ", "c=%s;", s.Canonicalization)
	}
	if s.Length >= 0 {
		w.Addf(" ", "l=%d;", s.Length)
	}
	if len(s.QueryMethods) > 0 && !(len(s.QueryMethods) == 1 && strings.EqualFold(s.QueryMethods[0], "dns/txt")) {
		w.Addf(" ", "q=%s;", strings.Join(s.QueryMethods, ":"))
	}
	if s.SignTime >= 0 {
		w.Addf(" ", "t=%d;", s.SignTime)
	}
	if s.ExpireTime >= 0 {
		w.Addf(" ", "x=%d;", s.ExpireTime)
	}

	if len(s.SignedHeaders) > 0 {
		for i, v := range s.SignedHeaders {
			sep := ""
			if i == 0 {
				v = "h=" + v
				sep = " "
			}
			if i < len(s.SignedHeaders)-1 {
				v += ":"
			} else if i == len(s.SignedHeaders)-1 {
				v += ";"
			}
			w.Addf(sep, "%s", v)
		}
	}
	if len(s.CopiedHeaders) > 0 {
		// todo: wrap long headers? we can at least add FWS before the :
		for i, v := range s.CopiedHeaders {
			t := strings.SplitN(v, ":", 2)
			if len(t) == 2 {
				v = t[0] + ":" + packQpHdrValue(t[1])
			} else {
				return "", fmt.Errorf("invalid header in copied headers (z=): %q", v)
			}
			sep := ""
			if i == 0 {
				v = "z=" + v
				sep = " "
			}
			if i < len(s.CopiedHeaders)-1 {
				v += "|"
			} else if i == len(s.CopiedHeaders)-1 {
				v += ";"
			}
			w.Addf(sep, "%s", v)
		}
	}

	w.Addf(" ", "bh=%s;", base64.StdEncoding.EncodeToString(s.BodyHash))

	w.Addf(" ", "b=")
	if len(s.Signature) > 0 {
		w.AddWrap([]byte(base64.StdEncoding.EncodeToString(s.Signature)), false)
	}
	w.Add("\r\n")
	return w.String(), nil
}

// Like quoted printable, but with "|" encoded as well.
// We also encode ":" because it is used as separator in DKIM headers which can
// cause trouble for "q", even though it is listed in dkim-safe-char,
// ../rfc/6376:497.
func packQpHdrValue(s string) string {
	// ../rfc/6376:474
	const hex = "0123456789ABCDEF"
	var r string
	for _, b := range []byte(s) {
		if b > ' ' && b < 0x7f && b != ';' && b != '=' && b != '|' && b != ':' {
			r += string(b)
		} else {
			r += "=" + string(hex[b>>4]) + string(hex[(b>>0)&0xf])
		}
	}
	return r
}

var (
	errSigHeader         = errors.New("not DKIM-Signature header")
	errSigDuplicateTag   = errors.New("duplicate tag")
	errSigMissingCRLF    = errors.New("missing crlf at end")
	errSigExpired        = errors.New("signature timestamp (t=) must be before signature expiration (x=)")
	errSigIdentityDomain = errors.New("identity domain (i=) not under domain (d=)")
	errSigMissingTag     = errors.New("missing required tag")
	errSigUnknownVersion = errors.New("unknown version")
	errSigBodyHash       = errors.New("bad body hash size given algorithm")
)

// parseSignatures returns the parsed form of a DKIM-Signature header.
//
// buf must end in crlf, as it should have occurred in the mail message.
//
// The dkim signature with signature left empty ("b=") and without trailing
// crlf is returned, for use in verification.
func parseSignature(buf []byte, smtputf8 bool) (sig *Sig, verifySig []byte, err error) {
	defer func() {
		if x := recover(); x == nil {
			return
		} else if xerr, ok := x.(error); ok {
			sig = nil
			verifySig = nil
			err = xerr
		} else {
			panic(x)
		}
	}()

	xerrorf := func(format string, args ...any) {
		panic(fmt.Errorf(format, args...))
	}

	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		xerrorf("%w", errSigMissingCRLF)
	}
	buf = buf[:len(buf)-2]

	ds := newSigWithDefaults()
	seen := map[string]struct{}{}
	p := parser{s: string(buf), smtputf8: smtputf8}
	name := p.xhdrName(false)
	if !strings.EqualFold(name, "DKIM-Signature") {
		xerrorf("%w", errSigHeader)
	}
	p.wsp()
	p.xtake(":")
	p.wsp()
	// ../rfc/6376:655
	// ../rfc/6376:656 ../rfc/6376-eid5070
	// ../rfc/6376:658 ../rfc/6376-eid5070
	for {
		p.fws()
		k := p.xtagName()
		p.fws()
		p.xtake("=")
		// Special case for "b", see below.
		if k != "b" {
			p.fws()
		}
		// Keys are case-sensitive: ../rfc/6376:679
		if _, ok := seen[k]; ok {
			// Duplicates not allowed: ../rfc/6376:683
			xerrorf("%w: %q", errSigDuplicateTag, k)
			break
		}
		seen[k] = struct{}{}

		// ../rfc/6376:1021
		switch k {
		case "v":
			// ../rfc/6376:1025
			ds.Version = int(p.xnumber(10))
			if ds.Version != 1 {
				xerrorf("%w: version %d", errSigUnknownVersion, ds.Version)
			}
		case "a":
			// ../rfc/6376:1038
			ds.AlgorithmSign, ds.AlgorithmHash = p.xalgorithm()
		case "b":
			// ../rfc/6376:1054
			// To calculate the hash, we have to feed the DKIM-Signature header to the hash
			// function, but with the value for "b=" (the signature) left out. The parser
			// tracks all data that is read, except when drop is true.
			// ../rfc/6376:997
			// Surrounding whitespace must be cleared as well. ../rfc/6376:1659
			// Note: The RFC says "surrounding" whitespace, but whitespace is only allowed
			// before the value as part of the ABNF production for "b". Presumably the
			// intention is to ignore the trailing "[FWS]" for the tag-spec production,
			// ../rfc/6376:656
			// Another indication is the term "value portion", ../rfc/6376:1667. It appears to
			// mean everything after the "b=" part, instead of the actual value (either encoded
			// or decoded).
			p.drop = true
			p.fws()
			ds.Signature = p.xbase64()
			p.fws()
			p.drop = false
		case "bh":
			// ../rfc/6376:1076
			ds.BodyHash = p.xbase64()
		case "c":
			// ../rfc/6376:1088
			ds.Canonicalization = p.xcanonical()
			// ../rfc/6376:810
		case "d":
			// ../rfc/6376:1105
			ds.Domain = p.xdomain()
		case "h":
			// ../rfc/6376:1134
			ds.SignedHeaders = p.xsignedHeaderFields()
		case "i":
			// ../rfc/6376:1171
			id := p.xauid()
			ds.Identity = &id
		case "l":
			// ../rfc/6376:1244
			ds.Length = p.xbodyLength()
		case "q":
			// ../rfc/6376:1268
			ds.QueryMethods = p.xqueryMethods()
		case "s":
			// ../rfc/6376:1300
			ds.Selector = p.xselector()
		case "t":
			// ../rfc/6376:1310
			ds.SignTime = p.xtimestamp()
		case "x":
			// ../rfc/6376:1327
			ds.ExpireTime = p.xtimestamp()
		case "z":
			// ../rfc/6376:1361
			ds.CopiedHeaders = p.xcopiedHeaderFields()
		default:
			// We must ignore unknown fields. ../rfc/6376:692 ../rfc/6376:1022
			p.xchar() // ../rfc/6376-eid5070
			for !p.empty() && !p.hasPrefix(";") {
				p.xchar()
			}
		}
		p.fws()

		if p.empty() {
			break
		}
		p.xtake(";")
		if p.empty() {
			break
		}
	}

	// ../rfc/6376:2532
	required := []string{"v", "a", "b", "bh", "d", "h", "s"}
	for _, req := range required {
		if _, ok := seen[req]; !ok {
			xerrorf("%w: %q", errSigMissingTag, req)
		}
	}

	if strings.EqualFold(ds.AlgorithmHash, "sha1") && len(ds.BodyHash) != 20 {
		xerrorf("%w: got %d bytes, must be 20 for sha1", errSigBodyHash, len(ds.BodyHash))
	} else if strings.EqualFold(ds.AlgorithmHash, "sha256") && len(ds.BodyHash) != 32 {
		xerrorf("%w: got %d bytes, must be 32 for sha256", errSigBodyHash, len(ds.BodyHash))
	}

	// ../rfc/6376:1337
	if ds.SignTime >= 0 && ds.ExpireTime >= 0 && ds.SignTime >= ds.ExpireTime {
		xerrorf("%w", errSigExpired)
	}

	// Default identity is "@" plus domain. We don't set this value because we want to
	// keep the distinction between absent value.
	// ../rfc/6376:1172 ../rfc/6376:2537 ../rfc/6376:2541
	if ds.Identity != nil && ds.Identity.Domain.ASCII != ds.Domain.ASCII && !strings.HasSuffix(ds.Identity.Domain.ASCII, "."+ds.Domain.ASCII) {
		xerrorf("%w: identity domain %q not under domain %q", errSigIdentityDomain, ds.Identity.Domain.ASCII, ds.Domain.ASCII)
	}

	return ds, []byte(p.tracked), nil
}
