package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Record is a DKIM DNS record, served on <selector>._domainkey.<domain> for a
// given selector and domain (s= and d= in the DKIM-Signature).
//
// The record is a semicolon-separated list of "="-separated field value pairs.
// Strings should be compared case-insensitively, e.g. k=ed25519 is equivalent to k=ED25519.
//
// Example:
//
//	v=DKIM1;h=sha256;k=ed25519;p=ln5zd/JEX4Jy60WAhUOv33IYm2YZMyTQAdr9stML504=
type Record struct {
	Version  string   // Version, fixed "DKIM1" (case sensitive). Field "v".
	Hashes   []string // Acceptable hash algorithms, e.g. "sha1", "sha256". Optional, defaults to all algorithms. Field "h".
	Key      string   // Key type, "rsa" or "ed25519". Optional, default "rsa". Field "k".
	Notes    string   // Debug notes. Field "n".
	Pubkey   []byte   // Public key, as base64 in record. If empty, the key has been revoked. Field "p".
	Services []string // Service types. Optional, default "*" for all services. Other values: "email". Field "s".
	Flags    []string // Flags, colon-separated. Optional, default is no flags. Other values: "y" for testing DKIM, "s" for "i=" must have same domain as "d" in signatures. Field "t".

	PublicKey any `json:"-"` // Parsed form of public key, an *rsa.PublicKey or ed25519.PublicKey.
}

// ../rfc/6376:1438

// ServiceAllowed returns whether service s is allowed by this key.
//
// The optional field "s" can specify purposes for which the key can be used. If
// value was specified, both "*" and "email" are enough for use with DKIM.
func (r *Record) ServiceAllowed(s string) bool {
	if len(r.Services) == 0 {
		return true
	}
	for _, ss := range r.Services {
		if ss == "*" || strings.EqualFold(s, ss) {
			return true
		}
	}
	return false
}

// Record returns a DNS TXT record that should be served at
// <selector>._domainkey.<domain>.
//
// Only values that are not the default values are included.
func (r *Record) Record() (string, error) {
	var l []string
	add := func(s string) {
		l = append(l, s)
	}

	if r.Version != "DKIM1" {
		return "", fmt.Errorf("bad version, must be \"DKIM1\"")
	}
	add("v=DKIM1")
	if len(r.Hashes) > 0 {
		add("h=" + strings.Join(r.Hashes, ":"))
	}
	if r.Key != "" && !strings.EqualFold(r.Key, "rsa") {
		add("k=" + r.Key)
	}
	if r.Notes != "" {
		add("n=" + qpSection(r.Notes))
	}
	if len(r.Services) > 0 && (len(r.Services) != 1 || r.Services[0] != "*") {
		add("s=" + strings.Join(r.Services, ":"))
	}
	if len(r.Flags) > 0 {
		add("t=" + strings.Join(r.Flags, ":"))
	}
	// A missing public key is valid, it means the key has been revoked. ../rfc/6376:1501
	pk := r.Pubkey
	if len(pk) == 0 && r.PublicKey != nil {
		switch k := r.PublicKey.(type) {
		case *rsa.PublicKey:
			var err error
			pk, err = x509.MarshalPKIXPublicKey(k)
			if err != nil {
				return "", fmt.Errorf("marshal rsa public key: %v", err)
			}
		case ed25519.PublicKey:
			pk = []byte(k)
		default:
			return "", fmt.Errorf("unknown public key type %T", r.PublicKey)
		}
	}
	add("p=" + base64.StdEncoding.EncodeToString(pk))
	return strings.Join(l, ";"), nil
}

func qpSection(s string) string {
	const hex = "0123456789ABCDEF"

	// ../rfc/2045:1260
	var r string
	for i, b := range []byte(s) {
		if i > 0 && (b == ' ' || b == '\t') || b > ' ' && b < 0x7f && b != '=' {
			r += string(rune(b))
		} else {
			r += "=" + string(hex[b>>4]) + string(hex[(b>>0)&0xf])
		}
	}
	return r
}

var (
	errRecordDuplicateTag     = errors.New("duplicate tag")
	errRecordMissingField     = errors.New("missing field")
	errRecordBadPublicKey     = errors.New("bad public key")
	errRecordUnknownAlgorithm = errors.New("unknown algorithm")
	errRecordVersionFirst     = errors.New("first field must be version")
)

// ParseRecord parses a DKIM DNS TXT record.
//
// If the record is a dkim record, but an error occurred, isdkim will be true and
// err will be the error. Such errors must be treated differently from parse errors
// where the record does not appear to be DKIM, which can happen with misconfigured
// DNS (e.g. wildcard records).
func ParseRecord(s string) (record *Record, isdkim bool, err error) {
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		if xerr, ok := x.(error); ok {
			record = nil
			err = xerr
			return
		}
		panic(x)
	}()

	xerrorf := func(format string, args ...any) {
		panic(fmt.Errorf(format, args...))
	}

	record = &Record{
		Version:  "DKIM1",
		Key:      "rsa",
		Services: []string{"*"},
	}

	p := parser{s: s, drop: true}
	seen := map[string]struct{}{}
	// ../rfc/6376:655
	// ../rfc/6376:656 ../rfc/6376-eid5070
	// ../rfc/6376:658 ../rfc/6376-eid5070
	// ../rfc/6376:1438
	for {
		p.fws()
		k := p.xtagName()
		p.fws()
		p.xtake("=")
		p.fws()
		// Keys are case-sensitive: ../rfc/6376:679
		if _, ok := seen[k]; ok {
			// Duplicates not allowed: ../rfc/6376:683
			xerrorf("%w: %q", errRecordDuplicateTag, k)
			break
		}
		seen[k] = struct{}{}
		// Version must be the first.
		switch k {
		case "v":
			// ../rfc/6376:1443
			v := p.xtake("DKIM1")
			// Version being set is a signal this appears to be a valid record. We must not
			// treat e.g. DKIM1.1 as valid, so we explicitly check there is no more data before
			// we decide this record is DKIM.
			p.fws()
			if !p.empty() {
				p.xtake(";")
			}
			record.Version = v
			if len(seen) != 1 {
				// If version is present, it must be the first.
				xerrorf("%w", errRecordVersionFirst)
			}
			isdkim = true
			if p.empty() {
				break
			}
			continue

		case "h":
			// ../rfc/6376:1463
			record.Hashes = []string{p.xhyphenatedWord()}
			for p.peekfws(":") {
				p.fws()
				p.xtake(":")
				p.fws()
				record.Hashes = append(record.Hashes, p.xhyphenatedWord())
			}
		case "k":
			// ../rfc/6376:1478
			record.Key = p.xhyphenatedWord()
		case "n":
			// ../rfc/6376:1491
			record.Notes = p.xqpSection()
		case "p":
			// ../rfc/6376:1501
			record.Pubkey = p.xbase64()
		case "s":
			// ../rfc/6376:1533
			record.Services = []string{p.xhyphenatedWord()}
			for p.peekfws(":") {
				p.fws()
				p.xtake(":")
				p.fws()
				record.Services = append(record.Services, p.xhyphenatedWord())
			}
		case "t":
			// ../rfc/6376:1554
			record.Flags = []string{p.xhyphenatedWord()}
			for p.peekfws(":") {
				p.fws()
				p.xtake(":")
				p.fws()
				record.Flags = append(record.Flags, p.xhyphenatedWord())
			}
		default:
			// We must ignore unknown fields. ../rfc/6376:692 ../rfc/6376:1439
			for !p.empty() && !p.hasPrefix(";") {
				p.xchar()
			}
		}

		isdkim = true
		p.fws()
		if p.empty() {
			break
		}
		p.xtake(";")
		if p.empty() {
			break
		}
	}

	if _, ok := seen["p"]; !ok {
		xerrorf("%w: public key", errRecordMissingField)
	}

	switch strings.ToLower(record.Key) {
	case "", "rsa":
		if len(record.Pubkey) == 0 {
			// Revoked key, nothing to do.
		} else if pk, err := x509.ParsePKIXPublicKey(record.Pubkey); err != nil {
			xerrorf("%w: %s", errRecordBadPublicKey, err)
		} else if _, ok := pk.(*rsa.PublicKey); !ok {
			xerrorf("%w: got %T, need an RSA key", errRecordBadPublicKey, record.PublicKey)
		} else {
			record.PublicKey = pk
		}
	case "ed25519":
		if len(record.Pubkey) == 0 {
			// Revoked key, nothing to do.
		} else if len(record.Pubkey) != ed25519.PublicKeySize {
			xerrorf("%w: got %d bytes, need %d", errRecordBadPublicKey, len(record.Pubkey), ed25519.PublicKeySize)
		} else {
			record.PublicKey = ed25519.PublicKey(record.Pubkey)
		}
	default:
		xerrorf("%w: %q", errRecordUnknownAlgorithm, record.Key)
	}

	return record, true, nil
}
