package arc

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mjl-/mox/dns"
)

var (
	ErrParse             = errors.New("arc: parse error")
	ErrMissingCRLF       = errors.New("arc: missing crlf at end")
	ErrMissingTag        = errors.New("arc: missing required tag")
	ErrDuplicateTag      = errors.New("arc: duplicate tag")
	ErrDisallowedTag     = errors.New("arc: disallowed tag present")
	ErrBadInstance       = errors.New("arc: invalid instance number")
	ErrBadChainStatus    = errors.New("arc: invalid chain validation status")
	ErrNotAMSHeader      = errors.New("arc: not an ARC-Message-Signature header")
	ErrNotASHeader       = errors.New("arc: not an ARC-Seal header")
	ErrNotAARHeader      = errors.New("arc: not an ARC-Authentication-Results header")
	ErrBodyHashSize      = errors.New("arc: bad body hash size for algorithm")
)

// arcParser handles tag=value parsing for ARC headers.
type arcParser struct {
	s        string
	o        int
	tracked  string
	drop     bool
}

func (p *arcParser) xerrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if p.o < len(p.s) {
		msg = fmt.Sprintf("%s (leftover %q)", msg, p.s[p.o:])
	}
	panic(fmt.Errorf("%w: %s", ErrParse, msg))
}

func (p *arcParser) track(s string) {
	if !p.drop {
		p.tracked += s
	}
}

func (p *arcParser) hasPrefix(s string) bool {
	return strings.HasPrefix(p.s[p.o:], s)
}

func (p *arcParser) xtaken(n int) string {
	r := p.s[p.o : p.o+n]
	p.o += n
	p.track(r)
	return r
}

func (p *arcParser) empty() bool {
	return p.o >= len(p.s)
}

func (p *arcParser) xtake(s string) string {
	if !strings.HasPrefix(p.s[p.o:], s) {
		p.xerrorf("expected %q", s)
	}
	return p.xtaken(len(s))
}

func (p *arcParser) take(s string) bool {
	if strings.HasPrefix(p.s[p.o:], s) {
		p.o += len(s)
		p.track(s)
		return true
	}
	return false
}

// wsp consumes optional whitespace (space and tab).
func (p *arcParser) wsp() {
	for !p.empty() {
		c := p.s[p.o]
		if c == ' ' || c == '\t' {
			p.xtaken(1)
		} else {
			break
		}
	}
}

// fws consumes optional folding whitespace.
func (p *arcParser) fws() {
	p.wsp()
	if p.hasPrefix("\r\n ") || p.hasPrefix("\r\n\t") {
		p.xtaken(3)
		p.wsp()
	}
}

func (p *arcParser) xtagName() string {
	start := p.o
	for i, c := range p.s[p.o:] {
		if isalpha(c) || (i > 0 && (isdigit(c) || c == '_')) {
			continue
		}
		if i == 0 {
			p.xerrorf("expected tag name")
		}
		result := p.s[start : start+i]
		p.xtaken(i)
		return result
	}
	if p.o == start {
		p.xerrorf("expected tag name")
	}
	result := p.s[start:]
	p.xtaken(len(p.s) - p.o)
	return result
}

func (p *arcParser) xnumber(maxDigits int) int64 {
	start := p.o
	for _, c := range p.s[p.o:] {
		if c >= '0' && c <= '9' {
			continue
		}
		break
	}
	i := 0
	for _, c := range p.s[p.o:] {
		if c >= '0' && c <= '9' {
			i++
			continue
		}
		break
	}
	if i == 0 {
		p.xerrorf("expected digits")
	}
	if i > maxDigits {
		p.xerrorf("too many digits")
	}
	s := p.xtaken(i)
	_ = start
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		p.xerrorf("parsing digits: %s", err)
	}
	return v
}

// xbase64 parses base64 data, ignoring FWS within.
func (p *arcParser) xbase64() []byte {
	var s string
	for !p.empty() {
		c := p.s[p.o]
		if isalphadigit(rune(c)) || c == '+' || c == '/' || c == '=' {
			s += string(c)
			p.xtaken(1)
			continue
		}
		if c == ' ' || c == '\t' {
			p.xtaken(1)
			continue
		}
		if c == '\r' && p.hasPrefix("\r\n") && len(p.s) > p.o+2 && (p.s[p.o+2] == ' ' || p.s[p.o+2] == '\t') {
			p.xtaken(3)
			p.wsp()
			continue
		}
		break
	}
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		p.xerrorf("decoding base64: %v", err)
	}
	return buf
}

func (p *arcParser) xalgorithm() (sign, hash string) {
	sign = p.xhyphenatedWord()
	p.xtake("-")
	hash = p.xhyphenatedWord()
	return
}

func (p *arcParser) xhyphenatedWord() string {
	start := p.o
	for i, c := range p.s[p.o:] {
		if isalpha(c) || (i > 0 && isdigit(c)) || (i > 0 && c == '-' && p.o+i+1 < len(p.s) && isalphadigit(rune(p.s[p.o+i+1]))) {
			continue
		}
		if i == 0 {
			p.xerrorf("expected hyphenated-word")
		}
		result := p.s[start : start+i]
		p.xtaken(i)
		return result
	}
	if p.o == start {
		p.xerrorf("expected hyphenated-word")
	}
	return p.xtaken(len(p.s) - p.o)
}

func (p *arcParser) xdomain() dns.Domain {
	subdomain := func(c rune, i int) bool {
		return isalphadigit(c) || (i > 0 && c == '-' && p.o+i+1 < len(p.s))
	}
	start := p.o
	s := p.xtakefn1(subdomain)
	for p.hasPrefix(".") {
		s += p.xtake(".")
		s += p.xtakefn1(subdomain)
	}
	_ = start
	d, err := dns.ParseDomain(s)
	if err != nil {
		p.xerrorf("parsing domain %q: %s", s, err)
	}
	return d
}

func (p *arcParser) xselector() dns.Domain {
	subdomain := func(c rune, i int) bool {
		return isalphadigit(c) || (i > 0 && (c == '-' || c == '_') && p.o+i+1 < len(p.s))
	}
	s := p.xtakefn1(subdomain)
	for p.hasPrefix(".") {
		s += p.xtake(".")
		s += p.xtakefn1(subdomain)
	}
	return dns.Domain{ASCII: strings.ToLower(s)}
}

func (p *arcParser) xtakefn1(fn func(c rune, i int) bool) string {
	if p.empty() {
		p.xerrorf("expected at least 1 char")
	}
	var r string
	for i, c := range p.s[p.o:] {
		if !fn(c, i) {
			if i == 0 {
				p.xerrorf("expected at least 1 matching char")
			}
			p.xtaken(i)
			return r
		}
		r += string(c)
	}
	return p.xtaken(len(p.s) - p.o)
}

func (p *arcParser) xcanonical() string {
	s := p.xhyphenatedWord()
	if p.take("/") {
		return s + "/" + p.xhyphenatedWord()
	}
	return s
}

func (p *arcParser) xsignedHeaderFields() []string {
	l := []string{p.xhdrName()}
	for {
		p.fws()
		if !p.hasPrefix(":") {
			break
		}
		p.xtake(":")
		p.fws()
		l = append(l, p.xhdrName())
	}
	return l
}

func (p *arcParser) xhdrName() string {
	start := p.o
	for i, c := range p.s[p.o:] {
		if c > ' ' && c < 0x7f && c != ':' && c != ';' {
			continue
		}
		if i == 0 {
			p.xerrorf("expected header name")
		}
		result := p.s[start : start+i]
		p.xtaken(i)
		return result
	}
	if p.o == start {
		p.xerrorf("expected header name")
	}
	return p.xtaken(len(p.s) - p.o)
}

func (p *arcParser) xtimestamp() int64 {
	return p.xnumber(12)
}

// xchar consumes and returns a single character, ignoring FWS.
func (p *arcParser) xchar() rune {
	for !p.empty() {
		c := p.s[p.o]
		if c == ' ' || c == '\t' {
			p.xtaken(1)
			continue
		}
		if c == '\r' && p.hasPrefix("\r\n") && len(p.s) > p.o+2 && (p.s[p.o+2] == ' ' || p.s[p.o+2] == '\t') {
			p.xtaken(3)
			p.wsp()
			continue
		}
		break
	}
	if p.empty() {
		p.xerrorf("need another character")
	}
	var r rune
	for _, c := range p.s[p.o:] {
		r = c
		break
	}
	p.xtaken(1)
	return r
}

func isalpha(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isdigit(c rune) bool {
	return c >= '0' && c <= '9'
}

func isalphadigit(c rune) bool {
	return isalpha(c) || isdigit(c)
}

// parseHdrName parses a header field name (case insensitive), consuming up to and
// including the colon after the name.
func (p *arcParser) parseHdrName(expected string) {
	// Consume the header name.
	start := p.o
	for i, c := range p.s[p.o:] {
		if c == ':' {
			name := p.s[start : start+i]
			if !strings.EqualFold(name, expected) {
				p.xerrorf("expected header %q, got %q", expected, name)
			}
			p.xtaken(i)
			p.wsp()
			p.xtake(":")
			p.wsp()
			return
		}
		if c <= ' ' || c >= 0x7f {
			break
		}
	}
	p.xerrorf("expected header %q", expected)
}

// parseTags parses tag=value pairs from the current position.
// Returns a map of tag name to tag value string (unparsed).
func parseTags(p *arcParser) (map[string]string, error) {
	tags := map[string]string{}
	for {
		p.fws()
		if p.empty() {
			break
		}
		k := p.xtagName()
		p.fws()
		p.xtake("=")
		p.fws()

		if _, ok := tags[k]; ok {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTag, k)
		}

		// Read value until ; or end.
		start := p.o
		for !p.empty() && !p.hasPrefix(";") {
			p.o++
		}
		v := strings.TrimRight(p.s[start:p.o], " \t\r\n")
		// Track what we consumed.
		p.tracked += p.s[start:p.o]
		tags[k] = v

		p.fws()
		if p.empty() {
			break
		}
		p.xtake(";")
		if p.empty() {
			break
		}
	}
	return tags, nil
}

// ParseAMS parses an ARC-Message-Signature header.
// buf must end in CRLF.
func ParseAMS(buf []byte, smtputf8 bool) (ams *AMS, err error) {
	defer func() {
		if x := recover(); x != nil {
			if xerr, ok := x.(error); ok {
				ams = nil
				err = xerr
			} else {
				panic(x)
			}
		}
	}()

	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return nil, ErrMissingCRLF
	}

	s := string(buf[:len(buf)-2])
	p := &arcParser{s: s}
	p.parseHdrName("ARC-Message-Signature")

	// We need to parse b= specially: we need the header with b= value emptied for
	// verification. We'll do manual tag-value parsing.
	ams = &AMS{
		SignTime: -1,
		Canonicalization: "simple/simple",
	}
	ams.Raw = append([]byte{}, buf...)

	// Parse tag-value pairs manually, tracking b= position for verifySig.
	seen := map[string]struct{}{}
	remaining := s[p.o:]

	// Build verifySig: the header without trailing CRLF, with b= value emptied.
	// We parse tag=value pairs and record positions of b= value.
	type tagRange struct {
		key        string
		valueStart int // offset into `remaining`
		valueEnd   int
	}

	var bValueStart, bValueEnd int
	var hasBTag bool

	// Parse remaining as tag=value pairs.
	pos := 0
	for pos < len(remaining) {
		// Skip FWS.
		for pos < len(remaining) && (remaining[pos] == ' ' || remaining[pos] == '\t' || remaining[pos] == '\r' || remaining[pos] == '\n') {
			pos++
		}
		if pos >= len(remaining) {
			break
		}

		// Parse tag name.
		tagStart := pos
		for pos < len(remaining) && remaining[pos] != '=' && remaining[pos] != ' ' && remaining[pos] != '\t' && remaining[pos] != '\r' && remaining[pos] != '\n' {
			pos++
		}
		tagName := remaining[tagStart:pos]

		// Skip FWS.
		for pos < len(remaining) && (remaining[pos] == ' ' || remaining[pos] == '\t' || remaining[pos] == '\r' || remaining[pos] == '\n') {
			pos++
		}
		if pos >= len(remaining) || remaining[pos] != '=' {
			return nil, fmt.Errorf("%w: expected '=' after tag %q", ErrParse, tagName)
		}
		pos++ // skip '='

		if _, ok := seen[tagName]; ok {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTag, tagName)
		}
		seen[tagName] = struct{}{}

		// Value starts after '='.
		valStart := pos
		// Value runs until ';' or end.
		for pos < len(remaining) && remaining[pos] != ';' {
			pos++
		}
		valEnd := pos
		value := strings.TrimRight(remaining[valStart:valEnd], " \t\r\n")

		if tagName == "b" {
			hasBTag = true
			bValueStart = p.o + valStart
			bValueEnd = p.o + valEnd
		}

		// Skip ';'.
		if pos < len(remaining) && remaining[pos] == ';' {
			pos++
		}

		// Strip FWS from value for processing.
		cleanValue := stripFWS(value)

		switch tagName {
		case "i":
			n, err := strconv.ParseInt(cleanValue, 10, 32)
			if err != nil || n < 1 || n > 50 {
				return nil, fmt.Errorf("%w: bad instance %q", ErrBadInstance, cleanValue)
			}
			ams.Instance = int(n)
		case "a":
			parts := strings.SplitN(cleanValue, "-", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("%w: bad algorithm %q", ErrParse, cleanValue)
			}
			ams.AlgorithmSign = parts[0]
			ams.AlgorithmHash = parts[1]
		case "b":
			sig, err := base64.StdEncoding.DecodeString(stripFWS(value))
			if err != nil {
				return nil, fmt.Errorf("%w: bad b= base64: %v", ErrParse, err)
			}
			ams.Signature = sig
		case "bh":
			bh, err := base64.StdEncoding.DecodeString(cleanValue)
			if err != nil {
				return nil, fmt.Errorf("%w: bad bh= base64: %v", ErrParse, err)
			}
			ams.BodyHash = bh
		case "d":
			d, err := dns.ParseDomain(cleanValue)
			if err != nil {
				return nil, fmt.Errorf("%w: bad d= domain %q: %v", ErrParse, cleanValue, err)
			}
			ams.Domain = d
		case "h":
			hdrs := strings.Split(cleanValue, ":")
			for i, h := range hdrs {
				hdrs[i] = strings.TrimSpace(h)
			}
			ams.SignedHeaders = hdrs
		case "s":
			ams.Selector = dns.Domain{ASCII: strings.ToLower(cleanValue)}
		case "c":
			ams.Canonicalization = cleanValue
		case "t":
			n, err := strconv.ParseInt(cleanValue, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: bad t= timestamp: %v", ErrParse, err)
			}
			ams.SignTime = n
		case "l", "q", "x", "z":
			return nil, fmt.Errorf("%w: %q not allowed in ARC-Message-Signature", ErrDisallowedTag, tagName)
		default:
			// Unknown tags are ignored per spec.
		}
	}

	// Check required tags.
	for _, req := range []string{"i", "a", "b", "bh", "d", "h", "s"} {
		if _, ok := seen[req]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrMissingTag, req)
		}
	}

	// Validate body hash size.
	if strings.EqualFold(ams.AlgorithmHash, "sha1") && len(ams.BodyHash) != 20 {
		return nil, fmt.Errorf("%w: got %d bytes, must be 20 for sha1", ErrBodyHashSize, len(ams.BodyHash))
	} else if strings.EqualFold(ams.AlgorithmHash, "sha256") && len(ams.BodyHash) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, must be 32 for sha256", ErrBodyHashSize, len(ams.BodyHash))
	}

	// Build verifySig: header without trailing CRLF, with b= value emptied.
	if hasBTag {
		ams.VerifySig = append([]byte{}, s[:bValueStart]...)
		ams.VerifySig = append(ams.VerifySig, s[bValueEnd:]...)
	} else {
		ams.VerifySig = []byte(s)
	}

	return ams, nil
}

// ParseAS parses an ARC-Seal header.
// buf must end in CRLF.
func ParseAS(buf []byte, smtputf8 bool) (as *AS, err error) {
	defer func() {
		if x := recover(); x != nil {
			if xerr, ok := x.(error); ok {
				as = nil
				err = xerr
			} else {
				panic(x)
			}
		}
	}()

	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return nil, ErrMissingCRLF
	}

	s := string(buf[:len(buf)-2])

	// Find header name.
	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 {
		return nil, fmt.Errorf("%w: no colon in header", ErrNotASHeader)
	}
	name := strings.TrimRight(s[:colonIdx], " \t")
	if !strings.EqualFold(name, "ARC-Seal") {
		return nil, fmt.Errorf("%w: got %q", ErrNotASHeader, name)
	}

	valueStart := colonIdx + 1
	remaining := s[valueStart:]

	as = &AS{
		SignTime: -1,
	}
	as.Raw = append([]byte{}, buf...)

	seen := map[string]struct{}{}
	var bValueStart, bValueEnd int
	var hasBTag bool

	pos := 0
	for pos < len(remaining) {
		for pos < len(remaining) && (remaining[pos] == ' ' || remaining[pos] == '\t' || remaining[pos] == '\r' || remaining[pos] == '\n') {
			pos++
		}
		if pos >= len(remaining) {
			break
		}

		tagStart := pos
		for pos < len(remaining) && remaining[pos] != '=' && remaining[pos] != ' ' && remaining[pos] != '\t' && remaining[pos] != '\r' && remaining[pos] != '\n' {
			pos++
		}
		tagName := remaining[tagStart:pos]

		for pos < len(remaining) && (remaining[pos] == ' ' || remaining[pos] == '\t' || remaining[pos] == '\r' || remaining[pos] == '\n') {
			pos++
		}
		if pos >= len(remaining) || remaining[pos] != '=' {
			return nil, fmt.Errorf("%w: expected '=' after tag %q", ErrParse, tagName)
		}
		pos++

		if _, ok := seen[tagName]; ok {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTag, tagName)
		}
		seen[tagName] = struct{}{}

		valStart := pos
		for pos < len(remaining) && remaining[pos] != ';' {
			pos++
		}
		valEnd := pos
		value := strings.TrimRight(remaining[valStart:valEnd], " \t\r\n")

		if tagName == "b" {
			hasBTag = true
			bValueStart = valueStart + valStart
			bValueEnd = valueStart + valEnd
		}

		if pos < len(remaining) && remaining[pos] == ';' {
			pos++
		}

		cleanValue := stripFWS(value)

		// Check for disallowed tags first.
		switch tagName {
		case "h":
			return nil, fmt.Errorf("%w: h= not allowed in ARC-Seal", ErrDisallowedTag)
		case "bh":
			return nil, fmt.Errorf("%w: bh= not allowed in ARC-Seal", ErrDisallowedTag)
		}

		switch tagName {
		case "i":
			n, err := strconv.ParseInt(cleanValue, 10, 32)
			if err != nil || n < 1 || n > 50 {
				return nil, fmt.Errorf("%w: bad instance %q", ErrBadInstance, cleanValue)
			}
			as.Instance = int(n)
		case "a":
			parts := strings.SplitN(cleanValue, "-", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("%w: bad algorithm %q", ErrParse, cleanValue)
			}
			as.AlgorithmSign = parts[0]
			as.AlgorithmHash = parts[1]
		case "b":
			sig, err := base64.StdEncoding.DecodeString(stripFWS(value))
			if err != nil {
				return nil, fmt.Errorf("%w: bad b= base64: %v", ErrParse, err)
			}
			as.Signature = sig
		case "cv":
			switch ChainStatus(cleanValue) {
			case ChainStatusNone, ChainStatusPass, ChainStatusFail:
				as.ChainValidation = ChainStatus(cleanValue)
			default:
				return nil, fmt.Errorf("%w: %q", ErrBadChainStatus, cleanValue)
			}
		case "d":
			d, err := dns.ParseDomain(cleanValue)
			if err != nil {
				return nil, fmt.Errorf("%w: bad d= domain %q: %v", ErrParse, cleanValue, err)
			}
			as.Domain = d
		case "s":
			as.Selector = dns.Domain{ASCII: strings.ToLower(cleanValue)}
		case "t":
			n, err := strconv.ParseInt(cleanValue, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: bad t= timestamp: %v", ErrParse, err)
			}
			as.SignTime = n
		default:
			// Only allowed tags: i, a, b, cv, d, s, t. Others are ignored per
			// forward-compatibility, but we note that the RFC is quite strict about
			// ARC-Seal tags.
		}
	}

	for _, req := range []string{"i", "a", "b", "cv", "d", "s"} {
		if _, ok := seen[req]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrMissingTag, req)
		}
	}

	if hasBTag {
		as.VerifySig = append([]byte{}, s[:bValueStart]...)
		as.VerifySig = append(as.VerifySig, s[bValueEnd:]...)
	} else {
		as.VerifySig = []byte(s)
	}

	return as, nil
}

// ParseAAR parses an ARC-Authentication-Results header.
// buf must end in CRLF.
func ParseAAR(buf []byte, smtputf8 bool) (aar *AAR, err error) {
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return nil, ErrMissingCRLF
	}

	s := string(buf[:len(buf)-2])

	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 {
		return nil, fmt.Errorf("%w: no colon in header", ErrNotAARHeader)
	}
	name := strings.TrimRight(s[:colonIdx], " \t")
	if !strings.EqualFold(name, "ARC-Authentication-Results") {
		return nil, fmt.Errorf("%w: got %q", ErrNotAARHeader, name)
	}

	value := strings.TrimLeft(s[colonIdx+1:], " \t")

	// Format: i=<N>; <authserv-id>; <payload>
	// Or: i=<N>; <authserv-id> (with optional trailing authres-payload)

	// Strip FWS (unfold) for parsing the instance prefix.
	unfolded := unfoldFWS(value)

	// Parse i=N.
	unfolded = strings.TrimLeft(unfolded, " \t")
	if !strings.HasPrefix(unfolded, "i=") {
		return nil, fmt.Errorf("%w: missing i= tag", ErrMissingTag)
	}
	unfolded = unfolded[2:]

	// Parse instance number.
	numEnd := 0
	for numEnd < len(unfolded) && unfolded[numEnd] >= '0' && unfolded[numEnd] <= '9' {
		numEnd++
	}
	if numEnd == 0 {
		return nil, fmt.Errorf("%w: bad instance number", ErrBadInstance)
	}
	instance, err := strconv.ParseInt(unfolded[:numEnd], 10, 32)
	if err != nil || instance < 1 || instance > 50 {
		return nil, fmt.Errorf("%w: instance %q", ErrBadInstance, unfolded[:numEnd])
	}
	unfolded = unfolded[numEnd:]

	// Expect ';' separator after instance.
	unfolded = strings.TrimLeft(unfolded, " \t")
	if len(unfolded) == 0 || unfolded[0] != ';' {
		return nil, fmt.Errorf("%w: expected ';' after instance", ErrParse)
	}
	unfolded = strings.TrimLeft(unfolded[1:], " \t")

	// Parse authserv-id (up to next ';' or end).
	semiIdx := strings.IndexByte(unfolded, ';')
	var authServID, payload string
	if semiIdx >= 0 {
		authServID = strings.TrimSpace(unfolded[:semiIdx])
		payload = strings.TrimSpace(unfolded[semiIdx+1:])
	} else {
		authServID = strings.TrimSpace(unfolded)
		payload = ""
	}

	// Remove any comment from authServID.
	if parenIdx := strings.IndexByte(authServID, '('); parenIdx >= 0 {
		authServID = strings.TrimSpace(authServID[:parenIdx])
	}

	aar = &AAR{
		Instance:   int(instance),
		AuthServID: authServID,
		Payload:    payload,
		Raw:        append([]byte{}, buf...),
	}

	return aar, nil
}

// stripFWS removes CR, LF, space, and tab from a string.
func stripFWS(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// unfoldFWS removes CRLF followed by WSP (folding).
func unfoldFWS(s string) string {
	s = strings.ReplaceAll(s, "\r\n ", " ")
	s = strings.ReplaceAll(s, "\r\n\t", " ")
	return s
}
