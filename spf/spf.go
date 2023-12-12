// Package spf implements Sender Policy Framework (SPF, RFC 7208) for verifying
// remote mail server IPs with their published records.
//
// With SPF a domain can publish a policy as a DNS TXT record describing which IPs
// are allowed to send email with SMTP with the domain in the MAIL FROM command,
// and how to treat SMTP transactions coming from other IPs.
package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/stub"
)

// The net package always returns DNS names in absolute, lower-case form. We make
// sure we make names absolute when looking up. For verifying, we do not want to
// verify names relative to our local search domain.

var (
	MetricVerify stub.HistogramVec = stub.HistogramVecIgnore{}
)

// cross-link rfc and errata
// ../rfc/7208-eid5436 ../rfc/7208:2043
// ../rfc/7208-eid6721 ../rfc/7208:1928
// ../rfc/7208-eid5227 ../rfc/7208:1297
// ../rfc/7208-eid6595 ../rfc/7208:984

var (
	// Lookup errors.
	ErrName            = errors.New("spf: bad domain name")
	ErrNoRecord        = errors.New("spf: no txt record")
	ErrMultipleRecords = errors.New("spf: multiple spf txt records in dns")
	ErrDNS             = errors.New("spf: lookup of dns record")
	ErrRecordSyntax    = errors.New("spf: malformed spf txt record")

	// Evaluation errors.
	ErrTooManyDNSRequests = errors.New("spf: too many dns requests")
	ErrTooManyVoidLookups = errors.New("spf: too many void lookups")
	ErrMacroSyntax        = errors.New("spf: bad macro syntax")
)

const (
	// Maximum number of DNS requests to execute. This excludes some requests, such as
	// lookups of MX host results.
	dnsRequestsMax = 10

	// Maximum number of DNS lookups that result in no records before a StatusPermerror
	// is returned. This limit aims to prevent abuse.
	voidLookupsMax = 2
)

// Status is the result of an SPF verification.
type Status string

// ../rfc/7208:517
// ../rfc/7208:1836

const (
	StatusNone      Status = "none"      // E.g. no DNS domain name in session, or no SPF record in DNS.
	StatusNeutral   Status = "neutral"   // Explicit statement that nothing is said about the IP, "?" qualifier. None and Neutral must be treated the same.
	StatusPass      Status = "pass"      // IP is authorized.
	StatusFail      Status = "fail"      // IP is exlicitly not authorized. "-" qualifier.
	StatusSoftfail  Status = "softfail"  // Weak statement that IP is probably not authorized, "~" qualifier.
	StatusTemperror Status = "temperror" // Trying again later may succeed, e.g. for temporary DNS lookup error.
	StatusPermerror Status = "permerror" // Error requiring some intervention to correct. E.g. invalid DNS record.
)

// Args are the parameters to the SPF verification algorithm ("check_host" in the RFC).
//
// All fields should be set as they can be required for macro expansions.
type Args struct {
	// RemoteIP will be checked as sender for email.
	RemoteIP net.IP

	// Address from SMTP MAIL FROM command. Zero values for a null reverse path (used for DSNs).
	MailFromLocalpart smtp.Localpart
	MailFromDomain    dns.Domain

	// HelloDomain is from the SMTP EHLO/HELO command.
	HelloDomain dns.IPDomain

	LocalIP       net.IP
	LocalHostname dns.Domain

	// Explanation string to use for failure. In case of "include", where explanation
	// from original domain must be used.
	// May be set for recursive calls.
	explanation *string

	// Domain to validate.
	domain dns.Domain

	// Effective sender. Equal to MailFrom if non-zero, otherwise set to "postmaster" at HelloDomain.
	senderLocalpart smtp.Localpart
	senderDomain    dns.Domain

	// To enforce the limit on lookups. Initialized automatically if nil.
	dnsRequests *int
	voidLookups *int
}

// Mocked for testing expanding "t" macro.
var timeNow = time.Now

// Lookup looks up and parses an SPF TXT record for domain.
//
// Authentic indicates if the DNS results were DNSSEC-verified.
func Lookup(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, domain dns.Domain) (rstatus Status, rtxt string, rrecord *Record, authentic bool, rerr error) {
	log := mlog.New("spf", elog)
	start := time.Now()
	defer func() {
		log.Debugx("spf lookup result", rerr,
			slog.Any("domain", domain),
			slog.Any("status", rstatus),
			slog.Any("record", rrecord),
			slog.Duration("duration", time.Since(start)))
	}()

	// ../rfc/7208:586
	host := domain.ASCII + "."
	if err := validateDNS(host); err != nil {
		return StatusNone, "", nil, false, fmt.Errorf("%w: %s: %s", ErrName, domain, err)
	}

	// Lookup spf record.
	txts, result, err := dns.WithPackage(resolver, "spf").LookupTXT(ctx, host)
	if dns.IsNotFound(err) {
		return StatusNone, "", nil, result.Authentic, fmt.Errorf("%w for %s", ErrNoRecord, host)
	} else if err != nil {
		return StatusTemperror, "", nil, result.Authentic, fmt.Errorf("%w: %s: %s", ErrDNS, host, err)
	}

	// Parse the records. We only handle those that look like spf records.
	var record *Record
	var text string
	for _, txt := range txts {
		var isspf bool
		r, isspf, err := ParseRecord(txt)
		if !isspf {
			// ../rfc/7208:595
			continue
		} else if err != nil {
			// ../rfc/7208:852
			return StatusPermerror, txt, nil, result.Authentic, fmt.Errorf("%w: %s", ErrRecordSyntax, err)
		}
		if record != nil {
			// ../rfc/7208:576
			return StatusPermerror, "", nil, result.Authentic, ErrMultipleRecords
		}
		text = txt
		record = r
	}
	if record == nil {
		// ../rfc/7208:837
		return StatusNone, "", nil, result.Authentic, ErrNoRecord
	}
	return StatusNone, text, record, result.Authentic, nil
}

// Verify checks if a remote IP is allowed to send email for a domain.
//
// If the SMTP "MAIL FROM" is set, it is used as identity (domain) to verify.
// Otherwise, the EHLO domain is verified if it is a valid domain.
//
// The returned Received.Result status will always be set, regardless of whether an
// error is returned.
// For status Temperror and Permerror, an error is always returned.
// For Fail, explanation may be set, and should be returned in the SMTP session if
// it is the reason the message is rejected. The caller should ensure the
// explanation is valid for use in SMTP, taking line length and ascii-only
// requirement into account.
//
// Verify takes the maximum number of 10 DNS requests into account, and the maximum
// of 2 lookups resulting in no records ("void lookups").
//
// Authentic indicates if the DNS results were DNSSEC-verified.
func Verify(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, args Args) (received Received, domain dns.Domain, explanation string, authentic bool, rerr error) {
	log := mlog.New("spf", elog)
	start := time.Now()
	defer func() {
		MetricVerify.ObserveLabels(float64(time.Since(start))/float64(time.Second), string(received.Result))
		log.Debugx("spf verify result", rerr,
			slog.Any("domain", args.domain),
			slog.Any("ip", args.RemoteIP),
			slog.Any("status", received.Result),
			slog.String("explanation", explanation),
			slog.Duration("duration", time.Since(start)))
	}()

	isHello, ok := prepare(&args)
	if !ok {
		received = Received{
			Result:       StatusNone,
			Comment:      "no domain, ehlo is an ip literal and mailfrom is empty",
			ClientIP:     args.RemoteIP,
			EnvelopeFrom: fmt.Sprintf("%s@%s", args.senderLocalpart, args.HelloDomain.IP.String()),
			Helo:         args.HelloDomain,
			Receiver:     args.LocalHostname.ASCII,
		}
		return received, dns.Domain{}, "", false, nil
	}

	status, mechanism, expl, authentic, err := checkHost(ctx, log, resolver, args)
	comment := fmt.Sprintf("domain %s", args.domain.ASCII)
	if isHello {
		comment += ", from ehlo because mailfrom is empty"
	}
	received = Received{
		Result:       status,
		Comment:      comment,
		ClientIP:     args.RemoteIP,
		EnvelopeFrom: fmt.Sprintf("%s@%s", args.senderLocalpart, args.senderDomain.ASCII), // ../rfc/7208:2090, explicitly "sender", not "mailfrom".
		Helo:         args.HelloDomain,
		Receiver:     args.LocalHostname.ASCII,
		Mechanism:    mechanism,
	}
	if err != nil {
		received.Problem = err.Error()
	}
	if isHello {
		received.Identity = "helo"
	} else {
		received.Identity = "mailfrom"
	}
	return received, args.domain, expl, authentic, err
}

// prepare args, setting fields sender* and domain as required for checkHost.
func prepare(args *Args) (isHello bool, ok bool) {
	// If MAIL FROM is set, that identity is used. Otherwise the EHLO identity is used.
	// MAIL FROM is preferred, because if we accept the message, and we have to send a
	// DSN, it helps to know it is a verified sender. If we would check an EHLO
	// identity, and it is different from the MAIL FROM, we may be sending the DSN to
	// an address with a domain that would not allow sending from the originating IP.
	// The RFC seems a bit confused, ../rfc/7208:778 implies MAIL FROM is preferred,
	// but ../rfc/7208:424 mentions that a MAIL FROM check can be avoided by first
	// doing HELO.

	args.explanation = nil
	args.dnsRequests = nil
	args.voidLookups = nil
	if args.MailFromDomain.IsZero() {
		// If there is on EHLO, and it is an IP, there is nothing to SPF-validate.
		if !args.HelloDomain.IsDomain() {
			return false, false
		}
		// If we have a mailfrom, we also have a localpart. But for EHLO we won't. ../rfc/7208:810
		args.senderLocalpart = "postmaster"
		args.senderDomain = args.HelloDomain.Domain
		isHello = true
	} else {
		args.senderLocalpart = args.MailFromLocalpart
		args.senderDomain = args.MailFromDomain
	}
	args.domain = args.senderDomain
	return isHello, true
}

// lookup spf record, then evaluate args against it.
func checkHost(ctx context.Context, log mlog.Log, resolver dns.Resolver, args Args) (rstatus Status, mechanism, rexplanation string, rauthentic bool, rerr error) {
	status, _, record, rauthentic, err := Lookup(ctx, log.Logger, resolver, args.domain)
	if err != nil {
		return status, "", "", rauthentic, err
	}

	var evalAuthentic bool
	rstatus, mechanism, rexplanation, evalAuthentic, rerr = evaluate(ctx, log, record, resolver, args)
	rauthentic = rauthentic && evalAuthentic
	return
}

// Evaluate evaluates the IP and names from args against the SPF DNS record for the domain.
func Evaluate(ctx context.Context, elog *slog.Logger, record *Record, resolver dns.Resolver, args Args) (rstatus Status, mechanism, rexplanation string, rauthentic bool, rerr error) {
	log := mlog.New("spf", elog)
	_, ok := prepare(&args)
	if !ok {
		return StatusNone, "default", "", false, fmt.Errorf("no domain name to validate")
	}
	return evaluate(ctx, log, record, resolver, args)
}

// evaluate RemoteIP against domain from args, given record.
func evaluate(ctx context.Context, log mlog.Log, record *Record, resolver dns.Resolver, args Args) (rstatus Status, mechanism, rexplanation string, rauthentic bool, rerr error) {
	start := time.Now()
	defer func() {
		log.Debugx("spf evaluate result", rerr,
			slog.Int("dnsrequests", *args.dnsRequests),
			slog.Int("voidlookups", *args.voidLookups),
			slog.Any("domain", args.domain),
			slog.Any("status", rstatus),
			slog.String("mechanism", mechanism),
			slog.String("explanation", rexplanation),
			slog.Duration("duration", time.Since(start)))
	}()

	if args.dnsRequests == nil {
		args.dnsRequests = new(int)
		args.voidLookups = new(int)
	}

	// Response is authentic until we find a non-authentic DNS response.
	rauthentic = true

	// To4 returns nil for an IPv6 address. To16 will return an IPv4-to-IPv6-mapped address.
	var remote6 net.IP
	remote4 := args.RemoteIP.To4()
	if remote4 == nil {
		remote6 = args.RemoteIP.To16()
	}

	// Check if ip matches remote ip, taking cidr mask into account.
	checkIP := func(ip net.IP, d Directive) bool {
		// ../rfc/7208:1097
		if remote4 != nil {
			ip4 := ip.To4()
			if ip4 == nil {
				return false
			}
			ones := 32
			if d.IP4CIDRLen != nil {
				ones = *d.IP4CIDRLen
			}
			mask := net.CIDRMask(ones, 32)
			return ip4.Mask(mask).Equal(remote4.Mask(mask))
		}

		ip6 := ip.To16()
		if ip6 == nil {
			return false
		}
		ones := 128
		if d.IP6CIDRLen != nil {
			ones = *d.IP6CIDRLen
		}
		mask := net.CIDRMask(ones, 128)
		return ip6.Mask(mask).Equal(remote6.Mask(mask))
	}

	// Used for "a" and "mx".
	checkHostIP := func(domain dns.Domain, d Directive, args *Args) (bool, Status, error) {
		ips, result, err := resolver.LookupIP(ctx, "ip", domain.ASCII+".")
		rauthentic = rauthentic && result.Authentic
		trackVoidLookup(err, args)
		// If "not found", we must ignore the error and treat as zero records in answer. ../rfc/7208:1116
		if err != nil && !dns.IsNotFound(err) {
			return false, StatusTemperror, err
		}
		for _, ip := range ips {
			if checkIP(ip, d) {
				return true, StatusPass, nil
			}
		}
		return false, StatusNone, nil
	}

	for _, d := range record.Directives {
		var match bool

		switch d.Mechanism {
		case "include", "a", "mx", "ptr", "exists":
			if err := trackLookupLimits(&args); err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, err
			}
		}

		switch d.Mechanism {
		case "all":
			// ../rfc/7208:1127
			match = true

		case "include":
			// ../rfc/7208:1143
			name, authentic, err := expandDomainSpecDNS(ctx, resolver, d.DomainSpec, args)
			rauthentic = rauthentic && authentic
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, fmt.Errorf("expanding domain-spec for include: %w", err)
			}
			nargs := args
			nargs.domain = dns.Domain{ASCII: strings.TrimSuffix(name, ".")}
			nargs.explanation = &record.Explanation // ../rfc/7208:1548
			status, _, _, authentic, err := checkHost(ctx, log, resolver, nargs)
			rauthentic = rauthentic && authentic
			// ../rfc/7208:1202
			switch status {
			case StatusPass:
				match = true
			case StatusTemperror:
				return StatusTemperror, d.MechanismString(), "", rauthentic, fmt.Errorf("include %q: %w", name, err)
			case StatusPermerror, StatusNone:
				return StatusPermerror, d.MechanismString(), "", rauthentic, fmt.Errorf("include %q resulted in status %q: %w", name, status, err)
			}

		case "a":
			// ../rfc/7208:1249
			// note: the syntax for DomainSpec hints that macros should be expanded. But
			// expansion is explicitly documented, and only for "include", "exists" and
			// "redirect". This reason for this could be low-effort reuse of the domain-spec
			// ABNF rule. It could be an oversight. We are not implementing expansion for the
			// mechanism for which it isn't specified.
			host, err := evaluateDomainSpec(d.DomainSpec, args.domain)
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, err
			}
			hmatch, status, err := checkHostIP(host, d, &args)
			if err != nil {
				return status, d.MechanismString(), "", rauthentic, err
			}
			match = hmatch

		case "mx":
			// ../rfc/7208:1262
			host, err := evaluateDomainSpec(d.DomainSpec, args.domain)
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, err
			}
			// Note: LookupMX can return an error and still return MX records.
			mxs, result, err := resolver.LookupMX(ctx, host.ASCII+".")
			rauthentic = rauthentic && result.Authentic
			trackVoidLookup(err, &args)
			// note: we handle "not found" simply as a result of zero mx records.
			if err != nil && !dns.IsNotFound(err) {
				return StatusTemperror, d.MechanismString(), "", rauthentic, err
			}
			if err == nil && len(mxs) == 1 && mxs[0].Host == "." {
				// Explicitly no MX.
				break
			}
			for i, mx := range mxs {
				// ../rfc/7208:947 says that each mx record cannot result in more than 10 DNS
				// requests. This seems independent of the overall limit of 10 DNS requests. So an
				// MX request resulting in 11 names is valid, but we must return a permerror if we
				// found no match before the 11th name.
				// ../rfc/7208:945
				if i >= 10 {
					return StatusPermerror, d.MechanismString(), "", rauthentic, ErrTooManyDNSRequests
				}
				// Parsing lax (unless in pedantic mode) for MX targets with underscores as seen in the wild.
				mxd, err := dns.ParseDomainLax(strings.TrimSuffix(mx.Host, "."))
				if err != nil {
					return StatusPermerror, d.MechanismString(), "", rauthentic, err
				}
				hmatch, status, err := checkHostIP(mxd, d, &args)
				if err != nil {
					return status, d.MechanismString(), "", rauthentic, err
				}
				if hmatch {
					match = hmatch
					break
				}
			}

		case "ptr":
			// ../rfc/7208:1281
			host, err := evaluateDomainSpec(d.DomainSpec, args.domain)
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, err
			}

			rnames, result, err := resolver.LookupAddr(ctx, args.RemoteIP.String())
			rauthentic = rauthentic && result.Authentic
			trackVoidLookup(err, &args)
			if err != nil && !dns.IsNotFound(err) {
				return StatusTemperror, d.MechanismString(), "", rauthentic, err
			}
			lookups := 0
		ptrnames:
			for _, rname := range rnames {
				rd, err := dns.ParseDomain(strings.TrimSuffix(rname, "."))
				if err != nil {
					log.Errorx("bad address in ptr record", err, slog.String("address", rname))
					continue
				}
				// ../rfc/7208-eid4751 ../rfc/7208:1323
				if rd.ASCII != host.ASCII && !strings.HasSuffix(rd.ASCII, "."+host.ASCII) {
					continue
				}

				// ../rfc/7208:963, we must ignore entries after the first 10.
				if lookups >= 10 {
					break
				}
				lookups++
				ips, result, err := resolver.LookupIP(ctx, "ip", rd.ASCII+".")
				rauthentic = rauthentic && result.Authentic
				trackVoidLookup(err, &args)
				for _, ip := range ips {
					if checkIP(ip, d) {
						match = true
						break ptrnames
					}
				}
			}

		// ../rfc/7208:1351
		case "ip4":
			if remote4 != nil {
				match = checkIP(d.IP, d)
			}
		case "ip6":
			if remote6 != nil {
				match = checkIP(d.IP, d)
			}

		case "exists":
			// ../rfc/7208:1382
			name, authentic, err := expandDomainSpecDNS(ctx, resolver, d.DomainSpec, args)
			rauthentic = rauthentic && authentic
			if err != nil {
				return StatusPermerror, d.MechanismString(), "", rauthentic, fmt.Errorf("expanding domain-spec for exists: %w", err)
			}

			ips, result, err := resolver.LookupIP(ctx, "ip4", ensureAbsDNS(name))
			rauthentic = rauthentic && result.Authentic
			// Note: we do count this for void lookups, as that is an anti-abuse mechanism.
			// ../rfc/7208:1382 does not say anything special, so ../rfc/7208:984 applies.
			trackVoidLookup(err, &args)
			if err != nil && !dns.IsNotFound(err) {
				return StatusTemperror, d.MechanismString(), "", rauthentic, err
			}
			match = len(ips) > 0

		default:
			return StatusNone, d.MechanismString(), "", rauthentic, fmt.Errorf("internal error, unexpected mechanism %q", d.Mechanism)
		}

		if !match {
			continue
		}
		switch d.Qualifier {
		case "", "+":
			return StatusPass, d.MechanismString(), "", rauthentic, nil
		case "?":
			return StatusNeutral, d.MechanismString(), "", rauthentic, nil
		case "-":
			nargs := args
			// ../rfc/7208:1489
			authentic, expl := explanation(ctx, resolver, record, nargs)
			rauthentic = rauthentic && authentic
			return StatusFail, d.MechanismString(), expl, rauthentic, nil
		case "~":
			return StatusSoftfail, d.MechanismString(), "", rauthentic, nil
		}
		return StatusNone, d.MechanismString(), "", rauthentic, fmt.Errorf("internal error, unexpected qualifier %q", d.Qualifier)
	}

	if record.Redirect != "" {
		// We only know "redirect" for evaluating purposes, ignoring any others. ../rfc/7208:1423

		// ../rfc/7208:1440
		name, authentic, err := expandDomainSpecDNS(ctx, resolver, record.Redirect, args)
		rauthentic = rauthentic && authentic
		if err != nil {
			return StatusPermerror, "", "", rauthentic, fmt.Errorf("expanding domain-spec: %w", err)
		}
		nargs := args
		nargs.domain = dns.Domain{ASCII: strings.TrimSuffix(name, ".")}
		nargs.explanation = nil // ../rfc/7208:1548
		status, mechanism, expl, authentic, err := checkHost(ctx, log, resolver, nargs)
		rauthentic = rauthentic && authentic
		if status == StatusNone {
			return StatusPermerror, mechanism, "", rauthentic, err
		}
		return status, mechanism, expl, rauthentic, err
	}

	// ../rfc/7208:996 ../rfc/7208:2095
	return StatusNeutral, "default", "", rauthentic, nil
}

// evaluateDomainSpec returns the parsed dns domain for spec if non-empty, and
// otherwise returns d, which must be the Domain in checkHost Args.
func evaluateDomainSpec(spec string, d dns.Domain) (dns.Domain, error) {
	// ../rfc/7208:1037
	if spec == "" {
		return d, nil
	}
	d, err := dns.ParseDomain(spec)
	if err != nil {
		return d, fmt.Errorf("%w: %s", ErrName, err)
	}
	return d, nil
}

func expandDomainSpecDNS(ctx context.Context, resolver dns.Resolver, domainSpec string, args Args) (string, bool, error) {
	return expandDomainSpec(ctx, resolver, domainSpec, args, true)
}

func expandDomainSpecExp(ctx context.Context, resolver dns.Resolver, domainSpec string, args Args) (string, bool, error) {
	return expandDomainSpec(ctx, resolver, domainSpec, args, false)
}

// expandDomainSpec interprets macros in domainSpec.
// The expansion can fail due to macro syntax errors or DNS errors.
// Caller should typically treat failures as StatusPermerror. ../rfc/7208:1641
// ../rfc/7208:1639
// ../rfc/7208:1047
func expandDomainSpec(ctx context.Context, resolver dns.Resolver, domainSpec string, args Args, dns bool) (string, bool, error) {
	exp := !dns

	rauthentic := true // Until non-authentic record is found.

	s := domainSpec

	b := &strings.Builder{}
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		i++
		if c != '%' {
			b.WriteByte(c)
			continue
		}

		if i >= n {
			return "", rauthentic, fmt.Errorf("%w: trailing bare %%", ErrMacroSyntax)
		}
		c = s[i]
		i++
		if c == '%' {
			b.WriteByte(c)
			continue
		} else if c == '_' {
			b.WriteByte(' ')
			continue
		} else if c == '-' {
			b.WriteString("%20")
			continue
		} else if c != '{' {
			return "", rauthentic, fmt.Errorf("%w: invalid macro opening %%%c", ErrMacroSyntax, c)
		}

		if i >= n {
			return "", rauthentic, fmt.Errorf("%w: missing macro ending }", ErrMacroSyntax)
		}
		c = s[i]
		i++

		upper := false
		if c >= 'A' && c <= 'Z' {
			upper = true
			c += 'a' - 'A'
		}

		var v string
		switch c {
		case 's':
			// todo: should we check for utf8 in localpart, and fail? we may now generate utf8 strings to places that may not be able to parse them. it will probably lead to relatively harmless error somewhere else. perhaps we can just transform the localpart to IDN? because it may be used in a dns lookup. ../rfc/7208:1507
			v = smtp.NewAddress(args.senderLocalpart, args.senderDomain).String()
		case 'l':
			// todo: same about utf8 as for 's'.
			v = string(args.senderLocalpart)
		case 'o':
			v = args.senderDomain.ASCII
		case 'd':
			v = args.domain.ASCII
		case 'i':
			v = expandIP(args.RemoteIP)
		case 'p':
			// ../rfc/7208:937
			if err := trackLookupLimits(&args); err != nil {
				return "", rauthentic, err
			}
			names, result, err := resolver.LookupAddr(ctx, args.RemoteIP.String())
			rauthentic = rauthentic && result.Authentic
			trackVoidLookup(err, &args)
			if len(names) == 0 || err != nil {
				// ../rfc/7208:1709
				v = "unknown"
				break
			}

			// Verify finds the first dns name that resolves to the remote ip.
			verify := func(matchfn func(string) bool) (string, error) {
				for _, name := range names {
					if !matchfn(name) {
						continue
					}
					ips, result, err := resolver.LookupIP(ctx, "ip", name)
					rauthentic = rauthentic && result.Authentic
					trackVoidLookup(err, &args)
					// ../rfc/7208:1714, we don't have to check other errors.
					for _, ip := range ips {
						if ip.Equal(args.RemoteIP) {
							return name, nil
						}
					}
				}
				return "", nil
			}

			// First exact domain name matches, then subdomains, finally other names.
			domain := args.domain.ASCII + "."
			dotdomain := "." + domain
			v, err = verify(func(name string) bool { return name == domain })
			if err != nil {
				return "", rauthentic, err
			}
			if v == "" {
				v, err = verify(func(name string) bool { return strings.HasSuffix(name, dotdomain) })
				if err != nil {
					return "", rauthentic, err
				}
			}
			if v == "" {
				v, err = verify(func(name string) bool { return name != domain && !strings.HasSuffix(name, dotdomain) })
				if err != nil {
					return "", rauthentic, err
				}
			}
			if v == "" {
				// ../rfc/7208:1709
				v = "unknown"
			}

		case 'v':
			if args.RemoteIP.To4() != nil {
				v = "in-addr"
			} else {
				v = "ip6"
			}
		case 'h':
			if args.HelloDomain.IsIP() {
				// ../rfc/7208:1621 explicitly says "domain", not "ip". We'll handle IP, probably does no harm.
				v = expandIP(args.HelloDomain.IP)
			} else {
				v = args.HelloDomain.Domain.ASCII
			}
		case 'c', 'r', 't':
			if !exp {
				return "", rauthentic, fmt.Errorf("%w: macro letter %c only allowed in exp", ErrMacroSyntax, c)
			}
			switch c {
			case 'c':
				v = args.LocalIP.String()
			case 'r':
				v = args.LocalHostname.ASCII
			case 't':
				v = fmt.Sprintf("%d", timeNow().Unix())
			}
		default:
			return "", rauthentic, fmt.Errorf("%w: unknown macro letter %c", ErrMacroSyntax, c)
		}

		digits := ""
		for i < n && s[i] >= '0' && s[i] <= '9' {
			digits += string(s[i])
			i++
		}
		nlabels := -1
		if digits != "" {
			v, err := strconv.Atoi(digits)
			if err != nil {
				return "", rauthentic, fmt.Errorf("%w: bad macro transformer digits %q: %s", ErrMacroSyntax, digits, err)
			}
			nlabels = v
			if nlabels == 0 {
				return "", rauthentic, fmt.Errorf("%w: zero labels for digits transformer", ErrMacroSyntax)
			}
		}

		// If "r" follows, we must reverse the resulting name, splitting on a dot by default.
		// ../rfc/7208:1655
		reverse := false
		if i < n && (s[i] == 'r' || s[i] == 'R') {
			reverse = true
			i++
		}

		// Delimiters to split on, for subset of labels and/or reversing.
		delim := ""
		for i < n {
			switch s[i] {
			case '.', '-', '+', ',', '/', '_', '=':
				delim += string(s[i])
				i++
				continue
			}
			break
		}

		if i >= n || s[i] != '}' {
			return "", rauthentic, fmt.Errorf("%w: missing closing } for macro", ErrMacroSyntax)
		}
		i++

		// Only split and subset and/or reverse if necessary.
		if nlabels >= 0 || reverse || delim != "" {
			if delim == "" {
				delim = "."
			}
			t := split(v, delim)
			// ../rfc/7208:1655
			if reverse {
				nt := len(t)
				h := nt / 2
				for i := 0; i < h; i++ {
					t[i], t[nt-1-i] = t[nt-1-i], t[i]
				}
			}
			if nlabels > 0 && nlabels < len(t) {
				t = t[len(t)-nlabels:]
			}
			// Always join on dot. ../rfc/7208:1659
			v = strings.Join(t, ".")
		}

		// ../rfc/7208:1755
		if upper {
			v = url.QueryEscape(v)
		}

		b.WriteString(v)
	}
	r := b.String()
	if dns {
		isAbs := strings.HasSuffix(r, ".")
		r = ensureAbsDNS(r)
		if err := validateDNS(r); err != nil {
			return "", rauthentic, fmt.Errorf("invalid dns name: %s", err)
		}
		// If resulting name is too large, cut off labels on the left until it fits. ../rfc/7208:1749
		if len(r) > 253+1 {
			labels := strings.Split(r, ".")
			for i := range labels {
				if i == len(labels)-1 {
					return "", rauthentic, fmt.Errorf("expanded dns name too long")
				}
				s := strings.Join(labels[i+1:], ".")
				if len(s) <= 254 {
					r = s
					break
				}
			}
		}
		if !isAbs {
			r = r[:len(r)-1]
		}
	}
	return r, rauthentic, nil
}

func expandIP(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4.String()
	}
	v := ""
	for i, b := range ip.To16() {
		if i > 0 {
			v += "."
		}
		v += fmt.Sprintf("%x.%x", b>>4, b&0xf)
	}
	return v
}

// validateDNS checks if a DNS name is valid. Must not end in dot. This does not
// check valid host names, e.g. _ is allowed in DNS but not in a host name.
func validateDNS(s string) error {
	// ../rfc/7208:800
	// note: we are not checking for max 253 bytes length, because one of the callers may be chopping off labels to "correct" the name.
	labels := strings.Split(s, ".")
	if len(labels) > 128 {
		return fmt.Errorf("more than 128 labels")
	}
	for _, label := range labels[:len(labels)-1] {
		if len(label) > 63 {
			return fmt.Errorf("label longer than 63 bytes")
		}

		if label == "" {
			return fmt.Errorf("empty dns label")
		}
	}
	return nil
}

func split(v, delim string) (r []string) {
	isdelim := func(c rune) bool {
		for _, d := range delim {
			if d == c {
				return true
			}
		}
		return false
	}

	s := 0
	for i, c := range v {
		if isdelim(c) {
			r = append(r, v[s:i])
			s = i + 1
		}
	}
	r = append(r, v[s:])
	return r
}

// explanation does a best-effort attempt to fetch an explanation for a StatusFail response.
// If no explanation could be composed, an empty string is returned.
func explanation(ctx context.Context, resolver dns.Resolver, r *Record, args Args) (bool, string) {
	// ../rfc/7208:1485

	// If this record is the result of an "include", we have to use the explanation
	// string of the original domain, not of this domain.
	// ../rfc/7208:1548
	expl := r.Explanation
	if args.explanation != nil {
		expl = *args.explanation
	}

	// ../rfc/7208:1491
	if expl == "" {
		return true, ""
	}

	// Limits for dns requests and void lookups should not be taken into account.
	// Starting with zero ensures they aren't triggered.
	args.dnsRequests = new(int)
	args.voidLookups = new(int)
	name, authentic, err := expandDomainSpecDNS(ctx, resolver, r.Explanation, args)
	if err != nil || name == "" {
		return authentic, ""
	}
	txts, result, err := resolver.LookupTXT(ctx, ensureAbsDNS(name))
	authentic = authentic && result.Authentic
	if err != nil || len(txts) == 0 {
		return authentic, ""
	}
	txt := strings.Join(txts, "")
	s, exauthentic, err := expandDomainSpecExp(ctx, resolver, txt, args)
	authentic = authentic && exauthentic
	if err != nil {
		return authentic, ""
	}
	return authentic, s
}

func ensureAbsDNS(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func trackLookupLimits(args *Args) error {
	// ../rfc/7208:937
	if *args.dnsRequests >= dnsRequestsMax {
		return ErrTooManyDNSRequests
	}
	// ../rfc/7208:988
	if *args.voidLookups >= voidLookupsMax {
		return ErrTooManyVoidLookups
	}
	*args.dnsRequests++
	return nil
}

func trackVoidLookup(err error, args *Args) {
	if dns.IsNotFound(err) {
		*args.voidLookups++
	}
}
