package smtpclient

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

var (
	errCNAMELoop  = errors.New("cname loop")
	errCNAMELimit = errors.New("too many cname records")
	errDNS        = errors.New("dns lookup error")
	errNoMail     = errors.New("domain does not accept email as indicated with single dot for mx record")
)

// HostPref is a host for delivery, with preference for MX records.
type HostPref struct {
	Host dns.IPDomain
	Pref int // -1 when not an MX record.
}

// GatherDestinations looks up the hosts to deliver email to a domain ("next-hop").
// If it is an IP address, it is the only destination to try. Otherwise CNAMEs of
// the domain are followed. Then MX records for the expanded CNAME are looked up.
// If no MX record is present, the original domain is returned. If an MX record is
// present but indicates the domain does not accept email, ErrNoMail is returned.
// If valid MX records were found, the MX target hosts are returned.
//
// haveMX indicates if an MX record was found.
//
// origNextHopAuthentic indicates if the DNS record for the initial domain name was
// DNSSEC secure (CNAME, MX).
//
// expandedNextHopAuthentic indicates if the DNS records after following CNAMEs were
// DNSSEC secure.
//
// These authentic results are needed for DANE, to determine where to look up TLSA
// records, and which names to allow in the remote TLS certificate. If MX records
// were found, both the original and expanded next-hops must be authentic for DANE
// to be option. For a non-IP with no MX records found, the authentic result can
// be used to decide which of the names to use as TLSA base domain.
func GatherDestinations(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, origNextHop dns.IPDomain) (haveMX, origNextHopAuthentic, expandedNextHopAuthentic bool, expandedNextHop dns.Domain, hostPrefs []HostPref, permanent bool, err error) {
	// ../rfc/5321:3824

	log := mlog.New("smtpclient", elog)

	// IP addresses are dialed directly, and don't have TLSA records.
	if len(origNextHop.IP) > 0 {
		return false, false, false, expandedNextHop, []HostPref{{origNextHop, -1}}, false, nil
	}

	// We start out assuming the result is authentic. Updated with each lookup.
	origNextHopAuthentic = true
	expandedNextHopAuthentic = true

	// We start out delivering to the recipient domain. We follow CNAMEs.
	rcptDomain := origNextHop.Domain
	// Domain we are actually delivering to, after following CNAME record(s).
	expandedNextHop = rcptDomain
	// Keep track of CNAMEs we have followed, to detect loops.
	domainsSeen := map[string]bool{}
	for i := 0; ; i++ {
		if domainsSeen[expandedNextHop.ASCII] {
			// todo: only mark as permanent failure if TTLs for all records are beyond latest possibly delivery retry we would do.
			err := fmt.Errorf("%w: recipient domain %s: already saw %s", errCNAMELoop, rcptDomain, expandedNextHop)
			return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, false, err
		}
		domainsSeen[expandedNextHop.ASCII] = true

		// note: The Go resolver returns the requested name if the domain has no CNAME
		// record but has a host record.
		if i == 16 {
			// We have a maximum number of CNAME records we follow. There is no hard limit for
			// DNS, and you might think folks wouldn't configure CNAME chains at all, but for
			// (non-mail) domains, CNAME chains of 10 records have been encountered according
			// to the internet.
			// todo: only mark as permanent failure if TTLs for all records are beyond latest possibly delivery retry we would do.
			err := fmt.Errorf("%w: recipient domain %s, last resolved domain %s", errCNAMELimit, rcptDomain, expandedNextHop)
			return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, false, err
		}

		// Do explicit CNAME lookup. Go's LookupMX also resolves CNAMEs, but we want to
		// know the final name, and we're interested in learning if the first vs later
		// results were DNSSEC-(in)secure.
		// ../rfc/5321:3838 ../rfc/3974:197
		cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
		defer ccancel()
		cname, cnameResult, err := resolver.LookupCNAME(cctx, expandedNextHop.ASCII+".")
		ccancel()
		if i == 0 {
			origNextHopAuthentic = origNextHopAuthentic && cnameResult.Authentic
		}
		expandedNextHopAuthentic = expandedNextHopAuthentic && cnameResult.Authentic
		if err != nil && !dns.IsNotFound(err) {
			err = fmt.Errorf("%w: cname lookup for %s: %v", errDNS, expandedNextHop, err)
			return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, false, err
		}
		if err == nil && cname != expandedNextHop.ASCII+"." {
			d, err := dns.ParseDomain(strings.TrimSuffix(cname, "."))
			if err != nil {
				// todo: only mark as permanent failure if TTLs for all records are beyond latest possibly delivery retry we would do.
				err = fmt.Errorf("%w: parsing cname domain %s: %v", errDNS, expandedNextHop, err)
				return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, false, err
			}
			expandedNextHop = d
			// Start again with new domain.
			continue
		}

		// Not a CNAME, so lookup MX record.
		mctx, mcancel := context.WithTimeout(ctx, 30*time.Second)
		defer mcancel()
		// Note: LookupMX can return an error and still return records: Invalid records are
		// filtered out and an error returned. We must process any records that are valid.
		// Only if all are unusable will we return an error. ../rfc/5321:3851
		mxl, mxResult, err := resolver.LookupMX(mctx, expandedNextHop.ASCII+".")
		mcancel()
		if i == 0 {
			origNextHopAuthentic = origNextHopAuthentic && mxResult.Authentic
		}
		expandedNextHopAuthentic = expandedNextHopAuthentic && mxResult.Authentic
		if err != nil && len(mxl) == 0 {
			if !dns.IsNotFound(err) {
				err = fmt.Errorf("%w: mx lookup for %s: %v", errDNS, expandedNextHop, err)
				return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, false, err
			}

			// No MX record, attempt delivery directly to host. ../rfc/5321:3842
			hostPrefs = []HostPref{{dns.IPDomain{Domain: expandedNextHop}, -1}}
			return false, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, hostPrefs, false, nil
		} else if err != nil {
			log.Infox("mx record has some invalid records, keeping only the valid mx records", err)
		}

		// ../rfc/7505:122
		if err == nil && len(mxl) == 1 && mxl[0].Host == "." {
			// Note: Depending on MX record TTL, this record may be replaced with a more
			// receptive MX record before our final delivery attempt. But it's clearly the
			// explicit desire not to be bothered with email delivery attempts, so mark failure
			// as permanent.
			return true, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, true, errNoMail
		}

		// The Go resolver already sorts by preference, randomizing records of same
		// preference. ../rfc/5321:3885
		for _, mx := range mxl {
			// Parsing lax (unless pedantic mode) for MX targets with underscores as seen in the wild.
			host, err := dns.ParseDomainLax(strings.TrimSuffix(mx.Host, "."))
			if err != nil {
				// note: should not happen because Go resolver already filters these out.
				err = fmt.Errorf("%w: invalid host name in mx record %q: %v", errDNS, mx.Host, err)
				return true, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, nil, true, err
			}
			hostPrefs = append(hostPrefs, HostPref{dns.IPDomain{Domain: host}, int(mx.Pref)})
		}
		if len(hostPrefs) > 0 {
			err = nil
		}
		return true, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, hostPrefs, false, err
	}
}

// GatherIPs looks up the IPs to try for connecting to host, with the IPs ordered
// to take previous attempts into account. For use with DANE, the CNAME-expanded
// name is returned, and whether the DNS responses were authentic.
func GatherIPs(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, network string, host dns.IPDomain, dialedIPs map[string][]net.IP) (authentic bool, expandedAuthentic bool, expandedHost dns.Domain, ips []net.IP, dualstack bool, rerr error) {
	log := mlog.New("smtpclient", elog)

	if len(host.IP) > 0 {
		return false, false, dns.Domain{}, []net.IP{host.IP}, false, nil
	}

	authentic = true
	expandedAuthentic = true

	// The Go resolver automatically follows CNAMEs, which is not allowed for host
	// names in MX records, but seems to be accepted and is documented for DANE SMTP
	// behaviour. We resolve CNAMEs explicitly, so we can return the final name, which
	// DANE needs. ../rfc/7671:246
	// ../rfc/5321:3861 ../rfc/2181:661 ../rfc/7672:1382 ../rfc/7671:1030
	name := host.Domain.ASCII + "."

	for i := 0; ; i++ {
		cname, result, err := resolver.LookupCNAME(ctx, name)
		if i == 0 {
			authentic = result.Authentic
		}
		expandedAuthentic = expandedAuthentic && result.Authentic
		if dns.IsNotFound(err) {
			break
		} else if err != nil {
			return authentic, expandedAuthentic, dns.Domain{}, nil, dualstack, err
		} else if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(name, ".") {
			break
		}
		if i > 10 {
			return authentic, expandedAuthentic, dns.Domain{}, nil, dualstack, fmt.Errorf("mx lookup: %w", errCNAMELimit)
		}
		name = strings.TrimSuffix(cname, ".") + "."
	}

	if name == host.Domain.ASCII+"." {
		expandedHost = host.Domain
	} else {
		var err error
		expandedHost, err = dns.ParseDomain(strings.TrimSuffix(name, "."))
		if err != nil {
			return authentic, expandedAuthentic, dns.Domain{}, nil, dualstack, fmt.Errorf("parsing cname-resolved domain: %w", err)
		}
	}

	ipaddrs, result, err := resolver.LookupIP(ctx, network, name)
	authentic = authentic && result.Authentic
	expandedAuthentic = expandedAuthentic && result.Authentic
	if err != nil || len(ipaddrs) == 0 {
		return authentic, expandedAuthentic, expandedHost, nil, false, fmt.Errorf("looking up %q: %w", name, err)
	}
	var have4, have6 bool
	for _, ipaddr := range ipaddrs {
		ips = append(ips, ipaddr)
		if ipaddr.To4() == nil {
			have6 = true
		} else {
			have4 = true
		}
	}
	dualstack = have4 && have6
	prevIPs := dialedIPs[host.String()]
	if len(prevIPs) > 0 {
		prevIP := prevIPs[len(prevIPs)-1]
		prevIs4 := prevIP.To4() != nil
		sameFamily := 0
		for _, ip := range prevIPs {
			is4 := ip.To4() != nil
			if prevIs4 == is4 {
				sameFamily++
			}
		}
		preferPrev := sameFamily == 1
		// We use stable sort so any preferred/randomized listing from DNS is kept intact.
		sort.SliceStable(ips, func(i, j int) bool {
			aIs4 := ips[i].To4() != nil
			bIs4 := ips[j].To4() != nil
			if aIs4 != bIs4 {
				// Prefer "i" if it is not same address family.
				return aIs4 != prevIs4
			}
			// Prefer "i" if it is the same as last and we should be preferring it.
			return preferPrev && ips[i].Equal(prevIP)
		})
		log.Debug("ordered ips for dialing", slog.Any("ips", ips))
	}
	return
}

// GatherTLSA looks up TLSA record for either expandedHost or host, and returns
// records usable for DANE with SMTP, and host names to allow in DANE-TA
// certificate name verification.
//
// If no records are found, this isn't necessarily an error. It can just indicate
// the domain/host does not opt-in to DANE, and nil records and a nil error are
// returned.
//
// Only usable records are returned. If any record was found, DANE is required and
// this is indicated with daneRequired. If no usable records remain, the caller
// must do TLS, but not verify the remote TLS certificate.
//
// Returned values are always meaningful, also when an error was returned.
func GatherTLSA(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, host dns.Domain, expandedAuthentic bool, expandedHost dns.Domain) (daneRequired bool, daneRecords []adns.TLSA, tlsaBaseDomain dns.Domain, err error) {
	log := mlog.New("smtpclient", elog)

	// ../rfc/7672:912
	// This function is only called when the lookup of host was authentic.

	var l []adns.TLSA

	tlsaBaseDomain = host
	if host == expandedHost || !expandedAuthentic {
		l, err = lookupTLSACNAME(ctx, log, resolver, 25, "tcp", host)
	} else if expandedAuthentic {
		// ../rfc/7672:934
		tlsaBaseDomain = expandedHost
		l, err = lookupTLSACNAME(ctx, log, resolver, 25, "tcp", expandedHost)
		if err == nil && len(l) == 0 {
			tlsaBaseDomain = host
			l, err = lookupTLSACNAME(ctx, log, resolver, 25, "tcp", host)
		}
	}
	if len(l) == 0 || err != nil {
		daneRequired = err != nil
		log.Debugx("gathering tlsa records failed", err, slog.Bool("danerequired", daneRequired), slog.Any("basedomain", tlsaBaseDomain))
		return daneRequired, nil, tlsaBaseDomain, err
	}
	daneRequired = len(l) > 0
	l = filterUsableTLSARecords(log, l)
	log.Debug("tlsa records exist",
		slog.Bool("danerequired", daneRequired),
		slog.Any("records", l),
		slog.Any("basedomain", tlsaBaseDomain))
	return daneRequired, l, tlsaBaseDomain, err
}

// lookupTLSACNAME composes a TLSA domain name to lookup, follows CNAMEs and looks
// up TLSA records. no TLSA records exist, a nil error is returned as it means
// the host does not opt-in to DANE.
func lookupTLSACNAME(ctx context.Context, log mlog.Log, resolver dns.Resolver, port int, protocol string, host dns.Domain) (l []adns.TLSA, rerr error) {
	name := fmt.Sprintf("_%d._%s.%s", port, protocol, host.ASCII+".")
	for i := 0; ; i++ {
		cname, result, err := resolver.LookupCNAME(ctx, name)
		if dns.IsNotFound(err) {
			if !result.Authentic {
				log.Debugx("cname nxdomain result during tlsa lookup not authentic, not doing dane for host", err, slog.Any("host", host), slog.String("name", name))
				return nil, nil
			}
			break
		} else if err != nil {
			return nil, fmt.Errorf("looking up cname for tlsa candidate base domain: %w", err)
		} else if !result.Authentic {
			log.Debugx("cname result during tlsa lookup not authentic, not doing dane for host", err, slog.Any("host", host), slog.String("name", name))
			return nil, nil
		}
		if i == 10 {
			return nil, fmt.Errorf("looking up cname for tlsa candidate base domain: %w", errCNAMELimit)
		}
		name = strings.TrimSuffix(cname, ".") + "."
	}
	var result adns.Result
	var err error
	l, result, err = resolver.LookupTLSA(ctx, 0, "", name)
	if dns.IsNotFound(err) || err == nil && len(l) == 0 {
		log.Debugx("no tlsa records for host, not doing dane", err,
			slog.Any("host", host),
			slog.String("name", name),
			slog.Bool("authentic", result.Authentic))
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("looking up tlsa records for tlsa candidate base domain: %w", err)
	} else if !result.Authentic {
		log.Debugx("tlsa lookup not authentic, not doing dane for host", err, slog.Any("host", host), slog.String("name", name))
		return nil, nil
	}
	return l, nil
}

func filterUsableTLSARecords(log mlog.Log, l []adns.TLSA) []adns.TLSA {
	// Gather "usable" records. ../rfc/7672:708
	o := 0
	for _, r := range l {
		// A record is not usable when we don't recognize parameters. ../rfc/6698:649

		switch r.Usage {
		case adns.TLSAUsageDANETA, adns.TLSAUsageDANEEE:
		default:
			// We can regard PKIX-TA and PKIX-EE as "unusable" with SMTP DANE. ../rfc/7672:1304
			continue
		}
		switch r.Selector {
		case adns.TLSASelectorCert, adns.TLSASelectorSPKI:
		default:
			continue
		}
		switch r.MatchType {
		case adns.TLSAMatchTypeFull:
			if r.Selector == adns.TLSASelectorCert {
				if _, err := x509.ParseCertificate(r.CertAssoc); err != nil {
					log.Debugx("parsing certificate in dane tlsa record, ignoring", err)
					continue
				}
			} else if r.Selector == adns.TLSASelectorSPKI {
				if _, err := x509.ParsePKIXPublicKey(r.CertAssoc); err != nil {
					log.Debugx("parsing certificate in dane tlsa record, ignoring", err)
					continue
				}
			}
		case adns.TLSAMatchTypeSHA256:
			if len(r.CertAssoc) != sha256.Size {
				log.Debug("dane tlsa record with wrong data size for sha2-256", slog.Int("got", len(r.CertAssoc)), slog.Int("expect", sha256.Size))
				continue
			}
		case adns.TLSAMatchTypeSHA512:
			if len(r.CertAssoc) != sha512.Size {
				log.Debug("dane tlsa record with wrong data size for sha2-512", slog.Int("got", len(r.CertAssoc)), slog.Int("expect", sha512.Size))
				continue
			}
		default:
			continue
		}

		l[o] = r
		o++
	}
	return l[:o]
}

// GatherTLSANames returns the allowed names in TLS certificates for verification
// with PKIX-* or DANE-TA. The first name should be used for SNI.
//
// If there was no MX record, the next-hop domain parameters (i.e. the original
// email destination host, and its CNAME-expanded host, that has MX records) are
// ignored and only the base domain parameters are taken into account.
func GatherTLSANames(haveMX, expandedNextHopAuthentic, expandedTLSABaseDomainAuthentic bool, origNextHop, expandedNextHop, origTLSABaseDomain, expandedTLSABaseDomain dns.Domain) []dns.Domain {
	// Gather the names to check against TLS certificate. ../rfc/7672:1318
	if !haveMX {
		// ../rfc/7672:1336
		if !expandedTLSABaseDomainAuthentic || origTLSABaseDomain == expandedTLSABaseDomain {
			return []dns.Domain{origTLSABaseDomain}
		}
		return []dns.Domain{expandedTLSABaseDomain, origTLSABaseDomain}
	} else if expandedNextHopAuthentic {
		// ../rfc/7672:1326
		var l []dns.Domain
		if expandedTLSABaseDomainAuthentic {
			l = []dns.Domain{expandedTLSABaseDomain}
		}
		if expandedTLSABaseDomain != origTLSABaseDomain {
			l = append(l, origTLSABaseDomain)
		}
		l = append(l, origNextHop)
		if origNextHop != expandedNextHop {
			l = append(l, expandedNextHop)
		}
		return l
	} else {
		// We don't attempt DANE after insecure MX, but behaviour for it is specified.
		// ../rfc/7672:1332
		return []dns.Domain{origNextHop}
	}
}
