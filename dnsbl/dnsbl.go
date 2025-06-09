// Package dnsbl implements DNS block lists (RFC 5782), for checking incoming messages from sources without reputation.
//
// A DNS block list contains IP addresses that should be blocked. The DNSBL is
// queried using DNS "A" lookups. The DNSBL starts at a "zone", e.g.
// "dnsbl.example". To look up whether an IP address is listed, a DNS name is
// composed: For 10.11.12.13, that name would be "13.12.11.10.dnsbl.example". If
// the lookup returns "record does not exist", the IP is not listed. If an IP
// address is returned, the IP is listed. If an IP is listed, an additional TXT
// lookup is done for more information about the block. IPv6 addresses are also
// looked up with an DNS "A" lookup of a name similar to an IPv4 address, but with
// 4-bit hexadecimal dot-separated characters, in reverse.
//
// The health of a DNSBL "zone" can be checked through a lookup of 127.0.0.1
// (must not be present) and 127.0.0.2 (must be present).
package dnsbl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/stub"
)

var (
	MetricLookup stub.HistogramVec = stub.HistogramVecIgnore{}
)

var ErrDNS = errors.New("dnsbl: dns error") // Temporary error.

// Status is the result of a DNSBL lookup.
type Status string

var (
	StatusTemperr Status = "temperror" // Temporary failure.
	StatusPass    Status = "pass"      // Not present in block list.
	StatusFail    Status = "fail"      // Present in block list.
)

// Lookup checks if "ip" occurs in the DNS block list "zone" (e.g. dnsbl.example.org).
func Lookup(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, zone dns.Domain, ip net.IP) (rstatus Status, rexplanation string, rerr error) {
	log := mlog.New("dnsbl", elog)
	start := time.Now()
	defer func() {
		MetricLookup.ObserveLabels(float64(time.Since(start))/float64(time.Second), zone.Name(), string(rstatus))
		log.Debugx("dnsbl lookup result", rerr,
			slog.Any("zone", zone),
			slog.Any("ip", ip),
			slog.Any("status", rstatus),
			slog.String("explanation", rexplanation),
			slog.Duration("duration", time.Since(start)))
	}()

	b := &strings.Builder{}
	v4 := ip.To4()
	if v4 != nil {
		// ../rfc/5782:148
		s := len(v4) - 1
		for i := s; i >= 0; i-- {
			if i < s {
				b.WriteByte('.')
			}
			b.WriteString(strconv.Itoa(int(v4[i])))
		}
	} else {
		// ../rfc/5782:270
		s := len(ip) - 1
		const chars = "0123456789abcdef"
		for i := s; i >= 0; i-- {
			if i < s {
				b.WriteByte('.')
			}
			v := ip[i]
			b.WriteByte(chars[v>>0&0xf])
			b.WriteByte('.')
			b.WriteByte(chars[v>>4&0xf])
		}
	}
	b.WriteString("." + zone.ASCII + ".")
	addr := b.String()

	// ../rfc/5782:175
	_, _, err := dns.WithPackage(resolver, "dnsbl").LookupIP(ctx, "ip4", addr)
	if dns.IsNotFound(err) {
		return StatusPass, "", nil
	} else if err != nil {
		return StatusTemperr, "", fmt.Errorf("%w: %s", ErrDNS, err)
	}

	txts, _, err := dns.WithPackage(resolver, "dnsbl").LookupTXT(ctx, addr)
	if dns.IsNotFound(err) {
		return StatusFail, "", nil
	} else if err != nil {
		log.Debugx("looking up txt record from dnsbl", err, slog.String("addr", addr))
		return StatusFail, "", nil
	}
	return StatusFail, strings.Join(txts, "; "), nil
}

// CheckHealth checks whether the DNSBL "zone" is operating correctly by
// querying for 127.0.0.2 (must be present) and 127.0.0.1 (must not be present).
// Users of a DNSBL should periodically check if the DNSBL is still operating
// properly.
// For temporary errors, ErrDNS is returned.
func CheckHealth(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, zone dns.Domain) (rerr error) {
	log := mlog.New("dnsbl", elog)
	start := time.Now()
	defer func() {
		log.Debugx("dnsbl healthcheck result", rerr, slog.Any("zone", zone), slog.Duration("duration", time.Since(start)))
	}()

	// ../rfc/5782:355
	status1, _, err1 := Lookup(ctx, log.Logger, resolver, zone, net.IPv4(127, 0, 0, 1))
	status2, _, err2 := Lookup(ctx, log.Logger, resolver, zone, net.IPv4(127, 0, 0, 2))
	if status1 == StatusPass && status2 == StatusFail {
		return nil
	} else if status1 == StatusFail {
		return fmt.Errorf("dnsbl contains unwanted test address 127.0.0.1")
	} else if status2 == StatusPass {
		return fmt.Errorf("dnsbl does not contain required test address 127.0.0.2")
	}
	if err1 != nil {
		return err1
	} else if err2 != nil {
		return err2
	}
	return ErrDNS
}
