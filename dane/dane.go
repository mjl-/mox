// Package dane verifies TLS certificates through DNSSEC-verified TLSA records.
//
// On the internet, TLS certificates are commonly verified by checking if they are
// signed by one of many commonly trusted Certificate Authorities (CAs). This is
// PKIX or WebPKI. With DANE, TLS certificates are verified through
// DNSSEC-protected DNS records of type TLSA. These TLSA records specify the rules
// for verification ("usage") and whether a full certificate ("selector" cert) is
// checked or only its "subject public key info" ("selector" spki). The (hash of)
// the certificate or "spki" is included in the TLSA record ("matchtype").
//
// DANE SMTP connections have two allowed "usages" (verification rules):
//   - DANE-EE, which only checks if the certificate or spki match, without the
//     WebPKI verification of expiration, name or signed-by-trusted-party verification.
//   - DANE-TA, which does verification similar to PKIX/WebPKI, but verifies against
//     a certificate authority ("trust anchor", or "TA") specified in the TLSA record
//     instead of the CA pool.
//
// DANE has two more "usages", that may be used with protocols other than SMTP:
//   - PKIX-EE, which matches the certificate or spki, and also verifies the
//     certificate against the CA pool.
//   - PKIX-TA, which verifies the certificate or spki against a "trust anchor"
//     specified in the TLSA record, that also has to be trusted by the CA pool.
//
// TLSA records are looked up for a specific port number, protocol (tcp/udp) and
// host name. Each port can have different TLSA records. TLSA records must be
// signed and verified with DNSSEC before they can be trusted and used.
//
// TLSA records are looked up under "TLSA candidate base domains". The domain
// where the TLSA records are found is the "TLSA base domain". If the host to
// connect to is a CNAME that can be followed with DNSSEC protection, it is the
// first TLSA candidate base domain. If no protected records are found, the
// original host name is the second TLSA candidate base domain.
//
// For TLS connections, the TLSA base domain is used with SNI during the
// handshake.
//
// For TLS certificate verification that requires PKIX/WebPKI/trusted-anchor
// verification (all except DANE-EE), the potential second TLSA candidate base
// domain name is also valid. With SMTP, additionally for hosts found in MX records
// for a "next-hop domain", the "original next-hop domain" (domain of an email
// address to deliver to) is also a valid name, as is the "CNAME-expanded original
// next-hop domain", bringing the potential total allowed names to four (if CNAMEs
// are followed for the MX hosts).
package dane

// todo: why is https://datatracker.ietf.org/doc/html/draft-barnes-dane-uks-00 not in use? sounds reasonable.
// todo: add a DialSRV function that accepts a domain name, looks up srv records, dials the service, verifies dane certificate and returns the connection. for ../rfc/7673

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

var (
	metricVerify = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_dane_verify_total",
			Help: "Total number of DANE verification attempts, including mox_dane_verify_errors_total.",
		},
	)
	metricVerifyErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_dane_verify_errors_total",
			Help: "Total number of DANE verification failures, causing connections to fail.",
		},
	)
)

var (
	// ErrNoRecords means no TLSA records were found and host has not opted into DANE.
	ErrNoRecords = errors.New("dane: no tlsa records")

	// ErrInsecure indicates insecure DNS responses were encountered while looking up
	// the host, CNAME records, or TLSA records.
	ErrInsecure = errors.New("dane: dns lookups insecure")

	// ErrNoMatch means some TLSA records were found, but none can be verified against
	// the remote TLS certificate.
	ErrNoMatch = errors.New("dane: no match between certificate and tlsa records")
)

// VerifyError is an error encountered while verifying a DANE TLSA record. For
// example, an error encountered with x509 certificate trusted-anchor verification.
// A TLSA record that does not match a TLS certificate is not a VerifyError.
type VerifyError struct {
	Err    error     // Underlying error, possibly from crypto/x509.
	Record adns.TLSA // Cause of error.
}

// Error returns a string explaining this is a dane verify error along with the
// underlying error.
func (e VerifyError) Error() string {
	return fmt.Sprintf("dane verify error: %s", e.Err)
}

// Unwrap returns the underlying error.
func (e VerifyError) Unwrap() error {
	return e.Err
}

// Dial looks up a DNSSEC-protected DANE TLSA record for the domain name and
// port/service in address, checks for allowed usages, makes a network connection
// and verifies the remote certificate against the TLSA records. If
// verification succeeds, the verified record is returned.
//
// Different protocols require different usages. For example, SMTP with STARTTLS
// for delivery only allows usages DANE-TA and DANE-EE. If allowedUsages is
// non-nil, only the specified usages are taken into account when verifying, and
// any others ignored.
//
// Errors that can be returned, possibly in wrapped form:
//   - ErrNoRecords, also in case the DNS response indicates "not found".
//   - adns.DNSError, potentially wrapping adns.ExtendedError of which some can
//     indicate DNSSEC errors.
//   - ErrInsecure
//   - VerifyError, potentially wrapping errors from crypto/x509.
func Dial(ctx context.Context, resolver dns.Resolver, network, address string, allowedUsages []adns.TLSAUsage) (net.Conn, adns.TLSA, error) {
	log := mlog.New("dane").WithContext(ctx)

	// Split host and port.
	host, portstr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, adns.TLSA{}, fmt.Errorf("parsing address: %w", err)
	}
	port, err := resolver.LookupPort(ctx, network, portstr)
	if err != nil {
		return nil, adns.TLSA{}, fmt.Errorf("parsing port: %w", err)
	}

	hostDom, err := dns.ParseDomain(strings.TrimSuffix(host, "."))
	if err != nil {
		return nil, adns.TLSA{}, fmt.Errorf("parsing host: %w", err)
	}

	// ../rfc/7671:1015
	// First follow CNAMEs for host. If the path to the final name is secure, we must
	// lookup TLSA there first, then fallback to the original name. If the final name
	// is secure that's also the SNI server name we must use, with the original name as
	// allowed host during certificate name checks (for all TLSA usages other than
	// DANE-EE).
	cnameDom := hostDom
	cnameAuthentic := true
	for i := 0; ; i += 1 {
		if i == 10 {
			return nil, adns.TLSA{}, fmt.Errorf("too many cname lookups")
		}
		cname, cnameResult, err := resolver.LookupCNAME(ctx, cnameDom.ASCII+".")
		cnameAuthentic = cnameAuthentic && cnameResult.Authentic
		if !cnameResult.Authentic && i == 0 {
			return nil, adns.TLSA{}, fmt.Errorf("%w: cname lookup insecure", ErrInsecure)
		} else if dns.IsNotFound(err) {
			break
		} else if err != nil {
			return nil, adns.TLSA{}, fmt.Errorf("resolving cname %s: %w", cnameDom, err)
		} else if d, err := dns.ParseDomain(strings.TrimSuffix(cname, ".")); err != nil {
			return nil, adns.TLSA{}, fmt.Errorf("parsing cname: %w", err)
		} else {
			cnameDom = d
		}
	}

	// We lookup the IP.
	ipnetwork := "ip"
	if strings.HasSuffix(network, "4") {
		ipnetwork += "4"
	} else if strings.HasSuffix(network, "6") {
		ipnetwork += "6"
	}
	ips, _, err := resolver.LookupIP(ctx, ipnetwork, cnameDom.ASCII+".")
	// note: For SMTP with opportunistic DANE we would stop here with an insecure
	// response. But as long as long as we have a verified original tlsa base name, we
	// can continue with regular DANE.
	if err != nil {
		return nil, adns.TLSA{}, fmt.Errorf("resolving ips: %w", err)
	} else if len(ips) == 0 {
		return nil, adns.TLSA{}, &adns.DNSError{Err: "no ips for host", Name: cnameDom.ASCII, IsNotFound: true}
	}

	// Lookup TLSA records. If resolving CNAME was secure, we try that first. Otherwise
	// we try at the secure original domain.
	baseDom := hostDom
	if cnameAuthentic {
		baseDom = cnameDom
	}
	var records []adns.TLSA
	var result adns.Result
	for {
		var err error
		records, result, err = resolver.LookupTLSA(ctx, port, network, baseDom.ASCII+".")
		// If no (secure) records can be found at the final cname, and there is an original
		// name, try at original name.
		// ../rfc/7671:1015
		if baseDom != hostDom && (dns.IsNotFound(err) || !result.Authentic) {
			baseDom = hostDom
			continue
		}
		if !result.Authentic {
			return nil, adns.TLSA{}, ErrInsecure
		} else if dns.IsNotFound(err) {
			return nil, adns.TLSA{}, ErrNoRecords
		} else if err != nil {
			return nil, adns.TLSA{}, fmt.Errorf("lookup dane tlsa records: %w", err)
		}
		break
	}

	// Keep only the allowed usages.
	if allowedUsages != nil {
		o := 0
		for _, r := range records {
			for _, usage := range allowedUsages {
				if r.Usage == usage {
					records[o] = r
					o++
					break
				}
			}
		}
		records = records[:o]
		if len(records) == 0 {
			// No point in dialing when we know we won't be able to verify the remote TLS
			// certificate.
			return nil, adns.TLSA{}, fmt.Errorf("no usable tlsa records remaining: %w", ErrNoMatch)
		}
	}

	// We use the base domain for SNI, allowing the original domain as well.
	// ../rfc/7671:1021
	var moreAllowedHosts []dns.Domain
	if baseDom != hostDom {
		moreAllowedHosts = []dns.Domain{hostDom}
	}

	// Dial the remote host.
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok && len(ips) > 0 {
		timeout = time.Until(deadline) / time.Duration(len(ips))
	}
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var dialErrs []error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), portstr)
		c, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			dialErrs = append(dialErrs, err)
			continue
		}
		conn = c
		break
	}
	if conn == nil {
		return nil, adns.TLSA{}, errors.Join(dialErrs...)
	}

	var verifiedRecord adns.TLSA
	config := TLSClientConfig(log, records, baseDom, moreAllowedHosts, &verifiedRecord)
	tlsConn := tls.Client(conn, &config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, adns.TLSA{}, err
	}
	return tlsConn, verifiedRecord, nil
}

// TLSClientConfig returns a tls.Config to be used for dialing/handshaking a
// TLS connection with DANE verification.
//
// Callers should only pass records that are allowed for the use of DANE. DANE
// with SMTP only allows DANE-EE and DANE-TA usages, not the PKIX-usages.
//
// The config has InsecureSkipVerify set to true, with a custom VerifyConnection
// function for verifying DANE. Its VerifyConnection can return ErrNoMatch and
// additionally one or more (wrapped) errors of type VerifyError.
//
// The TLS config uses allowedHost for SNI.
//
// If verifiedRecord is not nil, it is set to the record that was successfully
// verified, if any.
func TLSClientConfig(log *mlog.Log, records []adns.TLSA, allowedHost dns.Domain, moreAllowedHosts []dns.Domain, verifiedRecord *adns.TLSA) tls.Config {
	return tls.Config{
		ServerName:         allowedHost.ASCII, // For SNI.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			verified, record, err := Verify(log, records, cs, allowedHost, moreAllowedHosts)
			log.Debugx("dane verification", err, mlog.Field("verified", verified), mlog.Field("record", record))
			if verified {
				if verifiedRecord != nil {
					*verifiedRecord = record
				}
				return nil
			} else if err == nil {
				return ErrNoMatch
			}
			return fmt.Errorf("%w, and error(s) encountered during verification: %w", ErrNoMatch, err)
		},
		MinVersion: tls.VersionTLS12, // ../rfc/8996:31 ../rfc/8997:66
	}
}

// Verify checks if the TLS connection state can be verified against DANE TLSA
// records.
//
// allowedHost along with the optional moreAllowedHosts are the host names that are
// allowed during certificate verification (as used by PKIX-TA, PKIX-EE, DANE-TA,
// but not DANE-EE). A typical connection would allow just one name, but some uses
// of DANE allow multiple, like SMTP which allow up to four valid names for a TLS
// certificate based on MX/CNAME/TLSA/DNSSEC lookup results.
//
// When one of the records matches, Verify returns true, along with the matching
// record and a nil error.
// If there is no match, then in the typical case false, a zero record value and a
// nil error is returned.
// If an error is encountered while verifying a record, e.g. for x509
// trusted-anchor verification, an error may be returned, typically one or more
// (wrapped) errors of type VerifyError.
func Verify(log *mlog.Log, records []adns.TLSA, cs tls.ConnectionState, allowedHost dns.Domain, moreAllowedHosts []dns.Domain) (verified bool, matching adns.TLSA, rerr error) {
	metricVerify.Inc()
	if len(records) == 0 {
		metricVerifyErrors.Inc()
		return false, adns.TLSA{}, fmt.Errorf("verify requires at least one tlsa record")
	}
	var errs []error
	for _, r := range records {
		ok, err := verifySingle(log, r, cs, allowedHost, moreAllowedHosts)
		if err != nil {
			errs = append(errs, VerifyError{err, r})
		} else if ok {
			return true, r, nil
		}
	}
	metricVerifyErrors.Inc()
	return false, adns.TLSA{}, errors.Join(errs...)
}

// verifySingle verifies the TLS connection against a single DANE TLSA record.
//
// If the remote TLS certificate matches with the TLSA record, true is
// returned. Errors may be encountered while verifying, e.g. when checking one
// of the allowed hosts against a TLSA record. A typical non-matching/verified
// TLSA record returns a nil error. But in some cases, e.g. when encountering
// errors while verifying certificates against a trust-anchor, an error can be
// returned with one or more underlying x509 verification errors. A nil-nil error
// is only returned when verified is false.
func verifySingle(log *mlog.Log, tlsa adns.TLSA, cs tls.ConnectionState, allowedHost dns.Domain, moreAllowedHosts []dns.Domain) (verified bool, rerr error) {
	if len(cs.PeerCertificates) == 0 {
		return false, fmt.Errorf("no server certificate")
	}

	match := func(cert *x509.Certificate) bool {
		var buf []byte
		switch tlsa.Selector {
		case adns.TLSASelectorCert:
			buf = cert.Raw
		case adns.TLSASelectorSPKI:
			buf = cert.RawSubjectPublicKeyInfo
		default:
			return false
		}

		switch tlsa.MatchType {
		case adns.TLSAMatchTypeFull:
		case adns.TLSAMatchTypeSHA256:
			d := sha256.Sum256(buf)
			buf = d[:]
		case adns.TLSAMatchTypeSHA512:
			d := sha512.Sum512(buf)
			buf = d[:]
		default:
			return false
		}

		return bytes.Equal(buf, tlsa.CertAssoc)
	}

	pkixVerify := func(host dns.Domain) ([][]*x509.Certificate, error) {
		// Default Verify checks for expiration. We pass the host name to check. And we
		// configure the intermediates. The roots are filled in by the x509 package.
		opts := x509.VerifyOptions{
			DNSName:       host.ASCII,
			Intermediates: x509.NewCertPool(),
			Roots:         mox.Conf.Static.TLS.CertPool,
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, err := cs.PeerCertificates[0].Verify(opts)
		return chains, err
	}

	switch tlsa.Usage {
	case adns.TLSAUsagePKIXTA:
		// We cannot get at the system trusted ca certificates to look for the trusted
		// anchor. So we just ask Go to verify, then see if any of the chains include the
		// ca certificate.
		var errs []error
		for _, host := range append([]dns.Domain{allowedHost}, moreAllowedHosts...) {
			chains, err := pkixVerify(host)
			log.Debugx("pkix-ta verify", err)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			// The chains by x509's Verify should include the longest possible match, so it is
			// sure to include the trusted anchor. ../rfc/7671:835
			for _, chain := range chains {
				// If pkix verified, check if any of the certificates match.
				for i := len(chain) - 1; i >= 0; i-- {
					if match(chain[i]) {
						return true, nil
					}
				}
			}
		}
		return false, errors.Join(errs...)

	case adns.TLSAUsagePKIXEE:
		// Check for a certificate match.
		if !match(cs.PeerCertificates[0]) {
			return false, nil
		}
		// And do regular pkix checks, ../rfc/7671:799
		var errs []error
		for _, host := range append([]dns.Domain{allowedHost}, moreAllowedHosts...) {
			_, err := pkixVerify(host)
			log.Debugx("pkix-ee verify", err)
			if err == nil {
				return true, nil
			}
			errs = append(errs, err)
		}
		return false, errors.Join(errs...)

	case adns.TLSAUsageDANETA:
		// We set roots, so the system defaults don't get used. Verify checks the host name
		// (set below) and checks for expiration.
		opts := x509.VerifyOptions{
			Roots: x509.NewCertPool(),
		}

		// If the full certificate was included, we must add it to the valid roots, the TLS
		// server may not send it. ../rfc/7671:692
		var found bool
		if tlsa.Selector == adns.TLSASelectorCert && tlsa.MatchType == adns.TLSAMatchTypeFull {
			cert, err := x509.ParseCertificate(tlsa.CertAssoc)
			if err != nil {
				log.Debugx("parsing full exact certificate from tlsa record to use as root for usage dane-trusted-anchor", err)
				// Continue anyway, perhaps the servers sends it again in a way that the tls package can parse? (unlikely)
			} else {
				opts.Roots.AddCert(cert)
				found = true
			}
		}

		for _, cert := range cs.PeerCertificates {
			if match(cert) {
				opts.Roots.AddCert(cert)
				found = true
				break
			}
		}
		if !found {
			// Trusted anchor was not found in TLS certificates so we won't be able to
			// verify.
			return false, nil
		}

		// Trusted anchor was found, still need to verify.
		var errs []error
		for _, host := range append([]dns.Domain{allowedHost}, moreAllowedHosts...) {
			opts.DNSName = host.ASCII
			_, err := cs.PeerCertificates[0].Verify(opts)
			if err == nil {
				return true, nil
			}
			errs = append(errs, err)
		}
		return false, errors.Join(errs...)

	case adns.TLSAUsageDANEEE:
		// ../rfc/7250 is about raw public keys instead of x.509 certificates in tls
		// handshakes. Go's crypto/tls does not implement the extension (see
		// crypto/tls/common.go, the extensions values don't appear in the
		// rfc, but have values 19 and 20 according to
		// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
		// ../rfc/7671:1148 mentions the raw public keys are allowed. It's still
		// questionable that this is commonly implemented. For now the world can probably
		// live with an ignored certificate wrapped around the subject public key info.

		// We don't verify host name in certificate, ../rfc/7671:489
		// And we don't check for expiration. ../rfc/7671:527
		// The whole point of this type is to have simple secure infrastructure that
		// doesn't automatically expire (at the most inconvenient times).
		return match(cs.PeerCertificates[0]), nil

	default:
		// Unknown, perhaps defined in the future. Not an error.
		log.Debug("unrecognized tlsa usage, skipping", mlog.Field("tlsausage", tlsa.Usage))
		return false, nil
	}
}
