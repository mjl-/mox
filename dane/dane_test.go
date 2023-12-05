package dane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/exp/slog"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func tcheckf(t *testing.T, err error, format string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", fmt.Sprintf(format, args...), err)
	}
}

// Test dialing and DANE TLS verification.
func TestDial(t *testing.T) {
	mlog.SetConfig(map[string]slog.Level{"": mlog.LevelDebug})
	log := mlog.New("dane", nil)

	// Create fake CA/trusted-anchor certificate.
	taTempl := x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field.
		Subject:      pkix.Name{CommonName: "fake ca"},
		Issuer:       pkix.Name{CommonName: "fake ca"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	taPriv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	tcheckf(t, err, "generating trusted-anchor ca private key")
	taCertBuf, err := x509.CreateCertificate(cryptorand.Reader, &taTempl, &taTempl, taPriv.Public(), taPriv)
	tcheckf(t, err, "create trusted-anchor ca certificate")
	taCert, err := x509.ParseCertificate(taCertBuf)
	tcheckf(t, err, "parsing generated trusted-anchor ca certificate")

	tacertsha256 := sha256.Sum256(taCert.Raw)
	taCertSHA256 := tacertsha256[:]

	// Generate leaf private key & 2 certs, one expired and one valid, both signed by
	// trusted-anchor cert.
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	tcheckf(t, err, "generating leaf private key")

	makeLeaf := func(expired bool) (tls.Certificate, []byte, []byte) {
		now := time.Now()
		if expired {
			now = now.Add(-2 * time.Hour)
		}
		leafTempl := x509.Certificate{
			SerialNumber: big.NewInt(1), // Required field.
			Issuer:       taTempl.Subject,
			NotBefore:    now.Add(-1 * time.Hour),
			NotAfter:     now.Add(1 * time.Hour),
			DNSNames:     []string{"localhost"},
		}
		leafCertBuf, err := x509.CreateCertificate(cryptorand.Reader, &leafTempl, taCert, leafPriv.Public(), taPriv)
		tcheckf(t, err, "create trusted-anchor ca certificate")
		leafCert, err := x509.ParseCertificate(leafCertBuf)
		tcheckf(t, err, "parsing generated trusted-anchor ca certificate")

		leafSPKISHA256 := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
		leafSPKISHA512 := sha512.Sum512(leafCert.RawSubjectPublicKeyInfo)

		tlsLeafCert := tls.Certificate{
			Certificate: [][]byte{leafCertBuf, taCertBuf},
			PrivateKey:  leafPriv, // .(crypto.PrivateKey),
			Leaf:        leafCert,
		}
		return tlsLeafCert, leafSPKISHA256[:], leafSPKISHA512[:]
	}
	tlsLeafCert, leafSPKISHA256, leafSPKISHA512 := makeLeaf(false)
	tlsLeafCertExpired, _, _ := makeLeaf(true)

	// Set up loopback tls server.
	listenConn, err := net.Listen("tcp", "127.0.0.1:0")
	tcheckf(t, err, "listen for test server")
	addr := listenConn.Addr().String()
	_, portstr, err := net.SplitHostPort(addr)
	tcheckf(t, err, "get localhost port")
	uport, err := strconv.ParseUint(portstr, 10, 16)
	tcheckf(t, err, "parse localhost port")
	port := int(uport)

	defer listenConn.Close()

	// Config for server, replaced during tests.
	var tlsConfig atomic.Pointer[tls.Config]
	tlsConfig.Store(&tls.Config{
		Certificates: []tls.Certificate{tlsLeafCert},
	})

	// Loop handling incoming TLS connections.
	go func() {
		for {
			conn, err := listenConn.Accept()
			if err != nil {
				return
			}

			tlsConn := tls.Server(conn, tlsConfig.Load())
			tlsConn.Handshake()
			tlsConn.Close()
		}
	}()

	dialHost := "localhost"
	var allowedUsages []adns.TLSAUsage

	pkixRoots := x509.NewCertPool()

	// Helper function for dialing with DANE.
	test := func(resolver dns.Resolver, expRecord adns.TLSA, expErr any) {
		t.Helper()

		conn, record, err := Dial(context.Background(), log.Logger, resolver, "tcp", net.JoinHostPort(dialHost, portstr), allowedUsages, pkixRoots)
		if err == nil {
			conn.Close()
		}
		if (err == nil) != (expErr == nil) || err != nil && !errors.Is(err, expErr.(error)) && !errors.As(err, expErr) {
			t.Fatalf("got err %v (%#v), expected %#v", err, err, expErr)
		}
		if !reflect.DeepEqual(record, expRecord) {
			t.Fatalf("got verified record %v, expected %v", record, expRecord)
		}
	}

	tlsaName := fmt.Sprintf("_%d._tcp.localhost.", port)

	// Make all kinds of records, some invalid or non-matching.
	var zeroRecord adns.TLSA
	recordDANEEESPKISHA256 := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: leafSPKISHA256,
	}
	recordDANEEESPKISHA512 := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA512,
		CertAssoc: leafSPKISHA512,
	}
	recordDANEEESPKIFull := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeFull,
		CertAssoc: tlsLeafCert.Leaf.RawSubjectPublicKeyInfo,
	}
	mismatchRecordDANEEESPKISHA256 := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: make([]byte, sha256.Size), // Zero, no match.
	}
	malformedRecordDANEEESPKISHA256 := adns.TLSA{
		Usage:     adns.TLSAUsageDANEEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: leafSPKISHA256[:16], // Too short.
	}
	unknownparamRecordDANEEESPKISHA256 := adns.TLSA{
		Usage:     adns.TLSAUsage(10), // Unrecognized value.
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: leafSPKISHA256,
	}
	recordDANETACertSHA256 := adns.TLSA{
		Usage:     adns.TLSAUsageDANETA,
		Selector:  adns.TLSASelectorCert,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: taCertSHA256,
	}
	recordDANETACertFull := adns.TLSA{
		Usage:     adns.TLSAUsageDANETA,
		Selector:  adns.TLSASelectorCert,
		MatchType: adns.TLSAMatchTypeFull,
		CertAssoc: taCert.Raw,
	}
	malformedRecordDANETACertFull := adns.TLSA{
		Usage:     adns.TLSAUsageDANETA,
		Selector:  adns.TLSASelectorCert,
		MatchType: adns.TLSAMatchTypeFull,
		CertAssoc: taCert.Raw[1:], // Cannot parse certificate.
	}
	mismatchRecordDANETACertSHA256 := adns.TLSA{
		Usage:     adns.TLSAUsageDANETA,
		Selector:  adns.TLSASelectorCert,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: make([]byte, sha256.Size), // Zero, no match.
	}
	recordPKIXEESPKISHA256 := adns.TLSA{
		Usage:     adns.TLSAUsagePKIXEE,
		Selector:  adns.TLSASelectorSPKI,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: leafSPKISHA256,
	}
	recordPKIXTACertSHA256 := adns.TLSA{
		Usage:     adns.TLSAUsagePKIXTA,
		Selector:  adns.TLSASelectorCert,
		MatchType: adns.TLSAMatchTypeSHA256,
		CertAssoc: taCertSHA256,
	}

	resolver := dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANEEESPKISHA256}},
		AllAuthentic: true,
	}

	// DANE-EE SPKI SHA2-256 record.
	test(resolver, recordDANEEESPKISHA256, nil)

	// Check that record isn't used if not allowed.
	allowedUsages = []adns.TLSAUsage{adns.TLSAUsagePKIXTA}
	test(resolver, zeroRecord, ErrNoMatch)
	allowedUsages = nil // Restore.

	// Mixed allowed/not allowed usages are fine.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {mismatchRecordDANETACertSHA256, recordDANEEESPKISHA256}},
		AllAuthentic: true,
	}
	allowedUsages = []adns.TLSAUsage{adns.TLSAUsageDANEEE}
	test(resolver, recordDANEEESPKISHA256, nil)
	allowedUsages = nil // Restore.

	// DANE-TA CERT SHA2-256 record.
	resolver.TLSA = map[string][]adns.TLSA{
		tlsaName: {recordDANETACertSHA256},
	}
	test(resolver, recordDANETACertSHA256, nil)

	// No TLSA record.
	resolver.TLSA = nil
	test(resolver, zeroRecord, ErrNoRecords)

	// Insecure TLSA record.
	resolver.TLSA = map[string][]adns.TLSA{
		tlsaName: {recordDANEEESPKISHA256},
	}
	resolver.Inauthentic = []string{"tlsa " + tlsaName}
	test(resolver, zeroRecord, ErrInsecure)

	// Insecure CNAME.
	resolver.Inauthentic = []string{"cname localhost."}
	test(resolver, zeroRecord, ErrInsecure)

	// Insecure TLSA
	resolver.Inauthentic = []string{"tlsa " + tlsaName}
	test(resolver, zeroRecord, ErrInsecure)

	// Insecure CNAME should not look at TLSA records under that name, only under original.
	// Initial name/cname is secure. And it has secure TLSA records. But the lookup for
	// example1 is not secure, though the final example2 records are.
	resolver = dns.MockResolver{
		A:     map[string][]string{"example2.": {"127.0.0.1"}},
		CNAME: map[string]string{"localhost.": "example1.", "example1.": "example2."},
		TLSA: map[string][]adns.TLSA{
			fmt.Sprintf("_%d._tcp.example2.", port): {mismatchRecordDANETACertSHA256}, // Should be ignored.
			tlsaName:                                {recordDANEEESPKISHA256},         // Should match.
		},
		AllAuthentic: true,
		Inauthentic:  []string{"cname example1."},
	}
	test(resolver, recordDANEEESPKISHA256, nil)

	// Matching records after following cname.
	resolver = dns.MockResolver{
		A:            map[string][]string{"example.": {"127.0.0.1"}},
		CNAME:        map[string]string{"localhost.": "example."},
		TLSA:         map[string][]adns.TLSA{fmt.Sprintf("_%d._tcp.example.", port): {recordDANETACertSHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordDANETACertSHA256, nil)

	// Fallback to original name for TLSA records if cname-expanded name doesn't have records.
	resolver = dns.MockResolver{
		A:            map[string][]string{"example.": {"127.0.0.1"}},
		CNAME:        map[string]string{"localhost.": "example."},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANETACertSHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordDANETACertSHA256, nil)

	// Invalid DANE-EE record.
	resolver = dns.MockResolver{
		A: map[string][]string{
			"localhost.": {"127.0.0.1"},
		},
		TLSA: map[string][]adns.TLSA{
			tlsaName: {mismatchRecordDANEEESPKISHA256},
		},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, ErrNoMatch)

	// DANE-EE SPKI SHA2-512 record.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANEEESPKISHA512}},
		AllAuthentic: true,
	}
	test(resolver, recordDANEEESPKISHA512, nil)

	// DANE-EE SPKI Full record.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANEEESPKIFull}},
		AllAuthentic: true,
	}
	test(resolver, recordDANEEESPKIFull, nil)

	// DANE-TA with full certificate.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANETACertFull}},
		AllAuthentic: true,
	}
	test(resolver, recordDANETACertFull, nil)

	// DANE-TA for cert not in TLS handshake.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {mismatchRecordDANETACertSHA256}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, ErrNoMatch)

	// DANE-TA with leaf cert for other name.
	resolver = dns.MockResolver{
		A:            map[string][]string{"example.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{fmt.Sprintf("_%d._tcp.example.", port): {recordDANETACertSHA256}},
		AllAuthentic: true,
	}
	origDialHost := dialHost
	dialHost = "example."
	test(resolver, zeroRecord, ErrNoMatch)
	dialHost = origDialHost

	// DANE-TA with expired cert.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANETACertSHA256}},
		AllAuthentic: true,
	}
	tlsConfig.Store(&tls.Config{
		Certificates: []tls.Certificate{tlsLeafCertExpired},
	})
	test(resolver, zeroRecord, ErrNoMatch)
	test(resolver, zeroRecord, &VerifyError{})
	test(resolver, zeroRecord, &x509.CertificateInvalidError{})
	// Restore.
	tlsConfig.Store(&tls.Config{
		Certificates: []tls.Certificate{tlsLeafCert},
	})

	// Malformed TLSA record is unusable, resulting in failure if none left.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {malformedRecordDANEEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, ErrNoMatch)

	// Malformed TLSA record is unusable and skipped, other verified record causes Dial to succeed.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {malformedRecordDANEEESPKISHA256, recordDANEEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordDANEEESPKISHA256, nil)

	// Record with unknown parameters (usage in this case) is unusable, resulting in failure if none left.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {unknownparamRecordDANEEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, ErrNoMatch)

	// Unknown parameter does not prevent other valid record to verify.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {unknownparamRecordDANEEESPKISHA256, recordDANEEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordDANEEESPKISHA256, nil)

	// Malformed full TA certificate.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {malformedRecordDANETACertFull}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, ErrNoMatch)

	// Full TA certificate without getting it from TLS server.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordDANETACertFull}},
		AllAuthentic: true,
	}
	tlsLeafOnlyCert := tlsLeafCert
	tlsLeafOnlyCert.Certificate = tlsLeafOnlyCert.Certificate[:1]
	tlsConfig.Store(&tls.Config{
		Certificates: []tls.Certificate{tlsLeafOnlyCert},
	})
	test(resolver, recordDANETACertFull, nil)
	// Restore.
	tlsConfig.Store(&tls.Config{
		Certificates: []tls.Certificate{tlsLeafCert},
	})

	// PKIXEE, will fail due to not being CA-signed.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordPKIXEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, &x509.UnknownAuthorityError{})

	// PKIXTA, will fail due to not being CA-signed.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordPKIXTACertSHA256}},
		AllAuthentic: true,
	}
	test(resolver, zeroRecord, &x509.UnknownAuthorityError{})

	// Now we add the TA to the "pkix" trusted roots and try again.
	pkixRoots.AddCert(taCert)

	// PKIXEE, will now succeed.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordPKIXEESPKISHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordPKIXEESPKISHA256, nil)

	// PKIXTA, will fail due to not being CA-signed.
	resolver = dns.MockResolver{
		A:            map[string][]string{"localhost.": {"127.0.0.1"}},
		TLSA:         map[string][]adns.TLSA{tlsaName: {recordPKIXTACertSHA256}},
		AllAuthentic: true,
	}
	test(resolver, recordPKIXTACertSHA256, nil)
}
