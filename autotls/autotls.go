// Package autotls automatically configures TLS (for SMTP, IMAP, HTTP) by
// requesting certificates with ACME, typically from Let's Encrypt.
package autotls

// We do tls-alpn-01, and also http-01. For DNS we would need a third party tool
// with an API that can make the DNS changes, as we don't want to link in dozens of
// bespoke API's for DNS record manipulation into mox.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/autocert"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxvar"
)

var (
	metricCertput = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_autotls_certput_total",
			Help: "Number of certificate store puts.",
		},
	)
)

// Manager is in charge of a single ACME identity, and automatically requests
// certificates for allowlisted hosts.
type Manager struct {
	ACMETLSConfig *tls.Config // For serving HTTPS on port 443, which is required for certificate requests to succeed.
	TLSConfig     *tls.Config // For all TLS servers not used for validating ACME requests. Like SMTP and IMAP (including with STARTTLS) and HTTPS on ports other than 443.
	Manager       *autocert.Manager

	shutdown <-chan struct{}

	sync.Mutex
	hosts map[dns.Domain]struct{}
}

// Load returns an initialized autotls manager for "name" (used for the ACME key
// file and requested certs and their keys). All files are stored within acmeDir.
//
// contactEmail must be a valid email address to which notifications about ACME can
// be sent. directoryURL is the ACME starting point.
//
// eabKeyID and eabKey are for external account binding when making a new account,
// which some ACME providers require.
//
// getPrivateKey is called to get the private key for the host and key type. It
// can be used to deliver a specific (e.g. always the same) private key for a
// host, or a newly generated key.
//
// When shutdown is closed, no new TLS connections can be created.
func Load(name, acmeDir, contactEmail, directoryURL string, eabKeyID string, eabKey []byte, getPrivateKey func(host string, keyType autocert.KeyType) (crypto.Signer, error), shutdown <-chan struct{}) (*Manager, error) {
	if directoryURL == "" {
		return nil, fmt.Errorf("empty ACME directory URL")
	}
	if contactEmail == "" {
		return nil, fmt.Errorf("empty contact email")
	}

	// Load identity key if it exists. Otherwise, create a new key.
	p := filepath.Join(acmeDir, name+".key")
	var key crypto.Signer
	f, err := os.Open(p)
	if f != nil {
		defer f.Close()
	}
	if err != nil && os.IsNotExist(err) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ecdsa identity key: %s", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal identity key: %s", err)
		}
		block := &pem.Block{
			Type: "PRIVATE KEY",
			Headers: map[string]string{
				"Note": fmt.Sprintf("PEM PKCS8 ECDSA private key generated for ACME provider %s by mox", name),
			},
			Bytes: der,
		}
		b := &bytes.Buffer{}
		if err := pem.Encode(b, block); err != nil {
			return nil, fmt.Errorf("pem encode: %s", err)
		} else if err := os.WriteFile(p, b.Bytes(), 0660); err != nil {
			return nil, fmt.Errorf("writing identity key: %s", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("open identity key file: %s", err)
	} else {
		var privKey any
		if buf, err := io.ReadAll(f); err != nil {
			return nil, fmt.Errorf("reading identity key: %s", err)
		} else if p, _ := pem.Decode(buf); p == nil {
			return nil, fmt.Errorf("no pem data")
		} else if p.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("got PEM block %q, expected \"PRIVATE KEY\"", p.Type)
		} else if privKey, err = x509.ParsePKCS8PrivateKey(p.Bytes); err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %s", err)
		}
		switch k := privKey.(type) {
		case *ecdsa.PrivateKey:
			key = k
		case *rsa.PrivateKey:
			key = k
		default:
			return nil, fmt.Errorf("unsupported private key type %T", key)
		}
	}

	m := &autocert.Manager{
		Cache:  dirCache(filepath.Join(acmeDir, "keycerts", name)),
		Prompt: autocert.AcceptTOS,
		Email:  contactEmail,
		Client: &acme.Client{
			DirectoryURL: directoryURL,
			Key:          key,
			UserAgent:    "mox/" + moxvar.Version,
		},
		GetPrivateKey: getPrivateKey,
		// HostPolicy set below.
	}
	// If external account binding key is provided, use it for registering a new account.
	// todo: ideally the key and its id are provided temporarily by the admin when registering a new account. but we don't do that interactive setup yet. in the future, an interactive setup/quickstart would ask for the key once to register a new acme account.
	if eabKeyID != "" {
		m.ExternalAccountBinding = &acme.ExternalAccountBinding{
			KID: eabKeyID,
			Key: eabKey,
		}
	}

	loggingGetCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		log := mlog.New("autotls", nil).WithContext(hello.Context())

		// Handle missing SNI to prevent logging an error below.
		// At startup, during config initialization, we already adjust the tls config to
		// inject the listener hostname if there isn't one in the TLS client hello. This is
		// common for SMTP STARTTLS connections, which often do not care about the
		// verification of the certificate.
		if hello.ServerName == "" {
			log.Debug("tls request without sni servername, rejecting", slog.Any("localaddr", hello.Conn.LocalAddr()), slog.Any("supportedprotos", hello.SupportedProtos))
			return nil, fmt.Errorf("sni server name required")
		}

		cert, err := m.GetCertificate(hello)
		if err != nil {
			if errors.Is(err, errHostNotAllowed) {
				log.Debugx("requesting certificate", err, slog.String("host", hello.ServerName))
			} else {
				log.Errorx("requesting certificate", err, slog.String("host", hello.ServerName))
			}
		}
		return cert, err
	}

	acmeTLSConfig := *m.TLSConfig()
	acmeTLSConfig.GetCertificate = loggingGetCertificate

	tlsConfig := tls.Config{
		GetCertificate: loggingGetCertificate,
	}

	a := &Manager{
		ACMETLSConfig: &acmeTLSConfig,
		TLSConfig:     &tlsConfig,
		Manager:       m,
		shutdown:      shutdown,
		hosts:         map[dns.Domain]struct{}{},
	}
	m.HostPolicy = a.HostPolicy
	return a, nil
}

// CertAvailable checks whether a non-expired ECDSA certificate is available in the
// cache for host. No other checks than expiration are done.
func (m *Manager) CertAvailable(ctx context.Context, log mlog.Log, host dns.Domain) (bool, error) {
	ck := host.ASCII // Would be "+rsa" for rsa keys.
	data, err := m.Manager.Cache.Get(ctx, ck)
	if err != nil && errors.Is(err, autocert.ErrCacheMiss) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("attempt to get certificate from cache: %v", err)
	}

	// The cached keycert is of the form: private key, leaf certificate, intermediate certificates...
	privb, rem := pem.Decode(data)
	if privb == nil {
		return false, fmt.Errorf("missing private key in cached keycert file")
	}
	pubb, _ := pem.Decode(rem)
	if pubb == nil {
		return false, fmt.Errorf("missing certificate in cached keycert file")
	} else if pubb.Type != "CERTIFICATE" {
		return false, fmt.Errorf("second pem block is %q, expected CERTIFICATE", pubb.Type)
	}
	cert, err := x509.ParseCertificate(pubb.Bytes)
	if err != nil {
		return false, fmt.Errorf("parsing certificate from cached keycert file: %v", err)
	}
	// We assume the certificate has a matching hostname, and is properly CA-signed. We
	// only check the expiration time.
	if time.Until(cert.NotBefore) > 0 || time.Since(cert.NotAfter) > 0 {
		return false, nil
	}
	return true, nil
}

// SetAllowedHostnames sets a new list of allowed hostnames for automatic TLS.
// After setting the host names, a goroutine is start to check that new host names
// are fully served by publicIPs (only if non-empty and there is no unspecified
// address in the list). If no, log an error with a warning that ACME validation
// may fail.
func (m *Manager) SetAllowedHostnames(log mlog.Log, resolver dns.Resolver, hostnames map[dns.Domain]struct{}, publicIPs []string, checkHosts bool) {
	m.Lock()
	defer m.Unlock()

	// Log as slice, sorted.
	l := make([]dns.Domain, 0, len(hostnames))
	for d := range hostnames {
		l = append(l, d)
	}
	sort.Slice(l, func(i, j int) bool {
		return l[i].Name() < l[j].Name()
	})

	log.Debug("autotls setting allowed hostnames", slog.Any("hostnames", l), slog.Any("publicips", publicIPs))
	var added []dns.Domain
	for h := range hostnames {
		if _, ok := m.hosts[h]; !ok {
			added = append(added, h)
		}
	}
	m.hosts = hostnames

	if checkHosts && len(added) > 0 && len(publicIPs) > 0 {
		for _, ip := range publicIPs {
			if net.ParseIP(ip).IsUnspecified() {
				return
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			publicIPstrs := map[string]struct{}{}
			for _, ip := range publicIPs {
				publicIPstrs[ip] = struct{}{}
			}

			log.Debug("checking ips of hosts configured for acme tls cert validation")
			for _, h := range added {
				ips, _, err := resolver.LookupIP(ctx, "ip", h.ASCII+".")
				if err != nil {
					log.Errorx("warning: acme tls cert validation for host may fail due to dns lookup error", err, slog.Any("host", h))
					continue
				}
				for _, ip := range ips {
					if _, ok := publicIPstrs[ip.String()]; !ok {
						log.Error("warning: acme tls cert validation for host is likely to fail because not all its ips are being listened on",
							slog.Any("hostname", h),
							slog.Any("listenedips", publicIPs),
							slog.Any("hostips", ips),
							slog.Any("missingip", ip))
					}
				}
			}
		}()
	}
}

// Hostnames returns the allowed host names for use with ACME.
func (m *Manager) Hostnames() []dns.Domain {
	m.Lock()
	defer m.Unlock()
	var l []dns.Domain
	for h := range m.hosts {
		l = append(l, h)
	}
	return l
}

var errHostNotAllowed = errors.New("autotls: host not in allowlist")

// HostPolicy decides if a host is allowed for use with ACME, i.e. whether a
// certificate will be returned if present and/or will be requested if not yet
// present. Only hosts added with SetAllowedHostnames are allowed. During shutdown,
// no new connections are allowed.
func (m *Manager) HostPolicy(ctx context.Context, host string) (rerr error) {
	log := mlog.New("autotls", nil).WithContext(ctx)
	defer func() {
		log.Debugx("autotls hostpolicy result", rerr, slog.String("host", host))
	}()

	// Don't request new TLS certs when we are shutting down.
	select {
	case <-m.shutdown:
		return fmt.Errorf("shutting down")
	default:
	}

	xhost, _, err := net.SplitHostPort(host)
	if err == nil {
		// For http-01, host may include a port number.
		host = xhost
	}

	d, err := dns.ParseDomain(host)
	if err != nil {
		return fmt.Errorf("invalid host: %v", err)
	}

	m.Lock()
	defer m.Unlock()
	if _, ok := m.hosts[d]; !ok {
		return fmt.Errorf("%w: %q", errHostNotAllowed, d)
	}
	return nil
}

type dirCache autocert.DirCache

func (d dirCache) Delete(ctx context.Context, name string) (rerr error) {
	log := mlog.New("autotls", nil).WithContext(ctx)
	defer func() {
		log.Debugx("dircache delete result", rerr, slog.String("name", name))
	}()
	err := autocert.DirCache(d).Delete(ctx, name)
	if err != nil {
		log.Errorx("deleting cert from dir cache", err, slog.String("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Info("autotls cert delete", slog.String("name", name))
	}
	return err
}

func (d dirCache) Get(ctx context.Context, name string) (rbuf []byte, rerr error) {
	log := mlog.New("autotls", nil).WithContext(ctx)
	defer func() {
		log.Debugx("dircache get result", rerr, slog.String("name", name))
	}()
	buf, err := autocert.DirCache(d).Get(ctx, name)
	if err != nil && errors.Is(err, autocert.ErrCacheMiss) {
		log.Infox("getting cert from dir cache", err, slog.String("name", name))
	} else if err != nil {
		log.Errorx("getting cert from dir cache", err, slog.String("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Debug("autotls cert get", slog.String("name", name))
	}
	return buf, err
}

func (d dirCache) Put(ctx context.Context, name string, data []byte) (rerr error) {
	log := mlog.New("autotls", nil).WithContext(ctx)
	defer func() {
		log.Debugx("dircache put result", rerr, slog.String("name", name))
	}()
	metricCertput.Inc()
	err := autocert.DirCache(d).Put(ctx, name, data)
	if err != nil {
		log.Errorx("storing cert in dir cache", err, slog.String("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Info("autotls cert store", slog.String("name", name))
	}
	return err
}
