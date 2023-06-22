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
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxvar"
)

var xlog = mlog.New("autotls")

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
// contactEmail must be a valid email address to which notifications about ACME can
// be sent. directoryURL is the ACME starting point. When shutdown is closed, no
// new TLS connections can be created.
func Load(name, acmeDir, contactEmail, directoryURL string, shutdown <-chan struct{}) (*Manager, error) {
	if directoryURL == "" {
		return nil, fmt.Errorf("empty ACME directory URL")
	}
	if contactEmail == "" {
		return nil, fmt.Errorf("empty contact email")
	}

	// Load identity key if it exists. Otherwise, create a new key.
	p := filepath.Join(acmeDir + "/" + name + ".key")
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
		Cache:  dirCache(acmeDir + "/keycerts/" + name),
		Prompt: autocert.AcceptTOS,
		Email:  contactEmail,
		Client: &acme.Client{
			DirectoryURL: directoryURL,
			Key:          key,
			UserAgent:    "mox/" + moxvar.Version,
		},
		// HostPolicy set below.
	}

	loggingGetCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		log := xlog.WithContext(hello.Context())

		// Handle missing SNI to prevent logging an error below.
		// At startup, during config initialization, we already adjust the tls config to
		// inject the listener hostname if there isn't one in the TLS client hello. This is
		// common for SMTP STARTTLS connections, which often do not care about the
		// validation of the certificate.
		if hello.ServerName == "" {
			log.Debug("tls request without sni servername, rejecting", mlog.Field("localaddr", hello.Conn.LocalAddr()), mlog.Field("supportedprotos", hello.SupportedProtos))
			return nil, fmt.Errorf("sni server name required")
		}

		cert, err := m.GetCertificate(hello)
		if err != nil {
			if errors.Is(err, errHostNotAllowed) {
				log.Debugx("requesting certificate", err, mlog.Field("host", hello.ServerName))
			} else {
				log.Errorx("requesting certificate", err, mlog.Field("host", hello.ServerName))
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

// SetAllowedHostnames sets a new list of allowed hostnames for automatic TLS.
// After setting the host names, a goroutine is start to check that new host names
// are fully served by publicIPs (only if non-empty and there is no unspecified
// address in the list). If no, log an error with a warning that ACME validation
// may fail.
func (m *Manager) SetAllowedHostnames(resolver dns.Resolver, hostnames map[dns.Domain]struct{}, publicIPs []string, checkHosts bool) {
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

	xlog.Debug("autotls setting allowed hostnames", mlog.Field("hostnames", l), mlog.Field("publicips", publicIPs))
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

			xlog.Debug("checking ips of hosts configured for acme tls cert validation")
			for _, h := range added {
				ips, err := resolver.LookupIP(ctx, "ip", h.ASCII+".")
				if err != nil {
					xlog.Errorx("warning: acme tls cert validation for host may fail due to dns lookup error", err, mlog.Field("host", h))
					continue
				}
				for _, ip := range ips {
					if _, ok := publicIPstrs[ip.String()]; !ok {
						xlog.Error("warning: acme tls cert validation for host is likely to fail because not all its ips are being listened on", mlog.Field("hostname", h), mlog.Field("listenedips", publicIPs), mlog.Field("hostips", ips), mlog.Field("missingip", ip))
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
	log := xlog.WithContext(ctx)
	defer func() {
		log.WithContext(ctx).Debugx("autotls hostpolicy result", rerr, mlog.Field("host", host))
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
	log := xlog.WithContext(ctx)
	defer func() {
		log.Debugx("dircache delete result", rerr, mlog.Field("name", name))
	}()
	err := autocert.DirCache(d).Delete(ctx, name)
	if err != nil {
		log.Errorx("deleting cert from dir cache", err, mlog.Field("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Info("autotls cert delete", mlog.Field("name", name))
	}
	return err
}

func (d dirCache) Get(ctx context.Context, name string) (rbuf []byte, rerr error) {
	log := xlog.WithContext(ctx)
	defer func() {
		log.Debugx("dircache get result", rerr, mlog.Field("name", name))
	}()
	buf, err := autocert.DirCache(d).Get(ctx, name)
	if err != nil && errors.Is(err, autocert.ErrCacheMiss) {
		log.Infox("getting cert from dir cache", err, mlog.Field("name", name))
	} else if err != nil {
		log.Errorx("getting cert from dir cache", err, mlog.Field("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Debug("autotls cert get", mlog.Field("name", name))
	}
	return buf, err
}

func (d dirCache) Put(ctx context.Context, name string, data []byte) (rerr error) {
	log := xlog.WithContext(ctx)
	defer func() {
		log.Debugx("dircache put result", rerr, mlog.Field("name", name))
	}()
	metricCertput.Inc()
	err := autocert.DirCache(d).Put(ctx, name, data)
	if err != nil {
		log.Errorx("storing cert in dir cache", err, mlog.Field("name", name))
	} else if !strings.HasSuffix(name, "+token") {
		log.Info("autotls cert store", mlog.Field("name", name))
	}
	return err
}
