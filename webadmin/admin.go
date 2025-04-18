// Package webadmin is a web app for the mox administrator for viewing and changing
// the configuration, like creating/removing accounts, viewing DMARC and TLS
// reports, check DNS records for a domain, change the webserver configuration,
// etc.
package webadmin

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"

	"golang.org/x/text/unicode/norm"

	"github.com/mjl-/adns"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

	"github.com/mjl-/mox/admin"
	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	mox "github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/publicsuffix"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/webauth"
)

var pkglog = mlog.New("webadmin", nil)

//go:embed api.json
var adminapiJSON []byte

//go:embed admin.html
var adminHTML []byte

//go:embed admin.js
var adminJS []byte

var webadminFile = &mox.WebappFile{
	HTML:       adminHTML,
	JS:         adminJS,
	HTMLPath:   filepath.FromSlash("webadmin/admin.html"),
	JSPath:     filepath.FromSlash("webadmin/admin.js"),
	CustomStem: "webadmin",
}

var adminDoc = mustParseAPI("admin", adminapiJSON)

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		pkglog.Fatalx("parsing webadmin api docs", err, slog.String("api", api))
	}
	return doc
}

var sherpaHandlerOpts *sherpa.HandlerOpts

func makeSherpaHandler(cookiePath string, isForwarded bool) (http.Handler, error) {
	return sherpa.NewHandler("/api/", moxvar.Version, Admin{cookiePath, isForwarded}, &adminDoc, sherpaHandlerOpts)
}

func init() {
	collector, err := sherpaprom.NewCollector("moxadmin", nil)
	if err != nil {
		pkglog.Fatalx("creating sherpa prometheus collector", err)
	}

	sherpaHandlerOpts = &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none", NoCORS: true}
	// Just to validate.
	_, err = makeSherpaHandler("", false)
	if err != nil {
		pkglog.Fatalx("sherpa handler", err)
	}

	mox.NewWebadminHandler = func(basePath string, isForwarded bool) http.Handler {
		return http.HandlerFunc(Handler(basePath, isForwarded))
	}
}

// Handler returns a handler for the webadmin endpoints, customized for the
// cookiePath.
func Handler(cookiePath string, isForwarded bool) func(w http.ResponseWriter, r *http.Request) {
	sh, err := makeSherpaHandler(cookiePath, isForwarded)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, "500 - internal server error - cannot handle requests", http.StatusInternalServerError)
			return
		}
		handle(sh, isForwarded, w, r)
	}
}

// Admin exports web API functions for the admin web interface. All its methods are
// exported under api/. Function calls require valid HTTP Authentication
// credentials of a user.
type Admin struct {
	cookiePath  string // From listener, for setting authentication cookies.
	isForwarded bool   // From listener, whether we look at X-Forwarded-* headers.
}

type ctxKey string

var requestInfoCtxKey ctxKey = "requestInfo"

type requestInfo struct {
	SessionToken store.SessionToken
	Response     http.ResponseWriter
	Request      *http.Request // For Proto and TLS connection state during message submit.
}

func handle(apiHandler http.Handler, isForwarded bool, w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	log := pkglog.WithContext(ctx).With(slog.String("adminauth", ""))

	// HTML/JS can be retrieved without authentication.
	if r.URL.Path == "/" {
		switch r.Method {
		case "GET", "HEAD":
			webadminFile.Serve(ctx, log, w, r)
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		}
		return
	} else if r.URL.Path == "/licenses.txt" {
		switch r.Method {
		case "GET", "HEAD":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			mox.LicensesWrite(w)
		default:
			http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		}
		return
	}

	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	// Only allow POST for calls, they will not work cross-domain without CORS.
	if isAPI && r.URL.Path != "/api/" && r.Method != "POST" {
		http.Error(w, "405 - method not allowed - use post", http.StatusMethodNotAllowed)
		return
	}

	// All other URLs, except the login endpoint require some authentication.
	var sessionToken store.SessionToken
	if r.URL.Path != "/api/LoginPrep" && r.URL.Path != "/api/Login" {
		var ok bool
		_, sessionToken, _, ok = webauth.Check(ctx, log, webauth.Admin, "webadmin", isForwarded, w, r, isAPI, isAPI, false)
		if !ok {
			// Response has been written already.
			return
		}
	}

	if isAPI {
		reqInfo := requestInfo{sessionToken, w, r}
		ctx = context.WithValue(ctx, requestInfoCtxKey, reqInfo)
		apiHandler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	http.NotFound(w, r)
}

func xcheckf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	// If caller tried saving a config that is invalid, or because of a bad request, cause a user error.
	if errors.Is(err, mox.ErrConfig) || errors.Is(err, admin.ErrRequest) {
		xcheckuserf(ctx, err, format, args...)
	}

	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	pkglog.WithContext(ctx).Errorx(msg, err)
	code := "server:error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = "user:error"
	}
	panic(&sherpa.Error{Code: code, Message: errmsg})
}

func xcheckuserf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	pkglog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "user:error", Message: errmsg})
}

func xusererrorf(ctx context.Context, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	pkglog.WithContext(ctx).Error(msg)
	panic(&sherpa.Error{Code: "user:error", Message: msg})
}

// LoginPrep returns a login token, and also sets it as cookie. Both must be
// present in the call to Login.
func (w Admin) LoginPrep(ctx context.Context) string {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	var data [8]byte
	_, err := cryptorand.Read(data[:])
	xcheckf(ctx, err, "generate token")
	loginToken := base64.RawURLEncoding.EncodeToString(data[:])

	webauth.LoginPrep(ctx, log, "webadmin", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken)

	return loginToken
}

// Login returns a session token for the credentials, or fails with error code
// "user:badLogin". Call LoginPrep to get a loginToken.
func (w Admin) Login(ctx context.Context, loginToken, password string) store.CSRFToken {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	csrfToken, err := webauth.Login(ctx, log, webauth.Admin, "webadmin", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, loginToken, "", password)
	if _, ok := err.(*sherpa.Error); ok {
		panic(err)
	}
	xcheckf(ctx, err, "login")
	return csrfToken
}

// Logout invalidates the session token.
func (w Admin) Logout(ctx context.Context) {
	log := pkglog.WithContext(ctx)
	reqInfo := ctx.Value(requestInfoCtxKey).(requestInfo)

	err := webauth.Logout(ctx, log, webauth.Admin, "webadmin", w.cookiePath, w.isForwarded, reqInfo.Response, reqInfo.Request, "", reqInfo.SessionToken)
	xcheckf(ctx, err, "logout")
}

// Version returns the version, goos and goarch.
func (w Admin) Version(ctx context.Context) (version, goos, goarch string) {
	return moxvar.Version, runtime.GOOS, runtime.GOARCH
}

type Result struct {
	Errors       []string
	Warnings     []string
	Instructions []string
}

type DNSSECResult struct {
	Result
}

type IPRevCheckResult struct {
	Hostname dns.Domain          // This hostname, IPs must resolve back to this.
	IPNames  map[string][]string // IP to names.
	Result
}

type MX struct {
	Host string
	Pref int
	IPs  []string
}

type MXCheckResult struct {
	Records []MX
	Result
}

type TLSCheckResult struct {
	Result
}

type DANECheckResult struct {
	Result
}

type SPFRecord struct {
	spf.Record
}

type SPFCheckResult struct {
	DomainTXT    string
	DomainRecord *SPFRecord
	HostTXT      string
	HostRecord   *SPFRecord
	Result
}

type DKIMCheckResult struct {
	Records []DKIMRecord
	Result
}

type DKIMRecord struct {
	Selector string
	TXT      string
	Record   *dkim.Record
}

type DMARCRecord struct {
	dmarc.Record
}

type DMARCCheckResult struct {
	Domain string
	TXT    string
	Record *DMARCRecord
	Result
}

type TLSRPTRecord struct {
	tlsrpt.Record
}

type TLSRPTCheckResult struct {
	TXT    string
	Record *TLSRPTRecord
	Result
}

type MTASTSRecord struct {
	mtasts.Record
}
type MTASTSCheckResult struct {
	TXT        string
	Record     *MTASTSRecord
	PolicyText string
	Policy     *mtasts.Policy
	Result
}

type SRVConfCheckResult struct {
	SRVs map[string][]net.SRV // Service (e.g. "_imaps") to records.
	Result
}

type AutoconfCheckResult struct {
	ClientSettingsDomainIPs []string
	IPs                     []string
	Result
}

type AutodiscoverSRV struct {
	net.SRV
	IPs []string
}

type AutodiscoverCheckResult struct {
	Records []AutodiscoverSRV
	Result
}

// CheckResult is the analysis of a domain, its actual configuration (DNS, TLS,
// connectivity) and the mox configuration. It includes configuration instructions
// (e.g. DNS records), and warnings and errors encountered.
type CheckResult struct {
	Domain       string
	DNSSEC       DNSSECResult
	IPRev        IPRevCheckResult
	MX           MXCheckResult
	TLS          TLSCheckResult
	DANE         DANECheckResult
	SPF          SPFCheckResult
	DKIM         DKIMCheckResult
	DMARC        DMARCCheckResult
	HostTLSRPT   TLSRPTCheckResult
	DomainTLSRPT TLSRPTCheckResult
	MTASTS       MTASTSCheckResult
	SRVConf      SRVConfCheckResult
	Autoconf     AutoconfCheckResult
	Autodiscover AutodiscoverCheckResult
}

// logPanic can be called with a defer from a goroutine to prevent the entire program from being shutdown in case of a panic.
func logPanic(ctx context.Context) {
	x := recover()
	if x == nil {
		return
	}
	pkglog.WithContext(ctx).Error("recover from panic", slog.Any("panic", x))
	debug.PrintStack()
	metrics.PanicInc(metrics.Webadmin)
}

// return IPs we may be listening on.
func xlistenIPs(ctx context.Context, receiveOnly bool) []net.IP {
	ips, err := mox.IPs(ctx, receiveOnly)
	xcheckf(ctx, err, "listing ips")
	return ips
}

// return IPs from which we may be sending.
func xsendingIPs(ctx context.Context) []net.IP {
	ips, err := mox.IPs(ctx, false)
	xcheckf(ctx, err, "listing ips")
	return ips
}

// CheckDomain checks the configuration for the domain, such as MX, SMTP STARTTLS,
// SPF, DKIM, DMARC, TLSRPT, MTASTS, autoconfig, autodiscover.
func (Admin) CheckDomain(ctx context.Context, domainName string) (r CheckResult) {
	// todo future: should run these checks without a DNS cache so recent changes are picked up.

	resolver := dns.StrictResolver{Pkg: "check", Log: pkglog.WithContext(ctx).Logger}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	nctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return checkDomain(nctx, resolver, dialer, domainName)
}

func unptr[T any](l []*T) []T {
	if l == nil {
		return nil
	}
	r := make([]T, len(l))
	for i, e := range l {
		r[i] = *e
	}
	return r
}

func checkDomain(ctx context.Context, resolver dns.Resolver, dialer *net.Dialer, domainName string) (r CheckResult) {
	log := pkglog.WithContext(ctx)

	domain, xerr := dns.ParseDomain(domainName)
	xcheckuserf(ctx, xerr, "parsing domain")

	domConf, ok := mox.Conf.Domain(domain)
	if !ok {
		panic(&sherpa.Error{Code: "user:notFound", Message: "domain not found"})
	}

	listenIPs := xlistenIPs(ctx, true)
	isListenIP := func(ip net.IP) bool {
		for _, lip := range listenIPs {
			if ip.Equal(lip) {
				return true
			}
		}
		return false
	}

	addf := func(l *[]string, format string, args ...any) {
		*l = append(*l, fmt.Sprintf(format, args...))
	}

	// Host must be an absolute dns name, ending with a dot.
	lookupIPs := func(errors *[]string, host string) (ips []string, ourIPs, notOurIPs []net.IP, rerr error) {
		addrs, _, err := resolver.LookupHost(ctx, host)
		if err != nil {
			addf(errors, "Looking up %q: %s", host, err)
			return nil, nil, nil, err
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				addf(errors, "Bad IP %q", addr)
				continue
			}
			ips = append(ips, ip.String())
			if isListenIP(ip) {
				ourIPs = append(ourIPs, ip)
			} else {
				notOurIPs = append(notOurIPs, ip)
			}
		}
		return ips, ourIPs, notOurIPs, nil
	}

	checkTLS := func(errors *[]string, host string, ips []string, port string) {
		d := tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12, // ../rfc/8996:31 ../rfc/8997:66
				RootCAs:    mox.Conf.Static.TLS.CertPool,
			},
		}
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
			if err != nil {
				addf(errors, "TLS connection to hostname %q, IP %q: %s", host, ip, err)
			} else {
				err := conn.Close()
				log.Check(err, "closing tcp connection")
			}
		}
	}

	// If at least one listener with SMTP enabled has unspecified NATed IPs, we'll skip
	// some checks related to these IPs.
	var isNAT, isUnspecifiedNAT bool
	for _, l := range mox.Conf.Static.Listeners {
		if !l.SMTP.Enabled {
			continue
		}
		if l.IPsNATed {
			isUnspecifiedNAT = true
			isNAT = true
		}
		if len(l.NATIPs) > 0 {
			isNAT = true
		}
	}

	var wg sync.WaitGroup

	// DNSSEC
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// Some DNSSEC-verifying resolvers return unauthentic data for ".", so we check "com".
		_, result, err := resolver.LookupNS(ctx, "com.")
		if err != nil {
			addf(&r.DNSSEC.Errors, "Looking up NS for DNS root (.) to check support in resolver for DNSSEC-verification: %s", err)
		} else if !result.Authentic {
			addf(&r.DNSSEC.Warnings, `It looks like the DNS resolvers configured on your system do not verify DNSSEC, or aren't trusted (by having loopback IPs or through "options trust-ad" in /etc/resolv.conf).  Without DNSSEC, outbound delivery with SMTP uses unprotected MX records, and SMTP STARTTLS connections cannot verify the TLS certificate with DANE (based on public keys in DNS), and will fall back to either MTA-STS for verification, or use "opportunistic TLS" with no certificate verification.`)
		} else {
			_, result, _ := resolver.LookupMX(ctx, domain.ASCII+".")
			if !result.Authentic {
				addf(&r.DNSSEC.Warnings, `DNS records for this domain (zone) are not DNSSEC-signed. Mail servers sending email to your domain, or receiving email from your domain, cannot verify that the MX/SPF/DKIM/DMARC/MTA-STS records they see are authentic.`)
			}
		}

		addf(&r.DNSSEC.Instructions, `Enable DNSSEC-signing of the DNS records of your domain (zone) at your DNS hosting provider.`)

		addf(&r.DNSSEC.Instructions, `If your DNS records are already DNSSEC-signed, you may not have a DNSSEC-verifying recursive resolver configured. Install unbound, ensure it has DNSSEC root keys (see unbound-anchor), and enable support for "extended dns errors" (EDE, available since unbound v1.16.0). Test with "dig com. ns" and look for "ad" (authentic data) in response "flags".

cat <<EOF >/etc/unbound/unbound.conf.d/ede.conf
server:
    ede: yes
    val-log-level: 2
EOF
`)
	}()

	// IPRev
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// For each mox.Conf.SpecifiedSMTPListenIPs and all NATIPs, and each IP for
		// mox.Conf.HostnameDomain, check if they resolve back to the host name.
		hostIPs := map[dns.Domain][]net.IP{}
		ips, _, err := resolver.LookupIP(ctx, "ip", mox.Conf.Static.HostnameDomain.ASCII+".")
		if err != nil {
			addf(&r.IPRev.Errors, "Looking up IPs for hostname: %s", err)
		}

		gatherMoreIPs := func(publicIPs []net.IP) {
		nextip:
			for _, ip := range publicIPs {
				for _, xip := range ips {
					if ip.Equal(xip) {
						continue nextip
					}
				}
				ips = append(ips, ip)
			}
		}
		if !isNAT {
			gatherMoreIPs(mox.Conf.Static.SpecifiedSMTPListenIPs)
		}
		for _, l := range mox.Conf.Static.Listeners {
			if !l.SMTP.Enabled {
				continue
			}
			var natips []net.IP
			for _, ip := range l.NATIPs {
				natips = append(natips, net.ParseIP(ip))
			}
			gatherMoreIPs(natips)
		}
		hostIPs[mox.Conf.Static.HostnameDomain] = ips

		iplist := func(ips []net.IP) string {
			var ipstrs []string
			for _, ip := range ips {
				ipstrs = append(ipstrs, ip.String())
			}
			return strings.Join(ipstrs, ", ")
		}

		r.IPRev.Hostname = mox.Conf.Static.HostnameDomain
		r.IPRev.Instructions = []string{
			fmt.Sprintf("Ensure IPs %s have reverse address %s.", iplist(ips), mox.Conf.Static.HostnameDomain.ASCII),
		}

		// If we have a socks transport, also check its host and IP.
		for tname, t := range mox.Conf.Static.Transports {
			if t.Socks != nil {
				hostIPs[t.Socks.Hostname] = append(hostIPs[t.Socks.Hostname], t.Socks.IPs...)
				instr := fmt.Sprintf("For SOCKS transport %s, ensure IPs %s have reverse address %s.", tname, iplist(t.Socks.IPs), t.Socks.Hostname)
				r.IPRev.Instructions = append(r.IPRev.Instructions, instr)
			}
		}

		type result struct {
			Host  dns.Domain
			IP    string
			Addrs []string
			Err   error
		}
		results := make(chan result)
		n := 0
		for host, ips := range hostIPs {
			for _, ip := range ips {
				n++
				s := ip.String()
				host := host
				go func() {
					addrs, _, err := resolver.LookupAddr(ctx, s)
					results <- result{host, s, addrs, err}
				}()
			}
		}
		r.IPRev.IPNames = map[string][]string{}
		for range n {
			lr := <-results
			host, addrs, ip, err := lr.Host, lr.Addrs, lr.IP, lr.Err
			if err != nil {
				addf(&r.IPRev.Errors, "Looking up reverse name for %s of %s: %v", ip, host, err)
				continue
			}
			var match bool
			for i, a := range addrs {
				a = strings.TrimRight(a, ".")
				addrs[i] = a
				ad, err := dns.ParseDomain(a)
				if err != nil {
					addf(&r.IPRev.Errors, "Parsing reverse name %q for %s: %v", a, ip, err)
				}
				if ad == host {
					match = true
				}
			}
			if !match && !isNAT && host == mox.Conf.Static.HostnameDomain {
				addf(&r.IPRev.Warnings, "IP %s with name(s) %s is forward confirmed, but does not match hostname %s.", ip, strings.Join(addrs, ","), host)
			}
			r.IPRev.IPNames[ip] = addrs
		}

		// Linux machines are often initially set up with a loopback IP for the hostname in
		// /etc/hosts, presumably because it isn't known if their external IPs are static.
		// For mail servers, they should certainly be static. The quickstart would also
		// have warned about this, but could have been missed/ignored.
		for _, ip := range ips {
			if ip.IsLoopback() {
				addf(&r.IPRev.Errors, "Hostname %s resolves to loopback IP %s, this will likely prevent email delivery to local accounts from working. The loopback IP was probably configured in /etc/hosts at system installation time. Replace the loopback IP with your actual external IPs in /etc/hosts.", mox.Conf.Static.HostnameDomain, ip.String())
			}
		}
	}()

	// MX
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		mxs, _, err := resolver.LookupMX(ctx, domain.ASCII+".")
		if err != nil {
			addf(&r.MX.Errors, "Looking up MX records for %s: %s", domain, err)
		}
		r.MX.Records = make([]MX, len(mxs))
		for i, mx := range mxs {
			r.MX.Records[i] = MX{mx.Host, int(mx.Pref), nil}
		}
		if len(mxs) == 1 && mxs[0].Host == "." {
			addf(&r.MX.Errors, `MX records consists of explicit null mx record (".") indicating that domain does not accept email.`)
			return
		}
		for i, mx := range mxs {
			ips, ourIPs, notOurIPs, err := lookupIPs(&r.MX.Errors, mx.Host)
			if err != nil {
				addf(&r.MX.Errors, "Looking up IPs for mx host %q: %s", mx.Host, err)
			}
			r.MX.Records[i].IPs = ips
			if isUnspecifiedNAT {
				continue
			}
			if len(ourIPs) == 0 {
				addf(&r.MX.Errors, "None of the IPs that mx %q points to is ours: %v", mx.Host, notOurIPs)
			} else if len(notOurIPs) > 0 {
				addf(&r.MX.Errors, "Some of the IPs that mx %q points to are not ours: %v", mx.Host, notOurIPs)
			}

		}
		r.MX.Instructions = []string{
			fmt.Sprintf("Ensure a DNS MX record like the following exists:\n\n\t%s MX 10 %s\n\nWithout the trailing dot, the name would be interpreted as relative to the domain.", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+"."),
		}
	}()

	// TLS, mostly checking certificate expiration and CA trust.
	// todo: should add checks about the listeners (which aren't specific to domains) somewhere else, not on the domain page with this checkDomain call. i.e. submissions, imap starttls, imaps.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// MTA-STS, autoconfig, autodiscover are checked in their sections.

		// Dial a single MX host with given IP and perform STARTTLS handshake.
		dialSMTPSTARTTLS := func(host, ip string) error {
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "25"))
			if err != nil {
				return err
			}
			defer func() {
				if conn != nil {
					err := conn.Close()
					log.Check(err, "closing tcp connection")
				}
			}()

			end := time.Now().Add(10 * time.Second)
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			err = conn.SetDeadline(end)
			log.WithContext(ctx).Check(err, "setting deadline")

			br := bufio.NewReader(conn)
			_, err = br.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading SMTP banner from remote: %s", err)
			}
			if _, err := fmt.Fprintf(conn, "EHLO moxtest\r\n"); err != nil {
				return fmt.Errorf("writing SMTP EHLO to remote: %s", err)
			}
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return fmt.Errorf("reading SMTP EHLO response from remote: %s", err)
				}
				if strings.HasPrefix(line, "250-") {
					continue
				}
				if strings.HasPrefix(line, "250 ") {
					break
				}
				return fmt.Errorf("unexpected response to SMTP EHLO from remote: %q", strings.TrimSuffix(line, "\r\n"))
			}
			if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
				return fmt.Errorf("writing SMTP STARTTLS to remote: %s", err)
			}
			line, err := br.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading response to SMTP STARTTLS from remote: %s", err)
			}
			if !strings.HasPrefix(line, "220 ") {
				return fmt.Errorf("SMTP STARTTLS response from remote not 220 OK: %q", strings.TrimSuffix(line, "\r\n"))
			}
			config := &tls.Config{
				ServerName: host,
				RootCAs:    mox.Conf.Static.TLS.CertPool,
			}
			tlsconn := tls.Client(conn, config)
			if err := tlsconn.HandshakeContext(cctx); err != nil {
				return fmt.Errorf("TLS handshake after SMTP STARTTLS: %s", err)
			}
			cancel()
			err = conn.Close()
			log.Check(err, "closing smtp connection")
			conn = nil
			return nil
		}

		checkSMTPSTARTTLS := func() {
			// Initial errors are ignored, will already have been warned about by MX checks.
			mxs, _, err := resolver.LookupMX(ctx, domain.ASCII+".")
			if err != nil {
				return
			}
			if len(mxs) == 1 && mxs[0].Host == "." {
				return
			}
			for _, mx := range mxs {
				ips, _, _, err := lookupIPs(&r.MX.Errors, mx.Host)
				if err != nil {
					continue
				}

				for _, ip := range ips {
					if err := dialSMTPSTARTTLS(mx.Host, ip); err != nil {
						addf(&r.TLS.Errors, "SMTP connection with STARTTLS to MX hostname %q IP %s: %s", mx.Host, ip, err)
					}
				}
			}
		}

		checkSMTPSTARTTLS()

	}()

	// DANE
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		daneRecords := func(l config.Listener) map[string]struct{} {
			if l.TLS == nil {
				return nil
			}
			records := map[string]struct{}{}
			addRecord := func(privKey crypto.Signer) {
				spkiBuf, err := x509.MarshalPKIXPublicKey(privKey.Public())
				if err != nil {
					addf(&r.DANE.Errors, "marshal SubjectPublicKeyInfo for DANE record: %v", err)
					return
				}
				sum := sha256.Sum256(spkiBuf)
				r := adns.TLSA{
					Usage:     adns.TLSAUsageDANEEE,
					Selector:  adns.TLSASelectorSPKI,
					MatchType: adns.TLSAMatchTypeSHA256,
					CertAssoc: sum[:],
				}
				records[r.Record()] = struct{}{}
			}
			for _, privKey := range l.TLS.HostPrivateRSA2048Keys {
				addRecord(privKey)
			}
			for _, privKey := range l.TLS.HostPrivateECDSAP256Keys {
				addRecord(privKey)
			}
			return records
		}

		expectedDANERecords := func(host string) map[string]struct{} {
			for _, l := range mox.Conf.Static.Listeners {
				if l.HostnameDomain.ASCII == host {
					return daneRecords(l)
				}
			}
			public := mox.Conf.Static.Listeners["public"]
			if mox.Conf.Static.HostnameDomain.ASCII == host && public.HostnameDomain.ASCII == "" {
				return daneRecords(public)
			}
			return nil
		}

		mxl, result, err := resolver.LookupMX(ctx, domain.ASCII+".")
		if err != nil {
			addf(&r.DANE.Errors, "Looking up MX hosts to check for DANE records: %s", err)
		} else {
			if !result.Authentic {
				addf(&r.DANE.Warnings, "DANE is inactive because MX records are not DNSSEC-signed.")
			}
			for _, mx := range mxl {
				expect := expectedDANERecords(mx.Host)

				tlsal, tlsaResult, err := resolver.LookupTLSA(ctx, 25, "tcp", mx.Host+".")
				if dns.IsNotFound(err) {
					if len(expect) > 0 {
						addf(&r.DANE.Errors, "No DANE records for MX host %s, expected: %s.", mx.Host, strings.Join(slices.Collect(maps.Keys(expect)), "; "))
					}
					continue
				} else if err != nil {
					addf(&r.DANE.Errors, "Looking up DANE records for MX host %s: %v", mx.Host, err)
					continue
				} else if !tlsaResult.Authentic && len(tlsal) > 0 {
					addf(&r.DANE.Errors, "DANE records exist for MX host %s, but are not DNSSEC-signed.", mx.Host)
				}

				extra := map[string]struct{}{}
				for _, e := range tlsal {
					s := e.Record()
					if _, ok := expect[s]; ok {
						delete(expect, s)
					} else {
						extra[s] = struct{}{}
					}
				}
				if len(expect) > 0 {
					l := slices.Sorted(maps.Keys(expect))
					addf(&r.DANE.Errors, "Missing DANE records of type TLSA for MX host _25._tcp.%s: %s", mx.Host, strings.Join(l, "; "))
				}
				if len(extra) > 0 {
					l := slices.Sorted(maps.Keys(extra))
					addf(&r.DANE.Errors, "Unexpected DANE records of type TLSA for MX host _25._tcp.%s: %s", mx.Host, strings.Join(l, "; "))
				}
			}
		}

		public := mox.Conf.Static.Listeners["public"]
		pubDom := public.HostnameDomain
		if pubDom.ASCII == "" {
			pubDom = mox.Conf.Static.HostnameDomain
		}
		records := slices.Sorted(maps.Keys(daneRecords(public)))
		if len(records) > 0 {
			instr := "Ensure the DNS records below exist. These records are for the whole machine, not per domain, so create them only once. Make sure DNSSEC is enabled, otherwise the records have no effect. The records indicate that a remote mail server trying to deliver email with SMTP (TCP port 25) must verify the TLS certificate with DANE-EE (3), based on the certificate public key (\"SPKI\", 1) that is SHA2-256-hashed (1) to the hexadecimal hash. DANE-EE verification means only the certificate or public key is verified, not whether the certificate is signed by a (centralized) certificate authority (CA), is expired, or matches the host name.\n\n"
			for _, r := range records {
				instr += fmt.Sprintf("\t_25._tcp.%s. TLSA %s\n", pubDom.ASCII, r)
			}
			addf(&r.DANE.Instructions, instr)
		} else {
			addf(&r.DANE.Warnings, "DANE not configured: no static TLS host keys.")

			instr := "Add static TLS keys for use with DANE to mox.conf under: Listeners, public, TLS, HostPrivateKeyFiles.\n\nIf automatic TLS certificate management with ACME is configured, run \"mox config ensureacmehostprivatekeys\" to generate static TLS keys and to print a snippet for \"HostPrivateKeyFiles\" for inclusion in mox.conf.\n\nIf TLS keys and certificates are managed externally, configure the TLS keys manually under \"HostPrivateKeyFiles\" in mox.conf, and make sure new TLS keys are not generated for each new certificate (look for an option to \"reuse private keys\" when doing ACME). Important: Before using new TLS keys, corresponding new DANE (TLSA) DNS records must be published (taking TTL into account to let the previous records expire). Using new TLS keys without updating DANE (TLSA) DNS records will cause DANE verification failures, breaking incoming deliveries.\n\nWith \"HostPrivateKeyFiles\" configured, DNS records for DANE based on those TLS keys will be suggested, and future DNS checks will look for those DNS records. Once those DNS records are published, DANE is active for all domains with an MX record pointing to the host."
			addf(&r.DANE.Instructions, instr)
		}
	}()

	// SPF
	// todo: add warnings if we have Transports with submission? admin should ensure their IPs are in the SPF record. it may be an IP(net), or an include. that means we cannot easily check for it. and should we first check the transport can be used from this domain (or an account that has this domain?). also see DKIM.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		ips := mox.DomainSPFIPs()

		// Verify a domain with the configured IPs that do SMTP.
		verifySPF := func(isHost bool, domain dns.Domain) (string, *SPFRecord, spf.Record) {
			kind := "domain"
			if isHost {
				kind = "host"
			}

			_, txt, record, _, err := spf.Lookup(ctx, log.Logger, resolver, domain)
			if err != nil {
				addf(&r.SPF.Errors, "Looking up %s SPF record: %s", kind, err)
			}
			var xrecord *SPFRecord
			if record != nil {
				xrecord = &SPFRecord{*record}
			}

			spfr := spf.Record{
				Version: "spf1",
			}

			checkSPFIP := func(ip net.IP) {
				mechanism := "ip4"
				if ip.To4() == nil {
					mechanism = "ip6"
				}
				spfr.Directives = append(spfr.Directives, spf.Directive{Mechanism: mechanism, IP: ip})

				if record == nil {
					return
				}

				args := spf.Args{
					RemoteIP:          ip,
					MailFromLocalpart: "postmaster",
					MailFromDomain:    domain,
					HelloDomain:       dns.IPDomain{Domain: domain},
					LocalIP:           net.ParseIP("127.0.0.1"),
					LocalHostname:     dns.Domain{ASCII: "localhost"},
				}
				status, mechanism, expl, _, err := spf.Evaluate(ctx, log.Logger, record, resolver, args)
				if err != nil {
					addf(&r.SPF.Errors, "Evaluating IP %q against %s SPF record: %s", ip, kind, err)
				} else if status != spf.StatusPass {
					addf(&r.SPF.Errors, "IP %q does not pass %s SPF evaluation, status not \"pass\" but %q (mechanism %q, explanation %q)", ip, kind, status, mechanism, expl)
				}
			}

			for _, ip := range ips {
				checkSPFIP(ip)
			}
			if !isHost {
				spfr.Directives = append(spfr.Directives, spf.Directive{Mechanism: "mx"})
			}

			qual := "~"
			if isHost {
				qual = "-"
			}
			spfr.Directives = append(spfr.Directives, spf.Directive{Qualifier: qual, Mechanism: "all"})
			return txt, xrecord, spfr
		}

		// Check SPF record for domain.
		var dspfr spf.Record
		r.SPF.DomainTXT, r.SPF.DomainRecord, dspfr = verifySPF(false, domain)
		// todo: possibly check all hosts for MX records? assuming they are also sending mail servers.
		r.SPF.HostTXT, r.SPF.HostRecord, _ = verifySPF(true, mox.Conf.Static.HostnameDomain)

		if len(ips) == 0 {
			addf(&r.SPF.Warnings, `No explicitly configured IPs found to check SPF policy against. Consider configuring public IPs instead of unspecified addresses (0.0.0.0 and/or ::) in the "public" listener in mox.conf, or NATIPs in case of NAT.`)
		}

		dtxt, err := dspfr.Record()
		if err != nil {
			addf(&r.SPF.Errors, "Making SPF record for instructions: %s", err)
		}
		domainspf := fmt.Sprintf("%s TXT %s", domain.ASCII+".", mox.TXTStrings(dtxt))

		// Check SPF record for sending host. ../rfc/7208:2263 ../rfc/7208:2287
		hostspf := fmt.Sprintf(`%s TXT "v=spf1 a -all"`, mox.Conf.Static.HostnameDomain.ASCII+".")

		addf(&r.SPF.Instructions, "Ensure DNS TXT records like the following exists:\n\n\t%s\n\t%s\n\nIf you have an existing mail setup, with other hosts also sending mail for you domain, you should add those IPs as well. You could replace \"-all\" with \"~all\" to treat mail sent from unlisted IPs as \"softfail\", or with \"?all\" for \"neutral\".", domainspf, hostspf)
	}()

	// DKIM
	// todo: add warnings if we have Transports with submission? admin should ensure DKIM records exist. we cannot easily check if they actually exist though. and should we first check the transport can be used from this domain (or an account that has this domain?). also see SPF.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		var missing []string
		for sel, selc := range domConf.DKIM.Selectors {
			_, record, txt, _, err := dkim.Lookup(ctx, log.Logger, resolver, selc.Domain, domain)
			if err != nil {
				missing = append(missing, sel)
				if errors.Is(err, dkim.ErrNoRecord) {
					addf(&r.DKIM.Errors, "No DKIM DNS record for selector %q.", sel)
				} else if errors.Is(err, dkim.ErrSyntax) {
					addf(&r.DKIM.Errors, "Parsing DKIM DNS record for selector %q: %s", sel, err)
				} else {
					addf(&r.DKIM.Errors, "Fetching DKIM record for selector %q: %s", sel, err)
				}
			}
			if txt != "" {
				r.DKIM.Records = append(r.DKIM.Records, DKIMRecord{sel, txt, record})
				pubKey := selc.Key.Public()
				var pk []byte
				switch k := pubKey.(type) {
				case *rsa.PublicKey:
					var err error
					pk, err = x509.MarshalPKIXPublicKey(k)
					if err != nil {
						addf(&r.DKIM.Errors, "Marshal public key for %q to compare against DNS: %s", sel, err)
						continue
					}
				case ed25519.PublicKey:
					pk = []byte(k)
				default:
					addf(&r.DKIM.Errors, "Internal error: unknown public key type %T.", pubKey)
					continue
				}

				if record != nil && !bytes.Equal(record.Pubkey, pk) {
					addf(&r.DKIM.Errors, "For selector %q, the public key in DKIM DNS TXT record does not match with configured private key.", sel)
					missing = append(missing, sel)
				}
			}
		}
		if len(domConf.DKIM.Selectors) == 0 {
			addf(&r.DKIM.Errors, "No DKIM configuration, add a key to the configuration file, and instructions for DNS records will appear here.")
		}
		instr := ""
		for _, sel := range missing {
			dkimr := dkim.Record{
				Version:   "DKIM1",
				Hashes:    []string{"sha256"},
				PublicKey: domConf.DKIM.Selectors[sel].Key.Public(),
			}
			switch dkimr.PublicKey.(type) {
			case *rsa.PublicKey:
			case ed25519.PublicKey:
				dkimr.Key = "ed25519"
			default:
				addf(&r.DKIM.Errors, "Internal error: unknown public key type %T.", dkimr.PublicKey)
			}
			txt, err := dkimr.Record()
			if err != nil {
				addf(&r.DKIM.Errors, "Making DKIM record for instructions: %s", err)
				continue
			}
			instr += fmt.Sprintf("\n\t%s._domainkey.%s TXT %s\n", sel, domain.ASCII+".", mox.TXTStrings(txt))
		}
		if instr != "" {
			instr = "Ensure the following DNS record(s) exists, so mail servers receiving emails from this domain can verify the signatures in the mail headers:\n" + instr
			addf(&r.DKIM.Instructions, "%s", instr)
		}
	}()

	// DMARC
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		_, dmarcDomain, record, txt, _, err := dmarc.Lookup(ctx, log.Logger, resolver, domain)
		if err != nil {
			addf(&r.DMARC.Errors, "Looking up DMARC record: %s", err)
		} else if record == nil {
			addf(&r.DMARC.Errors, "No DMARC record")
		}
		r.DMARC.Domain = dmarcDomain.Name()
		r.DMARC.TXT = txt
		if record != nil {
			r.DMARC.Record = &DMARCRecord{*record}
		}
		if record != nil && record.Policy == "none" {
			addf(&r.DMARC.Warnings, "DMARC policy is in test mode (p=none), do not forget to change to p=reject or p=quarantine after test period has been completed.")
		}
		if record != nil && record.SubdomainPolicy == "none" {
			addf(&r.DMARC.Warnings, "DMARC subdomain policy is in test mode (sp=none), do not forget to change to sp=reject or sp=quarantine after test period has been completed.")
		}
		if record != nil && len(record.AggregateReportAddresses) == 0 {
			addf(&r.DMARC.Warnings, "It is recommended you specify you would like aggregate reports about delivery success in the DMARC record, see instructions.")
		}

		dmarcr := dmarc.DefaultRecord
		dmarcr.Policy = "reject"

		var extInstr string
		if domConf.DMARC != nil {
			// If the domain is in a different Organizational Domain, the receiving domain
			// needs a special DNS record to opt-in to receiving reports. We check for that
			// record.
			// ../rfc/7489:1541
			orgDom := publicsuffix.Lookup(ctx, log.Logger, domain)
			destOrgDom := publicsuffix.Lookup(ctx, log.Logger, domConf.DMARC.DNSDomain)
			if orgDom != destOrgDom {
				accepts, status, _, _, _, err := dmarc.LookupExternalReportsAccepted(ctx, log.Logger, resolver, domain, domConf.DMARC.DNSDomain)
				if status != dmarc.StatusNone {
					addf(&r.DMARC.Errors, "Checking if external destination accepts reports: %s", err)
				} else if !accepts {
					addf(&r.DMARC.Errors, "External destination does not accept reports (%s)", err)
				}
				extInstr = fmt.Sprintf("Ensure a DNS TXT record exists in the domain of the destination address to opt-in to receiving reports from this domain:\n\n\t%s._report._dmarc.%s. TXT \"v=DMARC1;\"\n\n", domain.ASCII, domConf.DMARC.DNSDomain.ASCII)
			}

			uri := url.URL{
				Scheme: "mailto",
				Opaque: smtp.NewAddress(domConf.DMARC.ParsedLocalpart, domConf.DMARC.DNSDomain).Pack(false),
			}
			uristr := uri.String()
			dmarcr.AggregateReportAddresses = []dmarc.URI{
				{Address: uristr, MaxSize: 10, Unit: "m"},
			}

			if record != nil {
				found := false
				for _, addr := range record.AggregateReportAddresses {
					if addr.Address == uristr {
						found = true
						break
					}
				}
				if !found {
					addf(&r.DMARC.Errors, "Configured DMARC reporting address is not present in record.")
				}
			}
		} else {
			addf(&r.DMARC.Instructions, `Configure a DMARC destination in domain in config file.`)
		}
		instr := fmt.Sprintf("Ensure a DNS TXT record like the following exists:\n\n\t_dmarc.%s TXT %s\n\nYou can start with testing mode by replacing p=reject with p=none. You can also request for the policy to be applied to a percentage of emails instead of all, by adding pct=X, with X between 0 and 100. Keep in mind that receiving mail servers will apply some anti-spam assessment regardless of the policy and whether it is applied to the message. The ruf= part requests daily aggregate reports to be sent to the specified address, which is automatically configured and reports automatically analyzed.", domain.ASCII+".", mox.TXTStrings(dmarcr.String()))
		addf(&r.DMARC.Instructions, instr)
		if extInstr != "" {
			addf(&r.DMARC.Instructions, extInstr)
		}
	}()

	checkTLSRPT := func(result *TLSRPTCheckResult, dom dns.Domain, address smtp.Address, isHost bool) {
		defer logPanic(ctx)
		defer wg.Done()

		record, txt, err := tlsrpt.Lookup(ctx, log.Logger, resolver, dom)
		if err != nil {
			addf(&result.Errors, "Looking up TLSRPT record for domain %s: %s", dom, err)
		}
		result.TXT = txt
		if record != nil {
			result.Record = &TLSRPTRecord{*record}
		}

		instr := `TLSRPT is an opt-in mechanism to request feedback about TLS connectivity from remote SMTP servers when they connect to us. It allows detecting delivery problems and unwanted downgrades to plaintext SMTP connections. With TLSRPT you configure an email address to which reports should be sent. Remote SMTP servers will send a report once a day with the number of successful connections, and the number of failed connections including details that should help debugging/resolving any issues. Both the mail host (e.g. mail.domain.example) and a recipient domain (e.g. domain.example, with an MX record pointing to mail.domain.example) can have a TLSRPT record. The TLSRPT record for the hosts is for reporting about DANE, the TLSRPT record for the domain is for MTA-STS.`
		var zeroaddr smtp.Address
		if address != zeroaddr {
			// TLSRPT does not require validation of reporting addresses outside the domain.
			// ../rfc/8460:1463
			uri := url.URL{
				Scheme: "mailto",
				Opaque: address.Pack(false),
			}
			rua := tlsrpt.RUA(uri.String())
			tlsrptr := &tlsrpt.Record{
				Version: "TLSRPTv1",
				RUAs:    [][]tlsrpt.RUA{{rua}},
			}
			instr += fmt.Sprintf(`

Ensure a DNS TXT record like the following exists:

	_smtp._tls.%s TXT %s

`, dom.ASCII+".", mox.TXTStrings(tlsrptr.String()))

			if err == nil {
				found := false
			RUA:
				for _, l := range record.RUAs {
					for _, e := range l {
						if e == rua {
							found = true
							break RUA
						}
					}
				}
				if !found {
					addf(&result.Errors, `Configured reporting address is not present in TLSRPT record.`)
				}
			}

		} else if isHost {
			instr += fmt.Sprintf(`

Ensure the following snippet is present in mox.conf (ensure tabs are used for indenting, not spaces):

HostTLSRPT:
	Account: %s
	Mailbox: TLSRPT
	Localpart: tlsrpt

`, mox.Conf.Static.Postmaster.Account)
			addf(&result.Errors, `Configure a HostTLSRPT section in the static mox.conf config file, restart mox and check again for instructions for the TLSRPT DNS record.`)
		} else {
			addf(&result.Errors, `Configure a TLSRPT destination for the domain (through the admin web interface or by editing the domains.conf config file, adding a TLSRPT section) and check again for instructions for the TLSRPT DNS record.`)
		}
		addf(&result.Instructions, instr)
	}

	// Host TLSRPT
	wg.Add(1)
	var hostTLSRPTAddr smtp.Address
	if mox.Conf.Static.HostTLSRPT.Localpart != "" {
		hostTLSRPTAddr = smtp.NewAddress(mox.Conf.Static.HostTLSRPT.ParsedLocalpart, mox.Conf.Static.HostnameDomain)
	}
	go checkTLSRPT(&r.HostTLSRPT, mox.Conf.Static.HostnameDomain, hostTLSRPTAddr, true)

	// Domain TLSRPT
	wg.Add(1)
	var domainTLSRPTAddr smtp.Address
	if domConf.TLSRPT != nil {
		domainTLSRPTAddr = smtp.NewAddress(domConf.TLSRPT.ParsedLocalpart, domain)
	}
	go checkTLSRPT(&r.DomainTLSRPT, domain, domainTLSRPTAddr, false)

	// MTA-STS
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// The admin has explicitly disabled mta-sts, keep warning about it.
		if domConf.MTASTS == nil {
			addf(&r.MTASTS.Warnings, "MTA-STS is not configured for this domain.")
		}

		record, txt, err := mtasts.LookupRecord(ctx, log.Logger, resolver, domain)
		if err != nil && !(domConf.MTASTS == nil && errors.Is(err, mtasts.ErrNoRecord)) {
			addf(&r.MTASTS.Errors, "Looking up MTA-STS record: %s", err)
		}
		r.MTASTS.TXT = txt
		if record != nil {
			r.MTASTS.Record = &MTASTSRecord{*record}
		}

		policy, text, err := mtasts.FetchPolicy(ctx, log.Logger, domain)
		if err != nil {
			if !(domConf.MTASTS == nil && errors.Is(err, mtasts.ErrNoPolicy)) {
				addf(&r.MTASTS.Errors, "Fetching MTA-STS policy: %s", err)
			}
		} else if policy.Mode == mtasts.ModeNone {
			addf(&r.MTASTS.Warnings, "MTA-STS policy is present, but does not require TLS.")
		} else if policy.Mode == mtasts.ModeTesting {
			addf(&r.MTASTS.Warnings, "MTA-STS policy is in testing mode, do not forget to change to mode enforce after testing period.")
		}
		r.MTASTS.PolicyText = text
		r.MTASTS.Policy = policy
		if policy != nil && policy.Mode != mtasts.ModeNone {
			if !policy.Matches(mox.Conf.Static.HostnameDomain) {
				addf(&r.MTASTS.Warnings, "Configured hostname is missing from policy MX list.")
			}
			if policy.MaxAgeSeconds <= 24*3600 {
				addf(&r.MTASTS.Warnings, "Policy has a MaxAge of less than 1 day. For stable configurations, the recommended period is in weeks.")
			}

			mxl, _, _ := resolver.LookupMX(ctx, domain.ASCII+".")
			// We do not check for errors, the MX check will complain about mx errors, we assume we will get the same error here.
			mxs := map[dns.Domain]struct{}{}
			for _, mx := range mxl {
				d, err := dns.ParseDomain(strings.TrimSuffix(mx.Host, "."))
				if err != nil {
					addf(&r.MTASTS.Warnings, "MX record %q is invalid: %s", mx.Host, err)
					continue
				}
				mxs[d] = struct{}{}
			}
			for mx := range mxs {
				if !policy.Matches(mx) {
					addf(&r.MTASTS.Warnings, "MX record %q does not match MTA-STS policy MX list.", mx)
				}
			}
			for _, mx := range policy.MX {
				if mx.Wildcard {
					continue
				}
				if _, ok := mxs[mx.Domain]; !ok {
					addf(&r.MTASTS.Warnings, "MX %q in MTA-STS policy is not in MX record.", mx)
				}
			}
		}

		intro := `MTA-STS is an opt-in mechanism to signal to remote SMTP servers which MX records are valid and that they must use the STARTTLS command and verify the TLS connection. Email servers should already be using STARTTLS to protect communication, but active attackers can, and have in the past, removed the indication of support for the optional STARTTLS support from SMTP sessions, or added additional MX records in DNS responses. MTA-STS protects against compromised DNS and compromised plaintext SMTP sessions, but not against compromised internet PKI infrastructure. If an attacker controls a certificate authority, and is willing to use it, MTA-STS does not prevent an attack. MTA-STS does not protect against attackers on first contact with a domain. Only on subsequent contacts, with MTA-STS policies in the cache, can attacks can be detected.

After enabling MTA-STS for this domain, remote SMTP servers may still deliver in plain text, without TLS-protection. MTA-STS is an opt-in mechanism, not all servers support it yet.

You can opt-in to MTA-STS by creating a DNS record, _mta-sts.<domain>, and serving a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt. Mox will serve the policy, you must create the DNS records.

You can start with a policy in "testing" mode. Remote SMTP servers will apply the MTA-STS policy, but not abort delivery in case of failure. Instead, you will receive a report if you have TLSRPT configured. By starting in testing mode for a representative period, verifying all mail can be deliverd, you can safely switch to "enforce" mode. While in enforce mode, plaintext deliveries to mox are refused.

The _mta-sts DNS TXT record has an "id" field. The id serves as a version of the policy. A policy specifies the mode: none, testing, enforce. For "none", no TLS is required. A policy has a "max age", indicating how long the policy can be cached. Allowing the policy to be cached for a long time provides stronger counter measures to active attackers, but reduces configuration change agility. After enabling "enforce" mode, remote SMTP servers may and will cache your policy for as long as "max age" was configured. Keep this in mind when enabling/disabling MTA-STS. To disable MTA-STS after having it enabled, publish a new record with mode "none" until all past policy expiration times have passed.

When enabling MTA-STS, or updating a policy, always update the policy first (through a configuration change and reload/restart), and the DNS record second.
`
		addf(&r.MTASTS.Instructions, intro)

		addf(&r.MTASTS.Instructions, `Enable a policy through the configuration file. For new deployments, it is best to start with mode "testing" while enabling TLSRPT. Start with a short "max_age", so updates to your policy are picked up quickly. When confidence in the deployment is high enough, switch to "enforce" mode and a longer "max age". A max age in the order of weeks is recommended. If you foresee a change to your setup in the future, requiring different policies or MX records, you may want to dial back the "max age" ahead of time, similar to how you would handle TTL's in DNS record updates.`)

		host := fmt.Sprintf("Ensure DNS CNAME/A/AAAA records exist that resolves mta-sts.%s to this mail server. For example:\n\n\tmta-sts.%s CNAME %s\n\n", domain.ASCII, domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")
		addf(&r.MTASTS.Instructions, host)

		mtastsr := mtasts.Record{
			Version: "STSv1",
			ID:      time.Now().Format("20060102T150405"),
		}
		dns := fmt.Sprintf("Ensure a DNS TXT record like the following exists:\n\n\t_mta-sts.%s TXT %s\n\nConfigure the ID in the configuration file, it must be of the form [a-zA-Z0-9]{1,31}. It represents the version of the policy. For each policy change, you must change the ID to a new unique value. You could use a timestamp like 20220621T123000. When this field exists, an SMTP server will fetch a policy at https://mta-sts.%s/.well-known/mta-sts.txt. This policy is served by mox.", domain.ASCII+".", mox.TXTStrings(mtastsr.String()), domain.Name())
		addf(&r.MTASTS.Instructions, dns)
	}()

	// SRVConf
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		type srvReq struct {
			name string
			port uint16
			host string
			srvs []*net.SRV
			err  error
		}

		// We'll assume if any submissions is configured, it is public. Same for imap. And
		// if not, that there is a plain option.
		var submissions, imaps bool
		for _, l := range mox.Conf.Static.Listeners {
			if l.TLS != nil && l.Submissions.Enabled {
				submissions = true
			}
			if l.TLS != nil && l.IMAPS.Enabled {
				imaps = true
			}
		}
		srvhost := func(ok bool) string {
			if ok {
				return mox.Conf.Static.HostnameDomain.ASCII + "."
			}
			return "."
		}
		var reqs = []srvReq{
			{name: "_submissions", port: 465, host: srvhost(submissions)},
			{name: "_submission", port: 587, host: srvhost(!submissions)},
			{name: "_imaps", port: 993, host: srvhost(imaps)},
			{name: "_imap", port: 143, host: srvhost(!imaps)},
			{name: "_pop3", port: 110, host: "."},
			{name: "_pop3s", port: 995, host: "."},
		}
		// Host "." indicates the service is not available. We suggested in the DNS records
		// that the port be set to 0, so check for that. ../rfc/6186:242
		for i := range reqs {
			if reqs[i].host == "." {
				reqs[i].port = 0
			}
		}
		var srvwg sync.WaitGroup
		srvwg.Add(len(reqs))
		for i := range reqs {
			go func(i int) {
				defer srvwg.Done()
				_, reqs[i].srvs, _, reqs[i].err = resolver.LookupSRV(ctx, reqs[i].name[1:], "tcp", domain.ASCII+".")
			}(i)
		}
		srvwg.Wait()

		instr := "Ensure DNS records like the following exist:\n\n"
		r.SRVConf.SRVs = map[string][]net.SRV{}
		for _, req := range reqs {
			name := req.name + "._tcp." + domain.ASCII
			weight := 1
			if req.host == "." {
				weight = 0
			}
			instr += fmt.Sprintf("\t%s._tcp.%-*s SRV 0 %d %d %s\n", req.name, len("_submissions")-len(req.name)+len(domain.ASCII+"."), domain.ASCII+".", weight, req.port, req.host)
			r.SRVConf.SRVs[req.name] = unptr(req.srvs)
			if req.err != nil {
				addf(&r.SRVConf.Errors, "Looking up SRV record %q: %s", name, req.err)
			} else if len(req.srvs) == 0 {
				if req.host == "." {
					addf(&r.SRVConf.Warnings, "Missing optional SRV record %q", name)
				} else {
					addf(&r.SRVConf.Errors, "Missing SRV record %q", name)
				}
			} else if len(req.srvs) != 1 || req.srvs[0].Target != req.host || req.srvs[0].Port != req.port {
				var srvs []string
				for _, srv := range req.srvs {
					srvs = append(srvs, fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target))
				}
				addf(&r.SRVConf.Errors, "Unexpected SRV record(s) for %q: %s", name, strings.Join(srvs, ", "))
			}
		}
		addf(&r.SRVConf.Instructions, instr)
	}()

	// Autoconf
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		if domConf.ClientSettingsDomain != "" {
			addf(&r.Autoconf.Instructions, "Ensure a DNS CNAME record like the following exists:\n\n\t%s CNAME %s\n\nNote: the trailing dot is relevant, it makes the host name absolute instead of relative to the domain name.", domConf.ClientSettingsDNSDomain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")

			ips, ourIPs, notOurIPs, err := lookupIPs(&r.Autoconf.Errors, domConf.ClientSettingsDNSDomain.ASCII+".")
			if err != nil {
				addf(&r.Autoconf.Errors, "Looking up client settings DNS CNAME: %s", err)
			}
			r.Autoconf.ClientSettingsDomainIPs = ips
			if !isUnspecifiedNAT {
				if len(ourIPs) == 0 {
					addf(&r.Autoconf.Errors, "Client settings domain does not point to one of our IPs.")
				} else if len(notOurIPs) > 0 {
					addf(&r.Autoconf.Errors, "Client settings domain points to some IPs that are not ours: %v", notOurIPs)
				}
			}
		}

		addf(&r.Autoconf.Instructions, "Ensure a DNS CNAME record like the following exists:\n\n\tautoconfig.%s CNAME %s\n\nNote: the trailing dot is relevant, it makes the host name absolute instead of relative to the domain name.", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")

		host := "autoconfig." + domain.ASCII + "."
		ips, ourIPs, notOurIPs, err := lookupIPs(&r.Autoconf.Errors, host)
		if err != nil {
			addf(&r.Autoconf.Errors, "Looking up autoconfig host: %s", err)
			return
		}

		r.Autoconf.IPs = ips
		if !isUnspecifiedNAT {
			if len(ourIPs) == 0 {
				addf(&r.Autoconf.Errors, "Autoconfig does not point to one of our IPs.")
			} else if len(notOurIPs) > 0 {
				addf(&r.Autoconf.Errors, "Autoconfig points to some IPs that are not ours: %v", notOurIPs)
			}
		}

		checkTLS(&r.Autoconf.Errors, "autoconfig."+domain.ASCII, ips, "443")
	}()

	// Autodiscover
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		addf(&r.Autodiscover.Instructions, "Ensure DNS records like the following exist:\n\n\t_autodiscover._tcp.%s SRV 0 1 443 %s\n\tautoconfig.%s CNAME %s\n\nNote: the trailing dots are relevant, it makes the host names absolute instead of relative to the domain name.", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")

		_, srvs, _, err := resolver.LookupSRV(ctx, "autodiscover", "tcp", domain.ASCII+".")
		if err != nil {
			addf(&r.Autodiscover.Errors, "Looking up SRV record %q: %s", "autodiscover", err)
			return
		}
		match := false
		for _, srv := range srvs {
			ips, ourIPs, notOurIPs, err := lookupIPs(&r.Autodiscover.Errors, srv.Target)
			if err != nil {
				addf(&r.Autodiscover.Errors, "Looking up target %q from SRV record: %s", srv.Target, err)
				continue
			}
			if srv.Port != 443 {
				continue
			}
			match = true
			r.Autodiscover.Records = append(r.Autodiscover.Records, AutodiscoverSRV{*srv, ips})
			if !isUnspecifiedNAT {
				if len(ourIPs) == 0 {
					addf(&r.Autodiscover.Errors, "SRV target %q does not point to our IPs.", srv.Target)
				} else if len(notOurIPs) > 0 {
					addf(&r.Autodiscover.Errors, "SRV target %q points to some IPs that are not ours: %v", srv.Target, notOurIPs)
				}
			}

			checkTLS(&r.Autodiscover.Errors, strings.TrimSuffix(srv.Target, "."), ips, "443")
		}
		if !match {
			addf(&r.Autodiscover.Errors, "No SRV record for port 443 for https.")
		}
	}()

	wg.Wait()
	return
}

// Domains returns all configured domain names.
func (Admin) Domains(ctx context.Context) []config.Domain {
	return mox.Conf.DomainConfigs()
}

// Domain returns the dns domain for a (potentially unicode as IDNA) domain name.
func (Admin) Domain(ctx context.Context, domain string) dns.Domain {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parse domain")
	_, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("no such domain"), "looking up domain")
	}
	return d
}

// ParseDomain parses a domain, possibly an IDNA domain.
func (Admin) ParseDomain(ctx context.Context, domain string) dns.Domain {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parse domain")
	return d
}

// DomainConfig returns the configuration for a domain.
func (Admin) DomainConfig(ctx context.Context, domain string) config.Domain {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parse domain")
	conf, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("no such domain"), "looking up domain")
	}
	return conf
}

// DomainLocalparts returns the encoded localparts and accounts configured in domain.
func (Admin) DomainLocalparts(ctx context.Context, domain string) (localpartAccounts map[string]string, localpartAliases map[string]config.Alias) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")
	_, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("no such domain"), "looking up domain")
	}
	return mox.Conf.DomainLocalparts(d)
}

// Accounts returns the names of all configured and all disabled accounts.
func (Admin) Accounts(ctx context.Context) (all, disabled []string) {
	all, disabled = mox.Conf.AccountsDisabled()
	slices.Sort(all)
	return
}

// Account returns the parsed configuration of an account.
func (Admin) Account(ctx context.Context, account string) (accountConfig config.Account, diskUsage int64) {
	log := pkglog.WithContext(ctx)

	acc, err := store.OpenAccount(log, account, false)
	if err != nil && errors.Is(err, store.ErrAccountUnknown) {
		xcheckuserf(ctx, err, "looking up account")
	}
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	var ac config.Account
	acc.WithRLock(func() {
		ac, _ = mox.Conf.Account(acc.Name)

		err := acc.DB.Read(ctx, func(tx *bstore.Tx) error {
			du := store.DiskUsage{ID: 1}
			err := tx.Get(&du)
			diskUsage = du.MessageSize
			return err
		})
		xcheckf(ctx, err, "get disk usage")
	})

	return ac, diskUsage
}

// ConfigFiles returns the paths and contents of the static and dynamic configuration files.
func (Admin) ConfigFiles(ctx context.Context) (staticPath, dynamicPath, static, dynamic string) {
	buf0, err := os.ReadFile(mox.ConfigStaticPath)
	xcheckf(ctx, err, "read static config file")
	buf1, err := os.ReadFile(mox.ConfigDynamicPath)
	xcheckf(ctx, err, "read dynamic config file")
	return mox.ConfigStaticPath, mox.ConfigDynamicPath, string(buf0), string(buf1)
}

// MTASTSPolicies returns all mtasts policies from the cache.
func (Admin) MTASTSPolicies(ctx context.Context) (records []mtastsdb.PolicyRecord) {
	records, err := mtastsdb.PolicyRecords(ctx)
	xcheckf(ctx, err, "fetching mtasts policies from database")
	return records
}

// TLSReports returns TLS reports overlapping with period start/end, for the given
// policy domain (or all domains if empty). The reports are sorted first by period
// end (most recent first), then by policy domain.
func (Admin) TLSReports(ctx context.Context, start, end time.Time, policyDomain string) (reports []tlsrptdb.Record) {
	var polDom dns.Domain
	if policyDomain != "" {
		var err error
		polDom, err = dns.ParseDomain(policyDomain)
		xcheckuserf(ctx, err, "parsing domain %q", policyDomain)
	}

	records, err := tlsrptdb.RecordsPeriodDomain(ctx, start, end, polDom)
	xcheckf(ctx, err, "fetching tlsrpt report records from database")
	sort.Slice(records, func(i, j int) bool {
		iend := records[i].Report.DateRange.End
		jend := records[j].Report.DateRange.End
		if iend == jend {
			return records[i].Domain < records[j].Domain
		}
		return iend.After(jend)
	})
	return records
}

// TLSReportID returns a single TLS report.
func (Admin) TLSReportID(ctx context.Context, domain string, reportID int64) tlsrptdb.Record {
	record, err := tlsrptdb.RecordID(ctx, reportID)
	if err == nil && record.Domain != domain {
		err = bstore.ErrAbsent
	}
	if err == bstore.ErrAbsent {
		xcheckuserf(ctx, err, "fetching tls report from database")
	}
	xcheckf(ctx, err, "fetching tls report from database")
	return record
}

// TLSRPTSummary presents TLS reporting statistics for a single domain
// over a period.
type TLSRPTSummary struct {
	PolicyDomain     dns.Domain
	Success          int64
	Failure          int64
	ResultTypeCounts map[tlsrpt.ResultType]int64
}

// TLSRPTSummaries returns a summary of received TLS reports overlapping with
// period start/end for one or all domains (when domain is empty).
// The returned summaries are ordered by domain name.
func (Admin) TLSRPTSummaries(ctx context.Context, start, end time.Time, policyDomain string) (domainSummaries []TLSRPTSummary) {
	var polDom dns.Domain
	if policyDomain != "" {
		var err error
		polDom, err = dns.ParseDomain(policyDomain)
		xcheckuserf(ctx, err, "parsing policy domain")
	}
	reports, err := tlsrptdb.RecordsPeriodDomain(ctx, start, end, polDom)
	xcheckf(ctx, err, "fetching tlsrpt reports from database")

	summaries := map[dns.Domain]TLSRPTSummary{}
	for _, r := range reports {
		dom, err := dns.ParseDomain(r.Domain)
		xcheckf(ctx, err, "parsing domain %q", r.Domain)

		sum := summaries[dom]
		sum.PolicyDomain = dom
		for _, result := range r.Report.Policies {
			sum.Success += result.Summary.TotalSuccessfulSessionCount
			sum.Failure += result.Summary.TotalFailureSessionCount
			for _, details := range result.FailureDetails {
				if sum.ResultTypeCounts == nil {
					sum.ResultTypeCounts = map[tlsrpt.ResultType]int64{}
				}
				sum.ResultTypeCounts[details.ResultType] += details.FailedSessionCount
			}
		}
		summaries[dom] = sum
	}
	sums := make([]TLSRPTSummary, 0, len(summaries))
	for _, sum := range summaries {
		sums = append(sums, sum)
	}
	sort.Slice(sums, func(i, j int) bool {
		return sums[i].PolicyDomain.Name() < sums[j].PolicyDomain.Name()
	})
	return sums
}

// DMARCReports returns DMARC reports overlapping with period start/end, for the
// given domain (or all domains if empty). The reports are sorted first by period
// end (most recent first), then by domain.
func (Admin) DMARCReports(ctx context.Context, start, end time.Time, domain string) (reports []dmarcdb.DomainFeedback) {
	reports, err := dmarcdb.RecordsPeriodDomain(ctx, start, end, domain)
	xcheckf(ctx, err, "fetching dmarc aggregate reports from database")
	sort.Slice(reports, func(i, j int) bool {
		iend := reports[i].ReportMetadata.DateRange.End
		jend := reports[j].ReportMetadata.DateRange.End
		if iend == jend {
			return reports[i].Domain < reports[j].Domain
		}
		return iend > jend
	})
	return reports
}

// DMARCReportID returns a single DMARC report.
func (Admin) DMARCReportID(ctx context.Context, domain string, reportID int64) (report dmarcdb.DomainFeedback) {
	report, err := dmarcdb.RecordID(ctx, reportID)
	if err == nil && report.Domain != domain {
		err = bstore.ErrAbsent
	}
	if err == bstore.ErrAbsent {
		xcheckuserf(ctx, err, "fetching dmarc aggregate report from database")
	}
	xcheckf(ctx, err, "fetching dmarc aggregate report from database")
	return report
}

// DMARCSummary presents DMARC aggregate reporting statistics for a single domain
// over a period.
type DMARCSummary struct {
	Domain                string
	Total                 int
	DispositionNone       int
	DispositionQuarantine int
	DispositionReject     int
	DKIMFail              int
	SPFFail               int
	PolicyOverrides       map[dmarcrpt.PolicyOverride]int
}

// DMARCSummaries returns a summary of received DMARC reports overlapping with
// period start/end for one or all domains (when domain is empty).
// The returned summaries are ordered by domain name.
func (Admin) DMARCSummaries(ctx context.Context, start, end time.Time, domain string) (domainSummaries []DMARCSummary) {
	reports, err := dmarcdb.RecordsPeriodDomain(ctx, start, end, domain)
	xcheckf(ctx, err, "fetching dmarc aggregate reports from database")
	summaries := map[string]DMARCSummary{}
	for _, r := range reports {
		sum := summaries[r.Domain]
		sum.Domain = r.Domain
		for _, record := range r.Records {
			n := record.Row.Count

			sum.Total += n

			switch record.Row.PolicyEvaluated.Disposition {
			case dmarcrpt.DispositionNone:
				sum.DispositionNone += n
			case dmarcrpt.DispositionQuarantine:
				sum.DispositionQuarantine += n
			case dmarcrpt.DispositionReject:
				sum.DispositionReject += n
			}

			if record.Row.PolicyEvaluated.DKIM == dmarcrpt.DMARCFail {
				sum.DKIMFail += n
			}
			if record.Row.PolicyEvaluated.SPF == dmarcrpt.DMARCFail {
				sum.SPFFail += n
			}

			for _, reason := range record.Row.PolicyEvaluated.Reasons {
				if sum.PolicyOverrides == nil {
					sum.PolicyOverrides = map[dmarcrpt.PolicyOverride]int{}
				}
				sum.PolicyOverrides[reason.Type] += n
			}
		}
		summaries[r.Domain] = sum
	}
	sums := make([]DMARCSummary, 0, len(summaries))
	for _, sum := range summaries {
		sums = append(sums, sum)
	}
	sort.Slice(sums, func(i, j int) bool {
		return sums[i].Domain < sums[j].Domain
	})
	return sums
}

// Reverse is the result of a reverse lookup.
type Reverse struct {
	Hostnames []string

	// In the future, we can add a iprev-validated host name, and possibly the IPs of the host names.
}

// LookupIP does a reverse lookup of ip.
func (Admin) LookupIP(ctx context.Context, ip string) Reverse {
	resolver := dns.StrictResolver{Pkg: "webadmin", Log: pkglog.WithContext(ctx).Logger}
	names, _, err := resolver.LookupAddr(ctx, ip)
	xcheckuserf(ctx, err, "looking up ip")
	return Reverse{names}
}

// DNSBLStatus returns the IPs from which outgoing connections may be made and
// their current status in DNSBLs that are configured. The IPs are typically the
// configured listen IPs, or otherwise IPs on the machines network interfaces, with
// internal/private IPs removed.
//
// The returned value maps IPs to per DNSBL statuses, where "pass" means not listed and
// anything else is an error string, e.g. "fail: ..." or "temperror: ...".
func (Admin) DNSBLStatus(ctx context.Context) (results map[string]map[string]string, using, monitoring []dns.Domain) {
	log := mlog.New("webadmin", nil).WithContext(ctx)
	resolver := dns.StrictResolver{Pkg: "check", Log: log.Logger}
	return dnsblsStatus(ctx, log, resolver)
}

func dnsblsStatus(ctx context.Context, log mlog.Log, resolver dns.Resolver) (results map[string]map[string]string, using, monitoring []dns.Domain) {
	// todo: check health before using dnsbl?
	using = mox.Conf.Static.Listeners["public"].SMTP.DNSBLZones
	zones := slices.Clone(using)
	conf := mox.Conf.DynamicConfig()
	for _, zone := range conf.MonitorDNSBLZones {
		if !slices.Contains(zones, zone) {
			zones = append(zones, zone)
			monitoring = append(monitoring, zone)
		}
	}

	r := map[string]map[string]string{}
	for _, ip := range xsendingIPs(ctx) {
		if ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		ipstr := ip.String()
		r[ipstr] = map[string]string{}
		for _, zone := range zones {
			status, expl, err := dnsbl.Lookup(ctx, log.Logger, resolver, zone, ip)
			result := string(status)
			if err != nil {
				result += ": " + err.Error()
			}
			if expl != "" {
				result += ": " + expl
			}
			r[ipstr][zone.LogString()] = result
		}
	}
	return r, using, monitoring
}

func (Admin) MonitorDNSBLsSave(ctx context.Context, text string) {
	var zones []dns.Domain
	publicZones := mox.Conf.Static.Listeners["public"].SMTP.DNSBLZones
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		d, err := dns.ParseDomain(line)
		xcheckuserf(ctx, err, "parsing dnsbl zone %s", line)
		if slices.Contains(zones, d) {
			xusererrorf(ctx, "duplicate dnsbl zone %s", line)
		}
		if slices.Contains(publicZones, d) {
			xusererrorf(ctx, "dnsbl zone %s already present in public listener", line)
		}
		zones = append(zones, d)
	}

	err := admin.ConfigSave(ctx, func(conf *config.Dynamic) {
		conf.MonitorDNSBLs = make([]string, len(zones))
		conf.MonitorDNSBLZones = nil
		for i, z := range zones {
			conf.MonitorDNSBLs[i] = z.Name()
		}
	})
	xcheckf(ctx, err, "saving monitoring dnsbl zones")
}

// DomainRecords returns lines describing DNS records that should exist for the
// configured domain.
func (Admin) DomainRecords(ctx context.Context, domain string) []string {
	log := pkglog.WithContext(ctx)
	return DomainRecords(ctx, log, domain)
}

// DomainRecords is the implementation of API function Admin.DomainRecords, taking
// a logger.
func DomainRecords(ctx context.Context, log mlog.Log, domain string) []string {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")
	dc, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("unknown domain"), "lookup domain")
	}
	resolver := dns.StrictResolver{Pkg: "webadmin", Log: pkglog.WithContext(ctx).Logger}
	_, result, err := resolver.LookupTXT(ctx, domain+".")
	if !dns.IsNotFound(err) {
		xcheckf(ctx, err, "looking up record to determine if dnssec is implemented")
	}

	var certIssuerDomainName, acmeAccountURI string
	public := mox.Conf.Static.Listeners["public"]
	if public.TLS != nil && public.TLS.ACME != "" {
		acme, ok := mox.Conf.Static.ACME[public.TLS.ACME]
		if ok && acme.Manager.Manager.Client != nil {
			certIssuerDomainName = acme.IssuerDomainName
			acc, err := acme.Manager.Manager.Client.GetReg(ctx, "")
			log.Check(err, "get public acme account")
			if err == nil {
				acmeAccountURI = acc.URI
			}
		}
	}

	records, err := admin.DomainRecords(dc, d, result.Authentic, certIssuerDomainName, acmeAccountURI)
	xcheckf(ctx, err, "dns records")
	return records
}

// DomainAdd adds a new domain and reloads the configuration.
func (Admin) DomainAdd(ctx context.Context, disabled bool, domain, accountName, localpart string) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	err = admin.DomainAdd(ctx, disabled, d, accountName, smtp.Localpart(norm.NFC.String(localpart)))
	xcheckf(ctx, err, "adding domain")
}

// DomainRemove removes an existing domain and reloads the configuration.
func (Admin) DomainRemove(ctx context.Context, domain string) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	err = admin.DomainRemove(ctx, d)
	xcheckf(ctx, err, "removing domain")
}

// AccountAdd adds existing a new account, with an initial email address, and
// reloads the configuration.
func (Admin) AccountAdd(ctx context.Context, accountName, address string) {
	err := admin.AccountAdd(ctx, accountName, address)
	xcheckf(ctx, err, "adding account")
}

// AccountRemove removes an existing account and reloads the configuration.
func (Admin) AccountRemove(ctx context.Context, accountName string) {
	err := admin.AccountRemove(ctx, accountName)
	xcheckf(ctx, err, "removing account")
}

// AddressAdd adds a new address to the account, which must already exist.
func (Admin) AddressAdd(ctx context.Context, address, accountName string) {
	err := admin.AddressAdd(ctx, address, accountName)
	xcheckf(ctx, err, "adding address")
}

// AddressRemove removes an existing address.
func (Admin) AddressRemove(ctx context.Context, address string) {
	err := admin.AddressRemove(ctx, address)
	xcheckf(ctx, err, "removing address")
}

// SetPassword saves a new password for an account, invalidating the previous password.
// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
// Password must be at least 8 characters.
func (Admin) SetPassword(ctx context.Context, accountName, password string) {
	log := pkglog.WithContext(ctx)
	if len(password) < 8 {
		xusererrorf(ctx, "message must be at least 8 characters")
	}
	acc, err := store.OpenAccount(log, accountName, false)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.WithContext(ctx).Check(err, "closing account")
	}()
	err = acc.SetPassword(log, password)
	xcheckf(ctx, err, "setting password")
}

// AccountSettingsSave set new settings for an account that only an admin can set.
func (Admin) AccountSettingsSave(ctx context.Context, accountName string, maxOutgoingMessagesPerDay, maxFirstTimeRecipientsPerDay int, maxMsgSize int64, firstTimeSenderDelay, noCustomPassword bool) {
	err := admin.AccountSave(ctx, accountName, func(acc *config.Account) {
		acc.MaxOutgoingMessagesPerDay = maxOutgoingMessagesPerDay
		acc.MaxFirstTimeRecipientsPerDay = maxFirstTimeRecipientsPerDay
		acc.QuotaMessageSize = maxMsgSize
		acc.NoFirstTimeSenderDelay = !firstTimeSenderDelay
		acc.NoCustomPassword = noCustomPassword
	})
	xcheckf(ctx, err, "saving account settings")
}

// AccountLoginDisabledSave saves the LoginDisabled field of an account.
func (Admin) AccountLoginDisabledSave(ctx context.Context, accountName string, loginDisabled string) {
	log := pkglog.WithContext(ctx)

	acc, err := store.OpenAccount(log, accountName, false)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	err = admin.AccountSave(ctx, accountName, func(acc *config.Account) {
		acc.LoginDisabled = loginDisabled
	})
	xcheckf(ctx, err, "saving login disabled account")

	err = acc.SessionsClear(ctx, log)
	xcheckf(ctx, err, "removing current sessions")
}

// ClientConfigsDomain returns configurations for email clients, IMAP and
// Submission (SMTP) for the domain.
func (Admin) ClientConfigsDomain(ctx context.Context, domain string) admin.ClientConfigs {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	cc, err := admin.ClientConfigsDomain(d)
	xcheckf(ctx, err, "client config for domain")
	return cc
}

// QueueSize returns the number of messages currently in the outgoing queue.
func (Admin) QueueSize(ctx context.Context) int {
	n, err := queue.Count(ctx)
	xcheckf(ctx, err, "listing messages in queue")
	return n
}

// QueueHoldRuleList lists the hold rules.
func (Admin) QueueHoldRuleList(ctx context.Context) []queue.HoldRule {
	l, err := queue.HoldRuleList(ctx)
	xcheckf(ctx, err, "listing queue hold rules")
	return l
}

// QueueHoldRuleAdd adds a hold rule. Newly submitted and existing messages
// matching the hold rule will be marked "on hold".
func (Admin) QueueHoldRuleAdd(ctx context.Context, hr queue.HoldRule) queue.HoldRule {
	var err error
	hr.SenderDomain, err = dns.ParseDomain(hr.SenderDomainStr)
	xcheckuserf(ctx, err, "parsing sender domain %q", hr.SenderDomainStr)
	hr.RecipientDomain, err = dns.ParseDomain(hr.RecipientDomainStr)
	xcheckuserf(ctx, err, "parsing recipient domain %q", hr.RecipientDomainStr)

	log := pkglog.WithContext(ctx)
	hr, err = queue.HoldRuleAdd(ctx, log, hr)
	xcheckf(ctx, err, "adding queue hold rule")
	return hr
}

// QueueHoldRuleRemove removes a hold rule. The Hold field of messages in
// the queue are not changed.
func (Admin) QueueHoldRuleRemove(ctx context.Context, holdRuleID int64) {
	log := pkglog.WithContext(ctx)
	err := queue.HoldRuleRemove(ctx, log, holdRuleID)
	xcheckf(ctx, err, "removing queue hold rule")
}

// QueueList returns the messages currently in the outgoing queue.
func (Admin) QueueList(ctx context.Context, filter queue.Filter, sort queue.Sort) []queue.Msg {
	l, err := queue.List(ctx, filter, sort)
	xcheckf(ctx, err, "listing messages in queue")
	return l
}

// QueueNextAttemptSet sets a new time for next delivery attempt of matching
// messages from the queue.
func (Admin) QueueNextAttemptSet(ctx context.Context, filter queue.Filter, minutes int) (affected int) {
	n, err := queue.NextAttemptSet(ctx, filter, time.Now().Add(time.Duration(minutes)*time.Minute))
	xcheckf(ctx, err, "setting new next delivery attempt time for matching messages in queue")
	return n
}

// QueueNextAttemptAdd adds a duration to the time of next delivery attempt of
// matching messages from the queue.
func (Admin) QueueNextAttemptAdd(ctx context.Context, filter queue.Filter, minutes int) (affected int) {
	n, err := queue.NextAttemptAdd(ctx, filter, time.Duration(minutes)*time.Minute)
	xcheckf(ctx, err, "adding duration to next delivery attempt for matching messages in queue")
	return n
}

// QueueHoldSet sets the Hold field of matching messages in the queue.
func (Admin) QueueHoldSet(ctx context.Context, filter queue.Filter, onHold bool) (affected int) {
	n, err := queue.HoldSet(ctx, filter, onHold)
	xcheckf(ctx, err, "changing onhold for matching messages in queue")
	return n
}

// QueueFail fails delivery for matching messages, causing DSNs to be sent.
func (Admin) QueueFail(ctx context.Context, filter queue.Filter) (affected int) {
	log := pkglog.WithContext(ctx)
	n, err := queue.Fail(ctx, log, filter)
	xcheckf(ctx, err, "drop messages from queue")
	return n
}

// QueueDrop removes matching messages from the queue.
func (Admin) QueueDrop(ctx context.Context, filter queue.Filter) (affected int) {
	log := pkglog.WithContext(ctx)
	n, err := queue.Drop(ctx, log, filter)
	xcheckf(ctx, err, "drop messages from queue")
	return n
}

// QueueRequireTLSSet updates the requiretls field for matching messages in the
// queue, to be used for the next delivery.
func (Admin) QueueRequireTLSSet(ctx context.Context, filter queue.Filter, requireTLS *bool) (affected int) {
	n, err := queue.RequireTLSSet(ctx, filter, requireTLS)
	xcheckf(ctx, err, "update requiretls for messages in queue")
	return n
}

// QueueTransportSet initiates delivery of a message from the queue and sets the transport
// to use for delivery.
func (Admin) QueueTransportSet(ctx context.Context, filter queue.Filter, transport string) (affected int) {
	n, err := queue.TransportSet(ctx, filter, transport)
	xcheckf(ctx, err, "changing transport for messages in queue")
	return n
}

// RetiredList returns messages retired from the queue (delivery could
// have succeeded or failed).
func (Admin) RetiredList(ctx context.Context, filter queue.RetiredFilter, sort queue.RetiredSort) []queue.MsgRetired {
	l, err := queue.RetiredList(ctx, filter, sort)
	xcheckf(ctx, err, "listing retired messages")
	return l
}

// HookQueueSize returns the number of webhooks still to be delivered.
func (Admin) HookQueueSize(ctx context.Context) int {
	n, err := queue.HookQueueSize(ctx)
	xcheckf(ctx, err, "get hook queue size")
	return n
}

// HookList lists webhooks still to be delivered.
func (Admin) HookList(ctx context.Context, filter queue.HookFilter, sort queue.HookSort) []queue.Hook {
	l, err := queue.HookList(ctx, filter, sort)
	xcheckf(ctx, err, "listing hook queue")
	return l
}

// HookNextAttemptSet sets a new time for next delivery attempt of matching
// hooks from the queue.
func (Admin) HookNextAttemptSet(ctx context.Context, filter queue.HookFilter, minutes int) (affected int) {
	n, err := queue.HookNextAttemptSet(ctx, filter, time.Now().Add(time.Duration(minutes)*time.Minute))
	xcheckf(ctx, err, "setting new next delivery attempt time for matching webhooks in queue")
	return n
}

// HookNextAttemptAdd adds a duration to the time of next delivery attempt of
// matching hooks from the queue.
func (Admin) HookNextAttemptAdd(ctx context.Context, filter queue.HookFilter, minutes int) (affected int) {
	n, err := queue.HookNextAttemptAdd(ctx, filter, time.Duration(minutes)*time.Minute)
	xcheckf(ctx, err, "adding duration to next delivery attempt for matching webhooks in queue")
	return n
}

// HookRetiredList lists retired webhooks.
func (Admin) HookRetiredList(ctx context.Context, filter queue.HookRetiredFilter, sort queue.HookRetiredSort) []queue.HookRetired {
	l, err := queue.HookRetiredList(ctx, filter, sort)
	xcheckf(ctx, err, "listing retired hooks")
	return l
}

// HookCancel prevents further delivery attempts of matching webhooks.
func (Admin) HookCancel(ctx context.Context, filter queue.HookFilter) (affected int) {
	log := pkglog.WithContext(ctx)
	n, err := queue.HookCancel(ctx, log, filter)
	xcheckf(ctx, err, "cancel hooks in queue")
	return n
}

// LogLevels returns the current log levels.
func (Admin) LogLevels(ctx context.Context) map[string]string {
	m := map[string]string{}
	for pkg, level := range mox.Conf.LogLevels() {
		s, ok := mlog.LevelStrings[level]
		if !ok {
			s = level.String()
		}
		m[pkg] = s
	}
	return m
}

// LogLevelSet sets a log level for a package.
func (Admin) LogLevelSet(ctx context.Context, pkg string, levelStr string) {
	level, ok := mlog.Levels[levelStr]
	if !ok {
		xcheckuserf(ctx, errors.New("unknown"), "lookup level")
	}
	mox.Conf.LogLevelSet(pkglog.WithContext(ctx), pkg, level)
}

// LogLevelRemove removes a log level for a package, which cannot be the empty string.
func (Admin) LogLevelRemove(ctx context.Context, pkg string) {
	mox.Conf.LogLevelRemove(pkglog.WithContext(ctx), pkg)
}

// CheckUpdatesEnabled returns whether checking for updates is enabled.
func (Admin) CheckUpdatesEnabled(ctx context.Context) bool {
	return mox.Conf.Static.CheckUpdates
}

// WebserverConfig is the combination of WebDomainRedirects and WebHandlers
// from the domains.conf configuration file.
type WebserverConfig struct {
	WebDNSDomainRedirects [][2]dns.Domain // From server to frontend.
	WebDomainRedirects    [][2]string     // From frontend to server, it's not convenient to create dns.Domain in the frontend.
	WebHandlers           []config.WebHandler
}

// WebserverConfig returns the current webserver config
func (Admin) WebserverConfig(ctx context.Context) (conf WebserverConfig) {
	conf = webserverConfig()
	conf.WebDomainRedirects = nil
	return conf
}

func webserverConfig() WebserverConfig {
	conf := mox.Conf.DynamicConfig()
	r := conf.WebDNSDomainRedirects
	l := conf.WebHandlers

	x := make([][2]dns.Domain, 0, len(r))
	xs := make([][2]string, 0, len(r))
	for k, v := range r {
		x = append(x, [2]dns.Domain{k, v})
		xs = append(xs, [2]string{k.Name(), v.Name()})
	}
	sort.Slice(x, func(i, j int) bool {
		return x[i][0].ASCII < x[j][0].ASCII
	})
	sort.Slice(xs, func(i, j int) bool {
		return xs[i][0] < xs[j][0]
	})
	return WebserverConfig{x, xs, l}
}

// WebserverConfigSave saves a new webserver config. If oldConf is not equal to
// the current config, an error is returned.
func (Admin) WebserverConfigSave(ctx context.Context, oldConf, newConf WebserverConfig) (savedConf WebserverConfig) {
	current := webserverConfig()
	webhandlersEqual := func() bool {
		if len(current.WebHandlers) != len(oldConf.WebHandlers) {
			return false
		}
		for i, wh := range current.WebHandlers {
			if !wh.Equal(oldConf.WebHandlers[i]) {
				return false
			}
		}
		return true
	}
	if !reflect.DeepEqual(oldConf.WebDNSDomainRedirects, current.WebDNSDomainRedirects) || !webhandlersEqual() {
		xcheckuserf(ctx, errors.New("config has changed"), "comparing old/current config")
	}

	// Convert to map, check that there are no duplicates here. The canonicalized
	// dns.Domain are checked again for uniqueness when parsing the config before
	// storing.
	domainRedirects := map[string]string{}
	for _, x := range newConf.WebDomainRedirects {
		if _, ok := domainRedirects[x[0]]; ok {
			xcheckuserf(ctx, errors.New("already present"), "checking redirect %s", x[0])
		}
		domainRedirects[x[0]] = x[1]
	}

	err := admin.ConfigSave(ctx, func(conf *config.Dynamic) {
		conf.WebDomainRedirects = domainRedirects
		conf.WebHandlers = newConf.WebHandlers
	})
	xcheckf(ctx, err, "saving webserver config")

	savedConf = webserverConfig()
	savedConf.WebDomainRedirects = nil
	return savedConf
}

// Transports returns the configured transports, for sending email.
func (Admin) Transports(ctx context.Context) map[string]config.Transport {
	return mox.Conf.Static.Transports
}

// DMARCEvaluationStats returns a map of all domains with evaluations to a count of
// the evaluations and whether those evaluations will cause a report to be sent.
func (Admin) DMARCEvaluationStats(ctx context.Context) map[string]dmarcdb.EvaluationStat {
	stats, err := dmarcdb.EvaluationStats(ctx)
	xcheckf(ctx, err, "get evaluation stats")
	return stats
}

// DMARCEvaluationsDomain returns all evaluations for aggregate reports for the
// domain, sorted from oldest to most recent.
func (Admin) DMARCEvaluationsDomain(ctx context.Context, domain string) (dns.Domain, []dmarcdb.Evaluation) {
	dom, err := dns.ParseDomain(domain)
	xcheckf(ctx, err, "parsing domain")

	evals, err := dmarcdb.EvaluationsDomain(ctx, dom)
	xcheckf(ctx, err, "get evaluations for domain")
	return dom, evals
}

// DMARCRemoveEvaluations removes evaluations for a domain.
func (Admin) DMARCRemoveEvaluations(ctx context.Context, domain string) {
	dom, err := dns.ParseDomain(domain)
	xcheckf(ctx, err, "parsing domain")

	err = dmarcdb.RemoveEvaluationsDomain(ctx, dom)
	xcheckf(ctx, err, "removing evaluations for domain")
}

// DMARCSuppressAdd adds a reporting address to the suppress list. Outgoing
// reports will be suppressed for a period.
func (Admin) DMARCSuppressAdd(ctx context.Context, reportingAddress string, until time.Time, comment string) {
	addr, err := smtp.ParseAddress(reportingAddress)
	xcheckuserf(ctx, err, "parsing reporting address")

	ba := dmarcdb.SuppressAddress{ReportingAddress: addr.String(), Until: until, Comment: comment}
	err = dmarcdb.SuppressAdd(ctx, &ba)
	xcheckf(ctx, err, "adding address to suppresslist")
}

// DMARCSuppressList returns all reporting addresses on the suppress list.
func (Admin) DMARCSuppressList(ctx context.Context) []dmarcdb.SuppressAddress {
	l, err := dmarcdb.SuppressList(ctx)
	xcheckf(ctx, err, "listing reporting addresses in suppresslist")
	return l
}

// DMARCSuppressRemove removes a reporting address record from the suppress list.
func (Admin) DMARCSuppressRemove(ctx context.Context, id int64) {
	err := dmarcdb.SuppressRemove(ctx, id)
	xcheckf(ctx, err, "removing reporting address from suppresslist")
}

// DMARCSuppressExtend updates the until field of a suppressed reporting address record.
func (Admin) DMARCSuppressExtend(ctx context.Context, id int64, until time.Time) {
	err := dmarcdb.SuppressUpdate(ctx, id, until)
	xcheckf(ctx, err, "updating reporting address in suppresslist")
}

// TLSRPTResults returns all TLSRPT results in the database.
func (Admin) TLSRPTResults(ctx context.Context) []tlsrptdb.TLSResult {
	results, err := tlsrptdb.Results(ctx)
	xcheckf(ctx, err, "get results")
	return results
}

// TLSRPTResultsPolicyDomain returns the TLS results for a domain.
func (Admin) TLSRPTResultsDomain(ctx context.Context, isRcptDom bool, policyDomain string) (dns.Domain, []tlsrptdb.TLSResult) {
	dom, err := dns.ParseDomain(policyDomain)
	xcheckf(ctx, err, "parsing domain")

	if isRcptDom {
		results, err := tlsrptdb.ResultsRecipientDomain(ctx, dom)
		xcheckf(ctx, err, "get result for recipient domain")
		return dom, results
	}
	results, err := tlsrptdb.ResultsPolicyDomain(ctx, dom)
	xcheckf(ctx, err, "get result for policy domain")
	return dom, results
}

// LookupTLSRPTRecord looks up a TLSRPT record and returns the parsed form, original txt
// form from DNS, and error with the TLSRPT record as a string.
func (Admin) LookupTLSRPTRecord(ctx context.Context, domain string) (record *TLSRPTRecord, txt string, errstr string) {
	log := pkglog.WithContext(ctx)
	dom, err := dns.ParseDomain(domain)
	xcheckf(ctx, err, "parsing domain")

	resolver := dns.StrictResolver{Pkg: "webadmin", Log: log.Logger}
	r, txt, err := tlsrpt.Lookup(ctx, log.Logger, resolver, dom)
	if err != nil && (errors.Is(err, tlsrpt.ErrNoRecord) || errors.Is(err, tlsrpt.ErrMultipleRecords) || errors.Is(err, tlsrpt.ErrRecordSyntax) || errors.Is(err, tlsrpt.ErrDNS)) {
		errstr = err.Error()
		err = nil
	}
	xcheckf(ctx, err, "fetching tlsrpt record")

	if r != nil {
		record = &TLSRPTRecord{Record: *r}
	}

	return record, txt, errstr
}

// TLSRPTRemoveResults removes the TLS results for a domain for the given day. If
// day is empty, all results are removed.
func (Admin) TLSRPTRemoveResults(ctx context.Context, isRcptDom bool, domain string, day string) {
	dom, err := dns.ParseDomain(domain)
	xcheckf(ctx, err, "parsing domain")

	if isRcptDom {
		err = tlsrptdb.RemoveResultsRecipientDomain(ctx, dom, day)
		xcheckf(ctx, err, "removing tls results")
	} else {
		err = tlsrptdb.RemoveResultsPolicyDomain(ctx, dom, day)
		xcheckf(ctx, err, "removing tls results")
	}
}

// TLSRPTSuppressAdd adds a reporting address to the suppress list. Outgoing
// reports will be suppressed for a period.
func (Admin) TLSRPTSuppressAdd(ctx context.Context, reportingAddress string, until time.Time, comment string) {
	addr, err := smtp.ParseAddress(reportingAddress)
	xcheckuserf(ctx, err, "parsing reporting address")

	ba := tlsrptdb.SuppressAddress{ReportingAddress: addr.String(), Until: until, Comment: comment}
	err = tlsrptdb.SuppressAdd(ctx, &ba)
	xcheckf(ctx, err, "adding address to suppresslist")
}

// TLSRPTSuppressList returns all reporting addresses on the suppress list.
func (Admin) TLSRPTSuppressList(ctx context.Context) []tlsrptdb.SuppressAddress {
	l, err := tlsrptdb.SuppressList(ctx)
	xcheckf(ctx, err, "listing reporting addresses in suppresslist")
	return l
}

// TLSRPTSuppressRemove removes a reporting address record from the suppress list.
func (Admin) TLSRPTSuppressRemove(ctx context.Context, id int64) {
	err := tlsrptdb.SuppressRemove(ctx, id)
	xcheckf(ctx, err, "removing reporting address from suppresslist")
}

// TLSRPTSuppressExtend updates the until field of a suppressed reporting address record.
func (Admin) TLSRPTSuppressExtend(ctx context.Context, id int64, until time.Time) {
	err := tlsrptdb.SuppressUpdate(ctx, id, until)
	xcheckf(ctx, err, "updating reporting address in suppresslist")
}

// LookupCid turns an ID from a Received header into a cid as used in logging.
func (Admin) LookupCid(ctx context.Context, recvID string) (cid string) {
	v, err := mox.ReceivedToCid(recvID)
	xcheckf(ctx, err, "received id to cid")
	return fmt.Sprintf("%x", v)
}

// Config returns the dynamic config.
func (Admin) Config(ctx context.Context) config.Dynamic {
	return mox.Conf.DynamicConfig()
}

// AccountRoutesSave saves routes for an account.
func (Admin) AccountRoutesSave(ctx context.Context, accountName string, routes []config.Route) {
	err := admin.AccountSave(ctx, accountName, func(acc *config.Account) {
		acc.Routes = routes
	})
	xcheckf(ctx, err, "saving account routes")
}

// DomainRoutesSave saves routes for a domain.
func (Admin) DomainRoutesSave(ctx context.Context, domainName string, routes []config.Route) {
	err := admin.DomainSave(ctx, domainName, func(domain *config.Domain) error {
		domain.Routes = routes
		return nil
	})
	xcheckf(ctx, err, "saving domain routes")
}

// RoutesSave saves global routes.
func (Admin) RoutesSave(ctx context.Context, routes []config.Route) {
	err := admin.ConfigSave(ctx, func(config *config.Dynamic) {
		config.Routes = routes
	})
	xcheckf(ctx, err, "saving global routes")
}

// DomainDescriptionSave saves the description for a domain.
func (Admin) DomainDescriptionSave(ctx context.Context, domainName, descr string) {
	err := admin.DomainSave(ctx, domainName, func(domain *config.Domain) error {
		domain.Description = descr
		return nil
	})
	xcheckf(ctx, err, "saving domain description")
}

// DomainClientSettingsDomainSave saves the client settings domain for a domain.
func (Admin) DomainClientSettingsDomainSave(ctx context.Context, domainName, clientSettingsDomain string) {
	err := admin.DomainSave(ctx, domainName, func(domain *config.Domain) error {
		domain.ClientSettingsDomain = clientSettingsDomain
		return nil
	})
	xcheckf(ctx, err, "saving client settings domain")
}

// DomainLocalpartConfigSave saves the localpart catchall and case-sensitive
// settings for a domain.
func (Admin) DomainLocalpartConfigSave(ctx context.Context, domainName string, localpartCatchallSeparators []string, localpartCaseSensitive bool) {
	err := admin.DomainSave(ctx, domainName, func(domain *config.Domain) error {
		// We don't allow introducing new catchall separators that are used in DMARC/TLS
		// reporting. Can occur in existing configs for backwards compatibility.
		containsSep := func(seps []string) bool {
			for _, sep := range seps {
				if domain.DMARC != nil && strings.Contains(domain.DMARC.Localpart, sep) {
					return true
				}
				if domain.TLSRPT != nil && strings.Contains(domain.TLSRPT.Localpart, sep) {
					return true
				}
			}
			return false
		}
		if !containsSep(domain.LocalpartCatchallSeparatorsEffective) && containsSep(localpartCatchallSeparators) {
			xusererrorf(ctx, "cannot add localpart catchall separators that are used in dmarc and/or tls reporting addresses, change reporting addresses first")
		}

		domain.LocalpartCatchallSeparatorsEffective = localpartCatchallSeparators
		// If there is a single separator, we prefer the non-list form, it's easier to
		// read/edit and should suffice for most setups.
		domain.LocalpartCatchallSeparator = ""
		domain.LocalpartCatchallSeparators = nil
		if len(localpartCatchallSeparators) == 1 {
			domain.LocalpartCatchallSeparator = localpartCatchallSeparators[0]
		} else {
			domain.LocalpartCatchallSeparators = localpartCatchallSeparators
		}

		domain.LocalpartCaseSensitive = localpartCaseSensitive
		return nil
	})
	xcheckf(ctx, err, "saving localpart settings for domain")
}

// DomainDMARCAddressSave saves the DMARC reporting address/processing
// configuration for a domain. If localpart is empty, processing reports is
// disabled.
func (Admin) DomainDMARCAddressSave(ctx context.Context, domainName, localpart, domain, account, mailbox string) {
	err := admin.DomainSave(ctx, domainName, func(d *config.Domain) error {
		// DMARC reporting addresses can contain the localpart catchall separator(s) for
		// backwards compability (hence not enforced when parsing the config files), but we
		// don't allow creating them.
		if d.DMARC == nil || d.DMARC.Localpart != localpart {
			for _, sep := range d.LocalpartCatchallSeparatorsEffective {
				if strings.Contains(localpart, sep) {
					xusererrorf(ctx, "dmarc reporting address cannot contain catchall separator %q in localpart (%q)", sep, localpart)
				}
			}
		}

		if localpart == "" {
			d.DMARC = nil
		} else {
			d.DMARC = &config.DMARC{
				Localpart: localpart,
				Domain:    domain,
				Account:   account,
				Mailbox:   mailbox,
			}
		}
		return nil
	})
	xcheckf(ctx, err, "saving dmarc reporting address/settings for domain")
}

// DomainTLSRPTAddressSave saves the TLS reporting address/processing
// configuration for a domain. If localpart is empty, processing reports is
// disabled.
func (Admin) DomainTLSRPTAddressSave(ctx context.Context, domainName, localpart, domain, account, mailbox string) {
	err := admin.DomainSave(ctx, domainName, func(d *config.Domain) error {
		// TLS reporting addresses can contain the localpart catchall separator(s) for
		// backwards compability (hence not enforced when parsing the config files), but we
		// don't allow creating them.
		if d.TLSRPT == nil || d.TLSRPT.Localpart != localpart {
			for _, sep := range d.LocalpartCatchallSeparatorsEffective {
				if strings.Contains(localpart, sep) {
					xusererrorf(ctx, "tls reporting address cannot contain catchall separator %q in localpart (%q)", sep, localpart)
				}
			}
		}

		if localpart == "" {
			d.TLSRPT = nil
		} else {
			d.TLSRPT = &config.TLSRPT{
				Localpart: localpart,
				Domain:    domain,
				Account:   account,
				Mailbox:   mailbox,
			}
		}
		return nil
	})
	xcheckf(ctx, err, "saving tls reporting address/settings for domain")
}

// DomainMTASTSSave saves the MTASTS policy for a domain. If policyID is empty,
// no MTASTS policy is served.
func (Admin) DomainMTASTSSave(ctx context.Context, domainName, policyID string, mode mtasts.Mode, maxAge time.Duration, mx []string) {
	err := admin.DomainSave(ctx, domainName, func(d *config.Domain) error {
		if policyID == "" {
			d.MTASTS = nil
		} else {
			d.MTASTS = &config.MTASTS{
				PolicyID: policyID,
				Mode:     mode,
				MaxAge:   maxAge,
				MX:       mx,
			}
		}
		return nil
	})
	xcheckf(ctx, err, "saving mtasts policy for domain")
}

// DomainDKIMAdd adds a DKIM selector for a domain, generating a new private
// key. The selector is not enabled for signing.
func (Admin) DomainDKIMAdd(ctx context.Context, domainName, selector, algorithm, hash string, headerRelaxed, bodyRelaxed, seal bool, headers []string, lifetime time.Duration) {
	d, err := dns.ParseDomain(domainName)
	xcheckuserf(ctx, err, "parsing domain")
	s, err := dns.ParseDomain(selector)
	xcheckuserf(ctx, err, "parsing selector")
	err = admin.DKIMAdd(ctx, d, s, algorithm, hash, headerRelaxed, bodyRelaxed, seal, headers, lifetime)
	xcheckf(ctx, err, "adding dkim key")
}

// DomainDKIMRemove removes a DKIM selector for a domain.
func (Admin) DomainDKIMRemove(ctx context.Context, domainName, selector string) {
	d, err := dns.ParseDomain(domainName)
	xcheckuserf(ctx, err, "parsing domain")
	s, err := dns.ParseDomain(selector)
	xcheckuserf(ctx, err, "parsing selector")
	err = admin.DKIMRemove(ctx, d, s)
	xcheckf(ctx, err, "removing dkim key")
}

// DomainDKIMSave saves the settings of selectors, and which to enable for
// signing, for a domain. All currently configured selectors must be present,
// selectors cannot be added/removed with this function.
func (Admin) DomainDKIMSave(ctx context.Context, domainName string, selectors map[string]config.Selector, sign []string) {
	for _, s := range sign {
		if _, ok := selectors[s]; !ok {
			xcheckuserf(ctx, fmt.Errorf("cannot sign unknown selector %q", s), "checking selectors")
		}
	}

	err := admin.DomainSave(ctx, domainName, func(d *config.Domain) error {
		if len(selectors) != len(d.DKIM.Selectors) {
			xcheckuserf(ctx, fmt.Errorf("cannot add/remove dkim selectors with this function"), "checking selectors")
		}
		for s := range selectors {
			if _, ok := d.DKIM.Selectors[s]; !ok {
				xcheckuserf(ctx, fmt.Errorf("unknown selector %q", s), "checking selectors")
			}
		}
		// At least the selectors are the same.

		// Build up new selectors.
		sels := map[string]config.Selector{}
		for name, nsel := range selectors {
			osel := d.DKIM.Selectors[name]
			xsel := config.Selector{
				Hash:             nsel.Hash,
				Canonicalization: nsel.Canonicalization,
				DontSealHeaders:  nsel.DontSealHeaders,
				Expiration:       nsel.Expiration,

				PrivateKeyFile: osel.PrivateKeyFile,
			}
			if !slices.Equal(osel.HeadersEffective, nsel.Headers) {
				xsel.Headers = nsel.Headers
			}
			sels[name] = xsel
		}

		// Enable the new selector settings.
		d.DKIM = config.DKIM{
			Selectors: sels,
			Sign:      sign,
		}
		return nil
	})
	xcheckf(ctx, err, "saving dkim selector for domain")
}

// DomainDisabledSave saves the Disabled field of a domain. A disabled domain
// rejects incoming/outgoing messages involving the domain and does not request new
// TLS certificats with ACME.
func (Admin) DomainDisabledSave(ctx context.Context, domainName string, disabled bool) {
	err := admin.DomainSave(ctx, domainName, func(d *config.Domain) error {
		d.Disabled = disabled
		return nil
	})
	xcheckf(ctx, err, "saving disabled setting for domain")
}

func xparseAddress(ctx context.Context, lp, domain string) smtp.Address {
	xlp, err := smtp.ParseLocalpart(lp)
	xcheckuserf(ctx, err, "parsing localpart")
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")
	return smtp.NewAddress(xlp, d)
}

func (Admin) AliasAdd(ctx context.Context, aliaslp string, domainName string, alias config.Alias) {
	addr := xparseAddress(ctx, aliaslp, domainName)
	err := admin.AliasAdd(ctx, addr, alias)
	xcheckf(ctx, err, "adding alias")
}

func (Admin) AliasUpdate(ctx context.Context, aliaslp string, domainName string, postPublic, listMembers, allowMsgFrom bool) {
	addr := xparseAddress(ctx, aliaslp, domainName)
	alias := config.Alias{
		PostPublic:   postPublic,
		ListMembers:  listMembers,
		AllowMsgFrom: allowMsgFrom,
	}
	err := admin.AliasUpdate(ctx, addr, alias)
	xcheckf(ctx, err, "saving alias")
}

func (Admin) AliasRemove(ctx context.Context, aliaslp string, domainName string) {
	addr := xparseAddress(ctx, aliaslp, domainName)
	err := admin.AliasRemove(ctx, addr)
	xcheckf(ctx, err, "removing alias")
}

func (Admin) AliasAddressesAdd(ctx context.Context, aliaslp string, domainName string, addresses []string) {
	addr := xparseAddress(ctx, aliaslp, domainName)
	err := admin.AliasAddressesAdd(ctx, addr, addresses)
	xcheckf(ctx, err, "adding address to alias")
}

func (Admin) AliasAddressesRemove(ctx context.Context, aliaslp string, domainName string, addresses []string) {
	addr := xparseAddress(ctx, aliaslp, domainName)
	err := admin.AliasAddressesRemove(ctx, addr, addresses)
	xcheckf(ctx, err, "removing address from alias")
}

func (Admin) TLSPublicKeys(ctx context.Context, accountOpt string) ([]store.TLSPublicKey, error) {
	return store.TLSPublicKeyList(ctx, accountOpt)
}

func (Admin) LoginAttempts(ctx context.Context, accountName string, limit int) []store.LoginAttempt {
	l, err := store.LoginAttemptList(ctx, accountName, limit)
	xcheckf(ctx, err, "listing login attempts")
	return l
}
