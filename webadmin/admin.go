package webadmin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	_ "embed"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sherpa"
	"github.com/mjl-/sherpadoc"
	"github.com/mjl-/sherpaprom"

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
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/tlsrptdb"
)

var xlog = mlog.New("webadmin")

//go:embed adminapi.json
var adminapiJSON []byte

//go:embed admin.html
var adminHTML []byte

var adminDoc = mustParseAPI("admin", adminapiJSON)

var adminSherpaHandler http.Handler

func mustParseAPI(api string, buf []byte) (doc sherpadoc.Section) {
	err := json.Unmarshal(buf, &doc)
	if err != nil {
		xlog.Fatalx("parsing api docs", err, mlog.Field("api", api))
	}
	return doc
}

func init() {
	collector, err := sherpaprom.NewCollector("moxadmin", nil)
	if err != nil {
		xlog.Fatalx("creating sherpa prometheus collector", err)
	}

	adminSherpaHandler, err = sherpa.NewHandler("/api/", moxvar.Version, Admin{}, &adminDoc, &sherpa.HandlerOpts{Collector: collector, AdjustFunctionNames: "none"})
	if err != nil {
		xlog.Fatalx("sherpa handler", err)
	}
}

// Admin exports web API functions for the admin web interface. All its methods are
// exported under api/. Function calls require valid HTTP Authentication
// credentials of a user.
type Admin struct{}

// We keep a cache for authentication so we don't bcrypt for each incoming HTTP request with HTTP basic auth.
// We keep track of the last successful password hash and Authorization header.
// The cache is cleared periodically, see below.
var authCache struct {
	sync.Mutex
	lastSuccessHash, lastSuccessAuth string
}

// started when we start serving. not at package init time, because we don't want
// to make goroutines that early.
func ManageAuthCache() {
	for {
		authCache.Lock()
		authCache.lastSuccessHash = ""
		authCache.lastSuccessAuth = ""
		authCache.Unlock()
		time.Sleep(15 * time.Minute)
	}
}

// check whether authentication from the config (passwordfile with bcrypt hash)
// matches the authorization header "authHdr". we don't care about any username.
// on (auth) failure, a http response is sent and false returned.
func checkAdminAuth(ctx context.Context, passwordfile string, w http.ResponseWriter, r *http.Request) bool {
	log := xlog.WithContext(ctx)

	respondAuthFail := func() bool {
		// note: browsers don't display the realm to prevent users getting confused by malicious realm messages.
		w.Header().Set("WWW-Authenticate", `Basic realm="mox admin - login with empty username and admin password"`)
		http.Error(w, "http 401 - unauthorized - mox admin - login with empty username and admin password", http.StatusUnauthorized)
		return false
	}

	authResult := "error"
	start := time.Now()
	var addr *net.TCPAddr
	defer func() {
		metrics.AuthenticationInc("webadmin", "httpbasic", authResult)
		if authResult == "ok" && addr != nil {
			mox.LimiterFailedAuth.Reset(addr.IP, start)
		}
	}()

	var err error
	var remoteIP net.IP
	addr, err = net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		log.Errorx("parsing remote address", err, mlog.Field("addr", r.RemoteAddr))
	} else if addr != nil {
		remoteIP = addr.IP
	}
	if remoteIP != nil && !mox.LimiterFailedAuth.Add(remoteIP, start, 1) {
		metrics.AuthenticationRatelimitedInc("webadmin")
		http.Error(w, "429 - too many auth attempts", http.StatusTooManyRequests)
		return false
	}

	authHdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "Basic ") || passwordfile == "" {
		return respondAuthFail()
	}
	buf, err := os.ReadFile(passwordfile)
	if err != nil {
		log.Errorx("reading admin password file", err, mlog.Field("path", passwordfile))
		return respondAuthFail()
	}
	passwordhash := strings.TrimSpace(string(buf))
	authCache.Lock()
	defer authCache.Unlock()
	if passwordhash != "" && passwordhash == authCache.lastSuccessHash && authHdr != "" && authCache.lastSuccessAuth == authHdr {
		authResult = "ok"
		return true
	}
	auth, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHdr, "Basic "))
	if err != nil {
		return respondAuthFail()
	}
	t := strings.SplitN(string(auth), ":", 2)
	if len(t) != 2 || len(t[1]) < 8 {
		log.Info("failed authentication attempt", mlog.Field("username", "admin"), mlog.Field("remote", remoteIP))
		return respondAuthFail()
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordhash), []byte(t[1])); err != nil {
		authResult = "badcreds"
		log.Info("failed authentication attempt", mlog.Field("username", "admin"), mlog.Field("remote", remoteIP))
		return respondAuthFail()
	}
	authCache.lastSuccessHash = passwordhash
	authCache.lastSuccessAuth = authHdr
	authResult = "ok"
	return true
}

func Handle(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), mlog.CidKey, mox.Cid())
	if !checkAdminAuth(ctx, mox.ConfigDirPath(mox.Conf.Static.AdminPasswordFile), w, r) {
		// Response already sent.
		return
	}

	if lw, ok := w.(interface{ AddField(f mlog.Pair) }); ok {
		lw.AddField(mlog.Field("authadmin", true))
	}

	if r.Method == "GET" && r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache; max-age=0")
		// We typically return the embedded admin.html, but during development it's handy
		// to load from disk.
		f, err := os.Open("webadmin/admin.html")
		if err == nil {
			defer f.Close()
			_, _ = io.Copy(w, f)
		} else {
			_, _ = w.Write(adminHTML)
		}
		return
	}
	adminSherpaHandler.ServeHTTP(w, r.WithContext(ctx))
}

func xcheckf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	xlog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "server:error", Message: errmsg})
}

func xcheckuserf(ctx context.Context, err error, format string, args ...any) {
	if err == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	errmsg := fmt.Sprintf("%s: %s", msg, err)
	xlog.WithContext(ctx).Errorx(msg, err)
	panic(&sherpa.Error{Code: "user:error", Message: errmsg})
}

type Result struct {
	Errors       []string
	Warnings     []string
	Instructions []string
}

type TLSCheckResult struct {
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
	CNAMEs     []string
	TXT        string
	Record     *MTASTSRecord
	PolicyText string
	Policy     *mtasts.Policy
	Result
}

type SRVConfCheckResult struct {
	SRVs map[string][]*net.SRV // Service (e.g. "_imaps") to records.
	Result
}

type AutoconfCheckResult struct {
	IPs []string
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
	IPRev        IPRevCheckResult
	MX           MXCheckResult
	TLS          TLSCheckResult
	SPF          SPFCheckResult
	DKIM         DKIMCheckResult
	DMARC        DMARCCheckResult
	TLSRPT       TLSRPTCheckResult
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
	log := xlog.WithContext(ctx)
	log.Error("recover from panic", mlog.Field("panic", x))
	debug.PrintStack()
	metrics.PanicInc("http")
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

	resolver := dns.StrictResolver{Pkg: "check"}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	nctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return checkDomain(nctx, resolver, dialer, domainName)
}

func checkDomain(ctx context.Context, resolver dns.Resolver, dialer *net.Dialer, domainName string) (r CheckResult) {
	domain, err := dns.ParseDomain(domainName)
	xcheckuserf(ctx, err, "parsing domain")

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

	// host must be an absolute dns name, ending with a dot.
	lookupIPs := func(errors *[]string, host string) (ips []string, ourIPs, notOurIPs []net.IP, rerr error) {
		addrs, err := resolver.LookupHost(ctx, host)
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
				conn.Close()
			}
		}
	}

	// If at least one listener with SMTP enabled has specified NATed IPs, we'll skip
	// some checks related to these IPs.
	var isNAT bool
	for _, l := range mox.Conf.Static.Listeners {
		if l.IPsNATed && l.SMTP.Enabled {
			isNAT = true
			break
		}
	}

	var wg sync.WaitGroup

	// IPRev
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// For each mox.Conf.SpecifiedSMTPListenIPs, and each address for
		// mox.Conf.HostnameDomain, check if they resolve back to the host name.
		hostIPs := map[dns.Domain][]net.IP{}
		ips, err := resolver.LookupIP(ctx, "ip", mox.Conf.Static.HostnameDomain.ASCII+".")
		if err != nil {
			addf(&r.IPRev.Errors, "Looking up IPs for hostname: %s", err)
		}
		if !isNAT {
		nextip:
			for _, ip := range mox.Conf.Static.SpecifiedSMTPListenIPs {
				for _, xip := range ips {
					if ip.Equal(xip) {
						continue nextip
					}
				}
				ips = append(ips, ip)
			}
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
					addrs, err := resolver.LookupAddr(ctx, s)
					results <- result{host, s, addrs, err}
				}()
			}
		}
		r.IPRev.IPNames = map[string][]string{}
		for i := 0; i < n; i++ {
			lr := <-results
			host, addrs, ip, err := lr.Host, lr.Addrs, lr.IP, lr.Err
			if err != nil {
				addf(&r.IPRev.Errors, "Looking up reverse name for %s of %s: %v", ip, host, err)
				continue
			}
			if len(addrs) != 1 {
				addf(&r.IPRev.Errors, "Expected exactly 1 name for %s of %s, got %d (%v)", ip, host, len(addrs), addrs)
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
			if !match {
				addf(&r.IPRev.Errors, "Reverse name(s) %s for ip %s do not match hostname %s, which will cause other mail servers to reject incoming messages from this IP.", strings.Join(addrs, ","), ip, host)
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

		mxs, err := resolver.LookupMX(ctx, domain.ASCII+".")
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
			if isNAT {
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
					conn.Close()
				}
			}()

			end := time.Now().Add(10 * time.Second)
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			err = conn.SetDeadline(end)
			xlog.WithContext(ctx).Check(err, "setting deadline")

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
			conn.Close()
			conn = nil
			return nil
		}

		checkSMTPSTARTTLS := func() {
			// Initial errors are ignored, will already have been warned about by MX checks.
			mxs, err := resolver.LookupMX(ctx, domain.ASCII+".")
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

	// SPF
	// todo: add warnings if we have Transports with submission? admin should ensure their IPs are in the SPF record. it may be an IP(net), or an include. that means we cannot easily check for it. and should we first check the transport can be used from this domain (or an account that has this domain?). also see DKIM.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		// Verify a domain with the configured IPs that do SMTP.
		verifySPF := func(kind string, domain dns.Domain) (string, *SPFRecord, spf.Record) {
			_, txt, record, err := spf.Lookup(ctx, resolver, domain)
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
				status, mechanism, expl, err := spf.Evaluate(ctx, record, resolver, args)
				if err != nil {
					addf(&r.SPF.Errors, "Evaluating IP %q against %s SPF record: %s", ip, kind, err)
				} else if status != spf.StatusPass {
					addf(&r.SPF.Errors, "IP %q does not pass %s SPF evaluation, status not \"pass\" but %q (mechanism %q, explanation %q)", ip, kind, status, mechanism, expl)
				}
			}

			for _, l := range mox.Conf.Static.Listeners {
				if !l.SMTP.Enabled || l.IPsNATed {
					continue
				}
				for _, ipstr := range l.IPs {
					ip := net.ParseIP(ipstr)
					checkSPFIP(ip)
				}
			}
			for _, t := range mox.Conf.Static.Transports {
				if t.Socks != nil {
					for _, ip := range t.Socks.IPs {
						checkSPFIP(ip)
					}
				}
			}

			spfr.Directives = append(spfr.Directives, spf.Directive{Qualifier: "-", Mechanism: "all"})
			return txt, xrecord, spfr
		}

		// Check SPF record for domain.
		var dspfr spf.Record
		r.SPF.DomainTXT, r.SPF.DomainRecord, dspfr = verifySPF("domain", domain)
		// todo: possibly check all hosts for MX records? assuming they are also sending mail servers.
		r.SPF.HostTXT, r.SPF.HostRecord, _ = verifySPF("host", mox.Conf.Static.HostnameDomain)

		dtxt, err := dspfr.Record()
		if err != nil {
			addf(&r.SPF.Errors, "Making SPF record for instructions: %s", err)
		}
		domainspf := fmt.Sprintf("%s IN TXT %s", domain.ASCII+".", mox.TXTStrings(dtxt))

		// Check SPF record for sending host. ../rfc/7208:2263 ../rfc/7208:2287
		hostspf := fmt.Sprintf(`%s IN TXT "v=spf1 a -all"`, mox.Conf.Static.HostnameDomain.ASCII+".")

		addf(&r.SPF.Instructions, "Ensure DNS TXT records like the following exists:\n\n\t%s\n\t%s\n\nIf you have an existing mail setup, with other hosts also sending mail for you domain, you should add those IPs as well. You could replace \"-all\" with \"~all\" to treat mail sent from unlisted IPs as \"softfail\", or with \"?all\" for \"neutral\".", domainspf, hostspf)
	}()

	// DKIM
	// todo: add warnings if we have Transports with submission? admin should ensure DKIM records exist. we cannot easily check if they actually exist though. and should we first check the transport can be used from this domain (or an account that has this domain?). also see SPF.
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		var missing []string
		var haveEd25519 bool
		for sel, selc := range domConf.DKIM.Selectors {
			if _, ok := selc.Key.(ed25519.PrivateKey); ok {
				haveEd25519 = true
			}

			_, record, txt, err := dkim.Lookup(ctx, resolver, selc.Domain, domain)
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
		} else if !haveEd25519 {
			addf(&r.DKIM.Warnings, "Consider adding an ed25519 key: the keys are smaller, the cryptography faster and more modern.")
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
			instr += fmt.Sprintf("\n\t%s._domainkey IN TXT %s\n", sel, mox.TXTStrings(txt))
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

		_, dmarcDomain, record, txt, err := dmarc.Lookup(ctx, resolver, domain)
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
		localpart := smtp.Localpart("dmarc-reports")
		if domConf.DMARC != nil {
			localpart = domConf.DMARC.ParsedLocalpart
		} else {
			addf(&r.DMARC.Instructions, `Configure a DMARC destination in domain in config file. Localpart could be %q.`, localpart)
		}
		dmarcr := dmarc.Record{
			Version: "DMARC1",
			Policy:  "reject",
			AggregateReportAddresses: []dmarc.URI{
				{Address: fmt.Sprintf("mailto:%s!10m", smtp.NewAddress(localpart, domain).Pack(false))},
			},
			AggregateReportingInterval: 86400,
			Percentage:                 100,
		}
		instr := fmt.Sprintf("Ensure a DNS TXT record like the following exists:\n\n\t_dmarc IN TXT %s\n\nYou can start with testing mode by replacing p=reject with p=none. You can also request for the policy to be applied to a percentage of emails instead of all, by adding pct=X, with X between 0 and 100. Keep in mind that receiving mail servers will apply some anti-spam assessment regardless of the policy and whether it is applied to the message. The ruf= part requests daily aggregate reports to be sent to the specified address, which is automatically configured and reports automatically analyzed.", mox.TXTStrings(dmarcr.String()))
		addf(&r.DMARC.Instructions, instr)
	}()

	// TLSRPT
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		record, txt, err := tlsrpt.Lookup(ctx, resolver, domain)
		if err != nil {
			addf(&r.TLSRPT.Errors, "Looking up TLSRPT record: %s", err)
		}
		r.TLSRPT.TXT = txt
		if record != nil {
			r.TLSRPT.Record = &TLSRPTRecord{*record}
		}

		localpart := smtp.Localpart("tls-reports")
		if domConf.TLSRPT != nil {
			localpart = domConf.TLSRPT.ParsedLocalpart
		} else {
			addf(&r.TLSRPT.Errors, `Configure a TLSRPT destination in domain in config file. Localpart could be %q.`, localpart)
		}
		tlsrptr := &tlsrpt.Record{
			Version: "TLSRPTv1",
			// todo: should URI-encode the URI, including ',', '!' and ';'.
			RUAs: [][]string{{fmt.Sprintf("mailto:%s", smtp.NewAddress(localpart, domain).Pack(false))}},
		}
		instr := fmt.Sprintf(`TLSRPT is an opt-in mechanism to request feedback about TLS connectivity from remote SMTP servers when they connect to us. It allows detecting delivery problems and unwanted downgrades to plaintext SMTP connections. With TLSRPT you configure an email address to which reports should be sent. Remote SMTP servers will send a report once a day with the number of successful connections, and the number of failed connections including details that should help debugging/resolving any issues.

Ensure a DNS TXT record like the following exists:

	_smtp._tls IN TXT %s
`, mox.TXTStrings(tlsrptr.String()))
		addf(&r.TLSRPT.Instructions, instr)
	}()

	// MTA-STS
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		record, txt, cnames, err := mtasts.LookupRecord(ctx, resolver, domain)
		if err != nil {
			addf(&r.MTASTS.Errors, "Looking up MTA-STS record: %s", err)
		}
		if cnames != nil {
			r.MTASTS.CNAMEs = cnames
		} else {
			r.MTASTS.CNAMEs = []string{}
		}
		r.MTASTS.TXT = txt
		if record != nil {
			r.MTASTS.Record = &MTASTSRecord{*record}
		}

		policy, text, err := mtasts.FetchPolicy(ctx, domain)
		if err != nil {
			addf(&r.MTASTS.Errors, "Fetching MTA-STS policy: %s", err)
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

			mxl, _ := resolver.LookupMX(ctx, domain.ASCII+".")
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

		host := fmt.Sprintf("Ensure DNS CNAME/A/AAAA records exist that resolve mta-sts.%s to this mail server. For example:\n\n\t%s IN CNAME %s\n\n", domain.ASCII, "mta-sts."+domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")
		addf(&r.MTASTS.Instructions, host)

		mtastsr := mtasts.Record{
			Version: "STSv1",
			ID:      time.Now().Format("20060102T150405"),
		}
		dns := fmt.Sprintf("Ensure a DNS TXT record like the following exists:\n\n\t_mta-sts IN TXT %s\n\nConfigure the ID in the configuration file, it must be of the form [a-zA-Z0-9]{1,31}. It represents the version of the policy. For each policy change, you must change the ID to a new unique value. You could use a timestamp like 20220621T123000. When this field exists, an SMTP server will fetch a policy at https://mta-sts.%s/.well-known/mta-sts.txt. This policy is served by mox.", mox.TXTStrings(mtastsr.String()), domain.Name())
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
		var srvwg sync.WaitGroup
		srvwg.Add(len(reqs))
		for i := range reqs {
			go func(i int) {
				defer srvwg.Done()
				_, reqs[i].srvs, reqs[i].err = resolver.LookupSRV(ctx, reqs[i].name[1:], "tcp", domain.ASCII+".")
			}(i)
		}
		srvwg.Wait()

		instr := "Ensure DNS records like the following exist:\n\n"
		r.SRVConf.SRVs = map[string][]*net.SRV{}
		for _, req := range reqs {
			name := req.name + "_.tcp." + domain.ASCII
			instr += fmt.Sprintf("\t%s._tcp.%-*s IN SRV 0 1 %d %s\n", req.name, len("_submissions")-len(req.name)+len(domain.ASCII+"."), domain.ASCII+".", req.port, req.host)
			r.SRVConf.SRVs[req.name] = req.srvs
			if err != nil {
				addf(&r.SRVConf.Errors, "Looking up SRV record %q: %s", name, err)
			} else if len(req.srvs) == 0 {
				addf(&r.SRVConf.Errors, "Missing SRV record %q", name)
			} else if len(req.srvs) != 1 || req.srvs[0].Target != req.host || req.srvs[0].Port != req.port {
				addf(&r.SRVConf.Errors, "Unexpected SRV record(s) for %q", name)
			}
		}
		addf(&r.SRVConf.Instructions, instr)
	}()

	// Autoconf
	wg.Add(1)
	go func() {
		defer logPanic(ctx)
		defer wg.Done()

		addf(&r.Autoconf.Instructions, "Ensure a DNS CNAME record like the following exists:\n\n\tautoconfig.%s IN CNAME %s\n\nNote: the trailing dot is relevant, it makes the host name absolute instead of relative to the domain name.", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")

		host := "autoconfig." + domain.ASCII + "."
		ips, ourIPs, notOurIPs, err := lookupIPs(&r.Autoconf.Errors, host)
		if err != nil {
			addf(&r.Autoconf.Errors, "Looking up autoconfig host: %s", err)
			return
		}

		r.Autoconf.IPs = ips
		if !isNAT {
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

		addf(&r.Autodiscover.Instructions, "Ensure DNS records like the following exist:\n\n\t_autodiscover._tcp.%s IN SRV 0 1 443 autoconfig.%s\n\tautoconfig.%s IN CNAME %s\n\nNote: the trailing dots are relevant, it makes the host names absolute instead of relative to the domain name.", domain.ASCII+".", domain.ASCII+".", domain.ASCII+".", mox.Conf.Static.HostnameDomain.ASCII+".")

		_, srvs, err := resolver.LookupSRV(ctx, "autodiscover", "tcp", domain.ASCII+".")
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
			if !isNAT {
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

// Domains returns all configured domain names, in UTF-8 for IDNA domains.
func (Admin) Domains(ctx context.Context) []dns.Domain {
	l := []dns.Domain{}
	for _, s := range mox.Conf.Domains() {
		d, _ := dns.ParseDomain(s)
		l = append(l, d)
	}
	return l
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

// DomainLocalparts returns the encoded localparts and accounts configured in domain.
func (Admin) DomainLocalparts(ctx context.Context, domain string) (localpartAccounts map[string]string) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")
	_, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("no such domain"), "looking up domain")
	}
	return mox.Conf.DomainLocalparts(d)
}

// Accounts returns the names of all configured accounts.
func (Admin) Accounts(ctx context.Context) []string {
	l := mox.Conf.Accounts()
	sort.Slice(l, func(i, j int) bool {
		return l[i] < l[j]
	})
	return l
}

// Account returns the parsed configuration of an account.
func (Admin) Account(ctx context.Context, account string) map[string]any {
	ac, ok := mox.Conf.Account(account)
	if !ok {
		xcheckuserf(ctx, errors.New("no such account"), "looking up account")
	}

	// todo: should change sherpa to understand config.Account directly, with its anonymous structs.
	buf, err := json.Marshal(ac)
	xcheckf(ctx, err, "marshal to json")
	r := map[string]any{}
	err = json.Unmarshal(buf, &r)
	xcheckf(ctx, err, "unmarshal from json")

	return r
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
// domain (or all domains if empty). The reports are sorted first by period end
// (most recent first), then by domain.
func (Admin) TLSReports(ctx context.Context, start, end time.Time, domain string) (reports []tlsrptdb.TLSReportRecord) {
	records, err := tlsrptdb.RecordsPeriodDomain(ctx, start, end, domain)
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
func (Admin) TLSReportID(ctx context.Context, domain string, reportID int64) tlsrptdb.TLSReportRecord {
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
	Domain           string
	Success          int64
	Failure          int64
	ResultTypeCounts map[tlsrpt.ResultType]int
}

// TLSRPTSummaries returns a summary of received TLS reports overlapping with
// period start/end for one or all domains (when domain is empty).
// The returned summaries are ordered by domain name.
func (Admin) TLSRPTSummaries(ctx context.Context, start, end time.Time, domain string) (domainSummaries []TLSRPTSummary) {
	reports, err := tlsrptdb.RecordsPeriodDomain(ctx, start, end, domain)
	xcheckf(ctx, err, "fetching tlsrpt reports from database")
	summaries := map[string]TLSRPTSummary{}
	for _, r := range reports {
		sum := summaries[r.Domain]
		sum.Domain = r.Domain
		for _, result := range r.Report.Policies {
			sum.Success += result.Summary.TotalSuccessfulSessionCount
			sum.Failure += result.Summary.TotalFailureSessionCount
			for _, details := range result.FailureDetails {
				if sum.ResultTypeCounts == nil {
					sum.ResultTypeCounts = map[tlsrpt.ResultType]int{}
				}
				sum.ResultTypeCounts[details.ResultType]++
			}
		}
		summaries[r.Domain] = sum
	}
	sums := make([]TLSRPTSummary, 0, len(summaries))
	for _, sum := range summaries {
		sums = append(sums, sum)
	}
	sort.Slice(sums, func(i, j int) bool {
		return sums[i].Domain < sums[j].Domain
	})
	return sums
}

// DMARCReports returns DMARC reports overlapping with period start/end, for the
// given domain (or all domains if empty). The reports are sorted first by period
// end (most recent first), then by domain.
func (Admin) DMARCReports(ctx context.Context, start, end time.Time, domain string) (reports []dmarcdb.DomainFeedback) {
	reports, err := dmarcdb.RecordsPeriodDomain(ctx, start, end, domain)
	xcheckf(ctx, err, "fetching dmarc reports from database")
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
		xcheckuserf(ctx, err, "fetching dmarc report from database")
	}
	xcheckf(ctx, err, "fetching dmarc report from database")
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
	xcheckf(ctx, err, "fetching dmarc reports from database")
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
	resolver := dns.StrictResolver{Pkg: "webadmin"}
	names, err := resolver.LookupAddr(ctx, ip)
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
func (Admin) DNSBLStatus(ctx context.Context) map[string]map[string]string {
	resolver := dns.StrictResolver{Pkg: "check"}
	return dnsblsStatus(ctx, resolver)
}

func dnsblsStatus(ctx context.Context, resolver dns.Resolver) map[string]map[string]string {
	// todo: check health before using dnsbl?
	var dnsbls []dns.Domain
	if l, ok := mox.Conf.Static.Listeners["public"]; ok {
		for _, dnsbl := range l.SMTP.DNSBLs {
			zone, err := dns.ParseDomain(dnsbl)
			xcheckf(ctx, err, "parse dnsbl zone")
			dnsbls = append(dnsbls, zone)
		}
	}

	r := map[string]map[string]string{}
	for _, ip := range xsendingIPs(ctx) {
		if ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		ipstr := ip.String()
		r[ipstr] = map[string]string{}
		for _, zone := range dnsbls {
			status, expl, err := dnsbl.Lookup(ctx, resolver, zone, ip)
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
	return r
}

// DomainRecords returns lines describing DNS records that should exist for the
// configured domain.
func (Admin) DomainRecords(ctx context.Context, domain string) []string {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")
	dc, ok := mox.Conf.Domain(d)
	if !ok {
		xcheckuserf(ctx, errors.New("unknown domain"), "lookup domain")
	}
	records, err := mox.DomainRecords(dc, d)
	xcheckf(ctx, err, "dns records")
	return records
}

// DomainAdd adds a new domain and reloads the configuration.
func (Admin) DomainAdd(ctx context.Context, domain, accountName, localpart string) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	err = mox.DomainAdd(ctx, d, accountName, smtp.Localpart(localpart))
	xcheckf(ctx, err, "adding domain")
}

// DomainRemove removes an existing domain and reloads the configuration.
func (Admin) DomainRemove(ctx context.Context, domain string) {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	err = mox.DomainRemove(ctx, d)
	xcheckf(ctx, err, "removing domain")
}

// AccountAdd adds existing a new account, with an initial email address, and reloads the configuration.
func (Admin) AccountAdd(ctx context.Context, accountName, address string) {
	err := mox.AccountAdd(ctx, accountName, address)
	xcheckf(ctx, err, "adding account")
}

// AccountRemove removes an existing account and reloads the configuration.
func (Admin) AccountRemove(ctx context.Context, accountName string) {
	err := mox.AccountRemove(ctx, accountName)
	xcheckf(ctx, err, "removing account")
}

// AddressAdd adds a new address to the account, which must already exist.
func (Admin) AddressAdd(ctx context.Context, address, accountName string) {
	err := mox.AddressAdd(ctx, address, accountName)
	xcheckf(ctx, err, "adding address")
}

// AddressRemove removes an existing address.
func (Admin) AddressRemove(ctx context.Context, address string) {
	err := mox.AddressRemove(ctx, address)
	xcheckf(ctx, err, "removing address")
}

// SetPassword saves a new password for an account, invalidating the previous password.
// Sessions are not interrupted, and will keep working. New login attempts must use the new password.
// Password must be at least 8 characters.
func (Admin) SetPassword(ctx context.Context, accountName, password string) {
	if len(password) < 8 {
		panic(&sherpa.Error{Code: "user:error", Message: "password must be at least 8 characters"})
	}
	acc, err := store.OpenAccount(accountName)
	xcheckf(ctx, err, "open account")
	defer func() {
		err := acc.Close()
		xlog.Check(err, "closing account")
	}()
	err = acc.SetPassword(password)
	xcheckf(ctx, err, "setting password")
}

// SetAccountLimits set new limits on outgoing messages for an account.
func (Admin) SetAccountLimits(ctx context.Context, accountName string, maxOutgoingMessagesPerDay, maxFirstTimeRecipientsPerDay int) {
	err := mox.AccountLimitsSave(ctx, accountName, maxOutgoingMessagesPerDay, maxFirstTimeRecipientsPerDay)
	xcheckf(ctx, err, "saving account limits")
}

// ClientConfigDomain returns configurations for email clients, IMAP and
// Submission (SMTP) for the domain.
func (Admin) ClientConfigDomain(ctx context.Context, domain string) mox.ClientConfig {
	d, err := dns.ParseDomain(domain)
	xcheckuserf(ctx, err, "parsing domain")

	cc, err := mox.ClientConfigDomain(d)
	xcheckf(ctx, err, "client config for domain")
	return cc
}

// QueueList returns the messages currently in the outgoing queue.
func (Admin) QueueList(ctx context.Context) []queue.Msg {
	l, err := queue.List(ctx)
	xcheckf(ctx, err, "listing messages in queue")
	return l
}

// QueueSize returns the number of messages currently in the outgoing queue.
func (Admin) QueueSize(ctx context.Context) int {
	n, err := queue.Count(ctx)
	xcheckf(ctx, err, "listing messages in queue")
	return n
}

// QueueKick initiates delivery of a message from the queue and sets the transport
// to use for delivery.
func (Admin) QueueKick(ctx context.Context, id int64, transport string) {
	n, err := queue.Kick(ctx, id, "", "", &transport)
	if err == nil && n == 0 {
		err = errors.New("message not found")
	}
	xcheckf(ctx, err, "kick message in queue")
}

// QueueDrop removes a message from the queue.
func (Admin) QueueDrop(ctx context.Context, id int64) {
	n, err := queue.Drop(ctx, id, "", "")
	if err == nil && n == 0 {
		err = errors.New("message not found")
	}
	xcheckf(ctx, err, "drop message from queue")
}

// LogLevels returns the current log levels.
func (Admin) LogLevels(ctx context.Context) map[string]string {
	m := map[string]string{}
	for pkg, level := range mox.Conf.LogLevels() {
		m[pkg] = level.String()
	}
	return m
}

// LogLevelSet sets a log level for a package.
func (Admin) LogLevelSet(ctx context.Context, pkg string, levelStr string) {
	level, ok := mlog.Levels[levelStr]
	if !ok {
		xcheckuserf(ctx, errors.New("unknown"), "lookup level")
	}
	mox.Conf.LogLevelSet(pkg, level)
}

// LogLevelRemove removes a log level for a package, which cannot be the empty string.
func (Admin) LogLevelRemove(ctx context.Context, pkg string) {
	mox.Conf.LogLevelRemove(pkg)
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
	r, l := mox.Conf.WebServer()
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

	err := mox.WebserverConfigSet(ctx, domainRedirects, newConf.WebHandlers)
	xcheckf(ctx, err, "saving webserver config")

	savedConf = webserverConfig()
	savedConf.WebDomainRedirects = nil
	return savedConf
}

// Transports returns the configured transports, for sending email.
func (Admin) Transports(ctx context.Context) map[string]config.Transport {
	return mox.Conf.Static.Transports
}
