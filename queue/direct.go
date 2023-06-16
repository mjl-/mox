package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// todo: rename function, perhaps put some of the params in a delivery struct so we don't pass all the params all the time?
func fail(qlog *mlog.Log, m Msg, backoff time.Duration, permanent bool, remoteMTA dsn.NameIP, secodeOpt, errmsg string) {
	if permanent || m.Attempts >= 8 {
		qlog.Errorx("permanent failure delivering from queue", errors.New(errmsg))
		queueDSNFailure(qlog, m, remoteMTA, secodeOpt, errmsg)

		if err := queueDelete(context.Background(), m.ID); err != nil {
			qlog.Errorx("deleting message from queue after permanent failure", err)
		}
		return
	}

	qup := bstore.QueryDB[Msg](context.Background(), DB)
	qup.FilterID(m.ID)
	if _, err := qup.UpdateNonzero(Msg{LastError: errmsg, DialedIPs: m.DialedIPs}); err != nil {
		qlog.Errorx("storing delivery error", err, mlog.Field("deliveryerror", errmsg))
	}

	if m.Attempts == 5 {
		// We've attempted deliveries at these intervals: 0, 7.5m, 15m, 30m, 1h, 2u.
		// Let sender know delivery is delayed.
		qlog.Errorx("temporary failure delivering from queue, sending delayed dsn", errors.New(errmsg), mlog.Field("backoff", backoff))

		retryUntil := m.LastAttempt.Add((4 + 8 + 16) * time.Hour)
		queueDSNDelay(qlog, m, remoteMTA, secodeOpt, errmsg, retryUntil)
	} else {
		qlog.Errorx("temporary failure delivering from queue", errors.New(errmsg), mlog.Field("backoff", backoff), mlog.Field("nextattempt", m.NextAttempt))
	}
}

// Delivery by directly dialing MX hosts for destination domain.
func deliverDirect(cid int64, qlog *mlog.Log, resolver dns.Resolver, dialer contextDialer, ourHostname dns.Domain, transportName string, m Msg, backoff time.Duration) {
	hosts, effectiveDomain, permanent, err := gatherHosts(resolver, m, cid, qlog)
	if err != nil {
		fail(qlog, m, backoff, permanent, dsn.NameIP{}, "", err.Error())
		return
	}

	// Check for MTA-STS policy and enforce it if needed. We have to check the
	// effective domain (found after following CNAME record(s)): there will certainly
	// not be an mtasts record for the original recipient domain, because that is not
	// allowed when a CNAME record is present.
	var policyFresh bool
	var policy *mtasts.Policy
	tlsModeDefault := smtpclient.TLSOpportunistic
	if !effectiveDomain.IsZero() {
		cidctx := context.WithValue(mox.Shutdown, mlog.CidKey, cid)
		policy, policyFresh, err = mtastsdb.Get(cidctx, resolver, effectiveDomain)
		if err != nil {
			// No need to refuse to deliver if we have some mtasts error.
			qlog.Infox("mtasts failed, continuing with strict tls requirement", err, mlog.Field("domain", effectiveDomain))
			tlsModeDefault = smtpclient.TLSStrictStartTLS
		}
		// note: policy can be nil, if a domain does not implement MTA-STS or its the first
		// time we fetch the policy and if we encountered an error.
	}

	// We try delivery to each record until we have success or a permanent failure. So
	// for transient errors, we'll try the next MX record. For MX records pointing to a
	// dual stack host, we turn a permanent failure due to policy on the first delivery
	// attempt into a temporary failure and make sure to try the other address family
	// the next attempt. This should reduce issues due to one of our IPs being on a
	// block list. We won't try multiple IPs of the same address family. Surprisingly,
	// RFC 5321 does not specify a clear algorithm, but common practicie is probably
	// ../rfc/3974:268.
	var remoteMTA dsn.NameIP
	var secodeOpt, errmsg string
	permanent = false
	mtastsFailure := true
	// todo: should make distinction between host permanently not accepting the message, and the message not being deliverable permanently. e.g. a mx host may have a size limit, or not accept 8bitmime, while another host in the list does accept the message. same for smtputf8, ../rfc/6531:555
	for _, h := range hosts {
		var badTLS, ok bool

		// ../rfc/8461:913
		if policy != nil && policy.Mode == mtasts.ModeEnforce && !policy.Matches(h.Domain) {
			var policyHosts []string
			for _, mx := range policy.MX {
				policyHosts = append(policyHosts, mx.LogString())
			}
			errmsg = fmt.Sprintf("mx host %s does not match enforced mta-sts policy with hosts %s", h.Domain, strings.Join(policyHosts, ","))
			qlog.Error("mx host does not match enforce mta-sts policy, skipping", mlog.Field("host", h.Domain), mlog.Field("policyhosts", policyHosts))
			continue
		}

		qlog.Info("delivering to remote", mlog.Field("remote", h), mlog.Field("queuecid", cid))
		cid := mox.Cid()
		nqlog := qlog.WithCid(cid)
		var remoteIP net.IP
		tlsMode := tlsModeDefault
		if policy != nil && policy.Mode == mtasts.ModeEnforce {
			tlsMode = smtpclient.TLSStrictStartTLS
		}
		permanent, badTLS, secodeOpt, remoteIP, errmsg, ok = deliverHost(nqlog, resolver, dialer, cid, ourHostname, transportName, h, &m, tlsMode)
		if !ok && badTLS && tlsMode == smtpclient.TLSOpportunistic {
			// In case of failure with opportunistic TLS, try again without TLS. ../rfc/7435:459
			// todo future: revisit this decision. perhaps it should be a configuration option that defaults to not doing this?
			nqlog.Info("connecting again for delivery attempt without tls")
			permanent, badTLS, secodeOpt, remoteIP, errmsg, ok = deliverHost(nqlog, resolver, dialer, cid, ourHostname, transportName, h, &m, smtpclient.TLSSkip)
		}
		if ok {
			nqlog.Info("delivered from queue")
			if err := queueDelete(context.Background(), m.ID); err != nil {
				nqlog.Errorx("deleting message from queue after delivery", err)
			}
			return
		}
		remoteMTA = dsn.NameIP{Name: h.XString(false), IP: remoteIP}
		if !badTLS {
			mtastsFailure = false
		}
		if permanent {
			break
		}
	}
	if mtastsFailure && policyFresh {
		permanent = true
	}

	fail(qlog, m, backoff, permanent, remoteMTA, secodeOpt, errmsg)
}

var (
	errCNAMELoop  = errors.New("cname loop")
	errCNAMELimit = errors.New("too many cname records")
	errNoRecord   = errors.New("no dns record")
	errDNS        = errors.New("dns lookup error")
	errNoMail     = errors.New("domain does not accept email as indicated with single dot for mx record")
)

// Gather hosts to try to deliver to. We start with the straight-forward MX record.
// If that does not exist, we'll look for CNAME of the entire domain (following
// chains if needed). If a CNAME does not exist, but the domain name has an A or
// AAAA record, we'll try delivery directly to that host.
// ../rfc/5321:3824
func gatherHosts(resolver dns.Resolver, m Msg, cid int64, qlog *mlog.Log) (hosts []dns.IPDomain, effectiveDomain dns.Domain, permanent bool, err error) {
	if len(m.RecipientDomain.IP) > 0 {
		return []dns.IPDomain{m.RecipientDomain}, effectiveDomain, false, nil
	}

	// We start out delivering to the recipient domain. We follow CNAMEs a few times.
	rcptDomain := m.RecipientDomain.Domain
	// Domain we are actually delivering to, after following CNAME record(s).
	effectiveDomain = rcptDomain
	domainsSeen := map[string]bool{}
	for i := 0; ; i++ {
		if domainsSeen[effectiveDomain.ASCII] {
			return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain %s: already saw %s", errCNAMELoop, rcptDomain, effectiveDomain)
		}
		domainsSeen[effectiveDomain.ASCII] = true

		// note: The Go resolver returns the requested name if the domain has no CNAME record but has a host record.
		if i == 16 {
			// We have a maximum number of CNAME records we follow. There is no hard limit for
			// DNS, and you might think folks wouldn't configure CNAME chains at all, but for
			// (non-mail) domains, CNAME chains of 10 records have been encountered according
			// to the internet.
			return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain %s, last resolved domain %s", errCNAMELimit, rcptDomain, effectiveDomain)
		}

		cidctx := context.WithValue(mox.Context, mlog.CidKey, cid)
		ctx, cancel := context.WithTimeout(cidctx, 30*time.Second)
		defer cancel()
		// Note: LookupMX can return an error and still return records: Invalid records are
		// filtered out and an error returned. We must process any records that are valid.
		// Only if all are unusable will we return an error. ../rfc/5321:3851
		mxl, err := resolver.LookupMX(ctx, effectiveDomain.ASCII+".")
		cancel()
		if err != nil && len(mxl) == 0 {
			if !dns.IsNotFound(err) {
				return nil, effectiveDomain, false, fmt.Errorf("%w: mx lookup for %s: %v", errDNS, effectiveDomain, err)
			}

			// No MX record. First attempt CNAME lookup. ../rfc/5321:3838 ../rfc/3974:197
			ctx, cancel = context.WithTimeout(cidctx, 30*time.Second)
			defer cancel()
			cname, err := resolver.LookupCNAME(ctx, effectiveDomain.ASCII+".")
			cancel()
			if err != nil && !dns.IsNotFound(err) {
				return nil, effectiveDomain, false, fmt.Errorf("%w: cname lookup for %s: %v", errDNS, effectiveDomain, err)
			}
			if err == nil && cname != effectiveDomain.ASCII+"." {
				d, err := dns.ParseDomain(strings.TrimSuffix(cname, "."))
				if err != nil {
					return nil, effectiveDomain, true, fmt.Errorf("%w: parsing cname domain %s: %v", errDNS, effectiveDomain, err)
				}
				effectiveDomain = d
				// Start again with new domain.
				continue
			}

			// See if the host exists. If so, attempt delivery directly to host. ../rfc/5321:3842
			ctx, cancel = context.WithTimeout(cidctx, 30*time.Second)
			defer cancel()
			_, err = resolver.LookupHost(ctx, effectiveDomain.ASCII+".")
			cancel()
			if dns.IsNotFound(err) {
				return nil, effectiveDomain, true, fmt.Errorf("%w: recipient domain/host %s", errNoRecord, effectiveDomain)
			} else if err != nil {
				return nil, effectiveDomain, false, fmt.Errorf("%w: looking up host %s because of no mx record: %v", errDNS, effectiveDomain, err)
			}
			hosts = []dns.IPDomain{{Domain: effectiveDomain}}
		} else if err != nil {
			qlog.Infox("partial mx failure, attempting delivery to valid mx records", err)
		}

		// ../rfc/7505:122
		if err == nil && len(mxl) == 1 && mxl[0].Host == "." {
			return nil, effectiveDomain, true, errNoMail
		}

		// The Go resolver already sorts by preference, randomizing records of same
		// preference. ../rfc/5321:3885
		for _, mx := range mxl {
			host, err := dns.ParseDomain(strings.TrimSuffix(mx.Host, "."))
			if err != nil {
				// note: should not happen because Go resolver already filters these out.
				return nil, effectiveDomain, true, fmt.Errorf("%w: invalid host name in mx record %q: %v", errDNS, mx.Host, err)
			}
			hosts = append(hosts, dns.IPDomain{Domain: host})
		}
		if len(hosts) > 0 {
			err = nil
		}
		return hosts, effectiveDomain, false, err
	}
}

// deliverHost attempts to deliver m to host.
// deliverHost updated m.DialedIPs, which must be saved in case of failure to deliver.
func deliverHost(log *mlog.Log, resolver dns.Resolver, dialer contextDialer, cid int64, ourHostname dns.Domain, transportName string, host dns.IPDomain, m *Msg, tlsMode smtpclient.TLSMode) (permanent, badTLS bool, secodeOpt string, remoteIP net.IP, errmsg string, ok bool) {
	// About attempting delivery to multiple addresses of a host: ../rfc/5321:3898

	start := time.Now()
	var deliveryResult string
	defer func() {
		metricDelivery.WithLabelValues(fmt.Sprintf("%d", m.Attempts), transportName, string(tlsMode), deliveryResult).Observe(float64(time.Since(start)) / float64(time.Second))
		log.Debug("queue deliverhost result", mlog.Field("host", host), mlog.Field("attempt", m.Attempts), mlog.Field("tlsmode", tlsMode), mlog.Field("permanent", permanent), mlog.Field("badtls", badTLS), mlog.Field("secodeopt", secodeOpt), mlog.Field("errmsg", errmsg), mlog.Field("ok", ok), mlog.Field("duration", time.Since(start)))
	}()

	f, err := os.Open(m.MessagePath())
	if err != nil {
		return false, false, "", nil, fmt.Sprintf("open message file: %s", err), false
	}
	msgr := store.FileMsgReader(m.MsgPrefix, f)
	defer func() {
		err := msgr.Close()
		log.Check(err, "closing message after delivery attempt")
	}()

	cidctx := context.WithValue(mox.Context, mlog.CidKey, cid)
	ctx, cancel := context.WithTimeout(cidctx, 30*time.Second)
	defer cancel()

	conn, ip, dualstack, err := dialHost(ctx, log, resolver, dialer, host, 25, m)
	remoteIP = ip
	cancel()
	var result string
	switch {
	case err == nil:
		result = "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		result = "timeout"
	case errors.Is(err, context.Canceled):
		result = "canceled"
	default:
		result = "error"
	}
	metricConnection.WithLabelValues(result).Inc()
	if err != nil {
		log.Debugx("connecting to remote smtp", err, mlog.Field("host", host))
		return false, false, "", ip, fmt.Sprintf("dialing smtp server: %v", err), false
	}

	var mailFrom string
	if m.SenderLocalpart != "" || !m.SenderDomain.IsZero() {
		mailFrom = m.Sender().XString(m.SMTPUTF8)
	}
	rcptTo := m.Recipient().XString(m.SMTPUTF8)

	// todo future: get closer to timeouts specified in rfc? ../rfc/5321:3610
	log = log.Fields(mlog.Field("remoteip", ip))
	ctx, cancel = context.WithTimeout(cidctx, 30*time.Minute)
	defer cancel()
	mox.Connections.Register(conn, "smtpclient", "queue")
	sc, err := smtpclient.New(ctx, log, conn, tlsMode, ourHostname, host.Domain, nil)
	defer func() {
		if sc == nil {
			conn.Close()
		} else {
			sc.Close()
		}
		mox.Connections.Unregister(conn)
	}()
	if err == nil {
		has8bit := m.Has8bit
		smtputf8 := m.SMTPUTF8
		var msg io.Reader = msgr
		size := m.Size
		if m.DSNUTF8 != nil && sc.Supports8BITMIME() && sc.SupportsSMTPUTF8() {
			has8bit = true
			smtputf8 = true
			size = int64(len(m.DSNUTF8))
			msg = bytes.NewReader(m.DSNUTF8)
		}
		err = sc.Deliver(ctx, mailFrom, rcptTo, size, msg, has8bit, smtputf8)
	}
	if err != nil {
		log.Infox("delivery failed", err)
	}
	var cerr smtpclient.Error
	switch {
	case err == nil:
		deliveryResult = "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		deliveryResult = "timeout"
	case errors.Is(err, context.Canceled):
		deliveryResult = "canceled"
	case errors.As(err, &cerr):
		deliveryResult = "temperror"
		if cerr.Permanent {
			deliveryResult = "permerror"
		}
	default:
		deliveryResult = "error"
	}
	if err == nil {
		return false, false, "", ip, "", true
	} else if cerr, ok := err.(smtpclient.Error); ok {
		// If we are being rejected due to policy reasons on the first
		// attempt and remote has both IPv4 and IPv6, we'll give it
		// another try. Our first IP may be in a block list, the address for
		// the other family perhaps is not.
		permanent := cerr.Permanent
		if permanent && m.Attempts == 1 && dualstack && strings.HasPrefix(cerr.Secode, "7.") {
			permanent = false
		}
		return permanent, errors.Is(cerr, smtpclient.ErrTLS), cerr.Secode, ip, cerr.Error(), false
	} else {
		return false, errors.Is(cerr, smtpclient.ErrTLS), "", ip, err.Error(), false
	}
}
