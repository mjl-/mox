package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/adns"
	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrpt"
	"github.com/mjl-/mox/webhook"
)

// Increased each time an outgoing connection is made for direct delivery. Used by
// dnsbl monitoring to pace querying.
var connectionCounter atomic.Int64

var (
	metricDestinations = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_destinations_total",
			Help: "Total destination (e.g. MX) lookups for delivery attempts, including those in mox_smtpclient_destinations_authentic_total.",
		},
	)
	metricDestinationsAuthentic = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_destinations_authentic_total",
			Help: "Destination (e.g. MX) lookups for delivery attempts authenticated with DNSSEC so they are candidates for DANE verification.",
		},
	)
	metricDestinationDANERequired = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_destination_dane_required_total",
			Help: "Total number of connections to hosts with valid TLSA records making DANE required.",
		},
	)
	metricDestinationDANESTARTTLSUnverified = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_destination_dane_starttlsunverified_total",
			Help: "Total number of connections with required DANE where all TLSA records were unusable.",
		},
	)
	metricDestinationDANEGatherTLSAErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_destination_dane_gathertlsa_errors_total",
			Help: "Total number of connections where looking up TLSA records resulted in an error.",
		},
	)
	// todo: recognize when "tls-required-no" message header caused a non-verifying certificate to be overridden. requires doing our own certificate validation after having set tls.Config.InsecureSkipVerify due to tls-required-no.
	metricTLSRequiredNoIgnored = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_queue_tlsrequiredno_ignored_total",
			Help: "Delivery attempts with TLS policy findings ignored due to message with TLS-Required: No header. Does not cover case where TLS certificate cannot be PKIX-verified.",
		},
		[]string{
			"ignored", // mtastspolicy (error getting policy), mtastsmx (mx host not allowed in policy), badtls (error negotiating tls), badtlsa (error fetching dane tlsa records)
		},
	)
	metricRequireTLSUnsupported = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_queue_requiretls_unsupported_total",
			Help: "Delivery attempts that failed due to message with REQUIRETLS.",
		},
		[]string{
			"reason", // nopolicy (no mta-sts and no dane), norequiretls (smtp server does not support requiretls)
		},
	)
	metricPlaintextFallback = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_queue_plaintext_fallback_total",
			Help: "Delivery attempts with fallback to plain text delivery.",
		},
	)
)

func ConnectionCounter() int64 {
	return connectionCounter.Load()
}

type msgResp struct {
	msg  *Msg
	resp smtpclient.Response
}

// Delivery by directly dialing (MX) hosts for destination domain of message.
//
// The returned results are for use in a TLSRPT report, it holds success/failure
// counts and failure details for delivery/connection attempts. The
// recipientDomainResult is for policies/counts/failures about the whole recipient
// domain (MTA-STS), its policy type can be empty, in which case there is no
// information (e.g. internal failure). hostResults are per-host details (DANE, one
// per MX target).
func deliverDirect(qlog mlog.Log, resolver dns.Resolver, dialer smtpclient.Dialer, ourHostname dns.Domain, transportName string, transportDirect *config.TransportDirect, msgs []*Msg, backoff time.Duration) (recipientDomainResult tlsrpt.Result, hostResults []tlsrpt.Result) {
	// High-level approach:
	// - Resolve domain to deliver to (CNAME), and determine hosts to try to deliver to (MX)
	// - Get MTA-STS policy for domain (optional). If present, only deliver to its
	//   allowlisted hosts and verify TLS against CA pool.
	// - For each host, attempt delivery. If the attempt results in a permanent failure
	//   (as claimed by remote with a 5xx SMTP response, or perhaps decided by us), the
	//   attempt can be aborted. Other errors are often temporary and may result in later
	//   successful delivery. But hopefully the delivery just succeeds. For each host:
	//   - If there is an MTA-STS policy, we only connect to allow-listed hosts.
	//   - We try to lookup DANE records (optional) and verify them if present.
	//   - If RequireTLS is true, we only deliver if the remote SMTP server implements it.
	//   - If RequireTLS is false, we'll fall back to regular delivery attempts without
	//     TLS verification and possibly without TLS at all, ignoring recipient domain/host
	//     MTA-STS and DANE policies.

	// For convenience, we use m0 to access properties that are shared over all
	// messages we are delivering.
	m0 := msgs[0]

	// Resolve domain and hosts to attempt delivery to.
	// These next-hop names are often the name under which we find MX records. The
	// expanded name is different from the original if the original was a CNAME,
	// possibly a chain. If there are no MX records, it can be an IP or the host
	// directly.
	origNextHop := m0.RecipientDomain.Domain
	ctx := mox.Shutdown
	haveMX, origNextHopAuthentic, expandedNextHopAuthentic, expandedNextHop, hostPrefs, permanent, err := smtpclient.GatherDestinations(ctx, qlog.Logger, resolver, m0.RecipientDomain)
	if err != nil {
		// If this is a DNSSEC authentication error, we'll collect it for TLS reporting.
		// Hopefully it's a temporary misconfiguration that is solve before we try to send
		// our report. We don't report as "dnssec-invalid", because that is defined as
		// being for DANE. ../rfc/8460:580
		var errCode adns.ErrorCode
		if errors.As(err, &errCode) && errCode.IsAuthentication() {
			// Result: ../rfc/8460:567
			reasonCode := fmt.Sprintf("dns-extended-error-%d-%s", errCode, strings.ReplaceAll(errCode.String(), " ", "-"))
			fd := tlsrpt.Details(tlsrpt.ResultValidationFailure, reasonCode)
			recipientDomainResult = tlsrpt.MakeResult(tlsrpt.NoPolicyFound, origNextHop, fd)
			recipientDomainResult.Summary.TotalFailureSessionCount++
		}
		if permanent {
			err = smtpclient.Error{Permanent: true, Err: err}
		}
		failMsgsDB(qlog, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, err)
		return
	}

	tlsRequiredNo := m0.RequireTLS != nil && !*m0.RequireTLS

	// Check for MTA-STS policy and enforce it if needed.
	// We must check at the original next-hop, i.e. recipient domain, not following any
	// CNAMEs. If we were to follow CNAMEs and ask for MTA-STS at that domain, it
	// would only take a single CNAME DNS response to direct us to an unrelated domain.
	var policy *mtasts.Policy // Policy can have mode enforce, testing and none.
	if !origNextHop.IsZero() {
		policy, recipientDomainResult, _, err = mtastsdb.Get(ctx, qlog.Logger, resolver, origNextHop)
		if err != nil {
			if tlsRequiredNo {
				qlog.Infox("mtasts lookup temporary error, continuing due to tls-required-no message header", err, slog.Any("domain", origNextHop))
				metricTLSRequiredNoIgnored.WithLabelValues("mtastspolicy").Inc()
			} else {
				qlog.Infox("mtasts lookup temporary error, aborting delivery attempt", err, slog.Any("domain", origNextHop))
				recipientDomainResult.Summary.TotalFailureSessionCount++
				failMsgsDB(qlog, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, err)
				return
			}
		}
		// note: policy can be nil, if a domain does not implement MTA-STS or it's the
		// first time we fetch the policy and if we encountered an error.
	}

	// We try delivery to each host until we have success or a permanent failure. So
	// for transient errors, we'll try the next host. For MX records pointing to a
	// dual stack host, we turn a permanent failure due to policy on the first delivery
	// attempt into a temporary failure and make sure to try the other address family
	// the next attempt. This should reduce issues due to one of our IPs being on a
	// block list. We won't try multiple IPs of the same address family. Surprisingly,
	// RFC 5321 does not specify a clear algorithm, but common practice is probably
	// ../rfc/3974:268.
	var remoteMTA dsn.NameIP
	var lastErr = errors.New("no error") // Can be smtpclient.Error.
	nmissingRequireTLS := 0
	// todo: should make distinction between host permanently not accepting the message, and the message not being deliverable permanently. e.g. a mx host may have a size limit, or not accept 8bitmime, while another host in the list does accept the message. same for smtputf8, ../rfc/6531:555
	for _, hp := range hostPrefs {
		h := hp.Host
		// ../rfc/8461:913
		if policy != nil && policy.Mode != mtasts.ModeNone && !policy.Matches(h.Domain) {
			// todo: perhaps only send tlsrpt failure if none of the mx hosts matched? reporting about each mismatch seems useful for domain owners, to discover mtasts policies they didn't update after changing mx. there is a risk a domain owner intentionally didn't put all mx'es in the mtasts policy, but they probably won't mind being reported about that.
			// Other error: Surprising that TLSRPT doesn't have an MTA-STS specific error code
			// for this case, it's a big part of the reason to have MTA-STS. ../rfc/8460:610
			// Result: ../rfc/8460:567 todo spec: propose adding a result for this case?
			fd := tlsrpt.Details(tlsrpt.ResultValidationFailure, "mtasts-policy-mx-mismatch")
			fd.ReceivingMXHostname = h.Domain.ASCII
			recipientDomainResult.Add(0, 0, fd)

			var policyHosts []string
			for _, mx := range policy.MX {
				policyHosts = append(policyHosts, mx.LogString())
			}
			if policy.Mode == mtasts.ModeEnforce {
				if tlsRequiredNo {
					qlog.Info("mx host does not match mta-sts policy in mode enforce, ignoring due to tls-required-no message header", slog.Any("host", h.Domain), slog.Any("policyhosts", policyHosts))
					metricTLSRequiredNoIgnored.WithLabelValues("mtastsmx").Inc()
				} else {
					lastErr = fmt.Errorf("mx host %s does not match enforced mta-sts policy with hosts %s", h.Domain, strings.Join(policyHosts, ","))
					qlog.Error("mx host does not match mta-sts policy in mode enforce, skipping", slog.Any("host", h.Domain), slog.Any("policyhosts", policyHosts))
					recipientDomainResult.Summary.TotalFailureSessionCount++
					continue
				}
			} else {
				qlog.Error("mx host does not match mta-sts policy, but it is not enforced, continuing", slog.Any("host", h.Domain), slog.Any("policyhosts", policyHosts))
			}
		}

		qlog.Info("delivering to remote", slog.Any("remote", h))
		nqlog := qlog.WithCid(mox.Cid())
		var remoteIP net.IP

		enforceMTASTS := policy != nil && policy.Mode == mtasts.ModeEnforce
		tlsMode := smtpclient.TLSOpportunistic
		tlsPKIX := false
		if enforceMTASTS {
			tlsMode = smtpclient.TLSRequiredStartTLS
			tlsPKIX = true
			// note: smtpclient will still go through PKIX verification, and report about it, but not fail the connection if not passing.
		}

		// Try to deliver to host. We can get various errors back. Like permanent failure
		// response codes, TCP, DNSSEC, TLS (opportunistic, i.e. optional with fallback to
		// without), etc. It's a balancing act to handle these situations correctly. We
		// don't want to bounce unnecessarily. But also not keep trying if there is no
		// chance of success.
		//
		// deliverHost will report generic TLS and MTA-STS-specific failures in
		// recipientDomainResult. If DANE is encountered, it will add a DANE reporting
		// result for generic TLS and DANE-specific errors.

		msgResps := make([]*msgResp, len(msgs))
		for i := range msgs {
			msgResps[i] = &msgResp{msg: msgs[i]}
		}

		result := deliverHost(nqlog, resolver, dialer, ourHostname, transportName, transportDirect, h, enforceMTASTS, haveMX, origNextHopAuthentic, origNextHop, expandedNextHopAuthentic, expandedNextHop, msgResps, tlsMode, tlsPKIX, &recipientDomainResult)

		var zerotype tlsrpt.PolicyType
		if result.hostResult.Policy.Type != zerotype {
			hostResults = append(hostResults, result.hostResult)
		}

		// If we had a TLS-related failure when doing TLS, and we don't have a requirement
		// for MTA-STS/DANE, we try again without TLS. This could be an old server that
		// only does ancient TLS versions, or has a misconfiguration. Note that
		// opportunistic TLS does not do regular certificate verification, so that can't be
		// the problem.
		// ../rfc/7435:459
		// We don't fall back to plain text for DMARC reports. ../rfc/7489:1768 ../rfc/7489:2683
		// We queue outgoing TLS reports with tlsRequiredNo, so reports can be delivered in
		// case of broken TLS.
		if result.err != nil && errors.Is(result.err, smtpclient.ErrTLS) && (!enforceMTASTS && tlsMode == smtpclient.TLSOpportunistic && !result.tlsDANE && !m0.IsDMARCReport || tlsRequiredNo) {
			metricPlaintextFallback.Inc()
			if tlsRequiredNo {
				metricTLSRequiredNoIgnored.WithLabelValues("badtls").Inc()
			}

			// todo future: add a configuration option to not fall back?
			nqlog.Info("connecting again for delivery attempt without tls",
				slog.Bool("enforcemtasts", enforceMTASTS),
				slog.Bool("tlsdane", result.tlsDANE),
				slog.Any("requiretls", m0.RequireTLS))
			result = deliverHost(nqlog, resolver, dialer, ourHostname, transportName, transportDirect, h, enforceMTASTS, haveMX, origNextHopAuthentic, origNextHop, expandedNextHopAuthentic, expandedNextHop, msgResps, smtpclient.TLSSkip, false, &tlsrpt.Result{})
		}

		remoteMTA = dsn.NameIP{Name: h.XString(false), IP: remoteIP}
		if result.err != nil {
			lastErr = result.err
			var cerr smtpclient.Error
			if errors.As(result.err, &cerr) {
				if cerr.Secode == smtp.SePol7MissingReqTLS30 {
					nmissingRequireTLS++
				}
				if cerr.Permanent {
					break
				}
			}
			continue
		}

		delMsgs := make([]Msg, len(result.delivered))
		for i, mr := range result.delivered {
			mqlog := nqlog.With(slog.Int64("msgid", mr.msg.ID), slog.Any("recipient", mr.msg.Recipient()))
			mqlog.Info("delivered from queue")
			mr.msg.markResult(mr.resp.Code, mr.resp.Secode, "", true)
			delMsgs[i] = *mr.msg
		}
		if len(delMsgs) > 0 {
			err := DB.Write(context.Background(), func(tx *bstore.Tx) error {
				return retireMsgs(nqlog, tx, webhook.EventDelivered, 0, "", nil, delMsgs...)
			})
			if err != nil {
				nqlog.Errorx("deleting messages from queue database after delivery", err)
			} else if err := removeMsgsFS(nqlog, delMsgs...); err != nil {
				nqlog.Errorx("removing queued messages from file system after delivery", err)
			}
			kick()
		}
		if len(result.failed) > 0 {
			err := DB.Write(context.Background(), func(tx *bstore.Tx) error {
				for _, mr := range result.failed {
					failMsgsTx(nqlog, tx, []*Msg{mr.msg}, m0.DialedIPs, backoff, remoteMTA, smtpclient.Error(mr.resp))
				}
				return nil
			})
			if err != nil {
				for _, mr := range result.failed {
					nqlog.Errorx("error processing delivery failure for messages", err,
						slog.Int64("msgid", mr.msg.ID),
						slog.Any("recipient", mr.msg.Recipient()))
				}
			}
			kick()
		}
		return
	}

	// In theory, we could make a failure permanent if we didn't find any mx host
	// matching the mta-sts policy AND the policy is fresh AND all DNS records leading
	// to the MX targets (including CNAME) have a TTL that is beyond the latest
	// possible delivery attempt. Until that time, configuration problems can be
	// corrected through DNS or policy update. Not sure if worth it in practice, there
	// is a good chance the MX records can still change, at least on initial delivery
	// failures.
	// todo: possibly detect that future deliveries will fail due to long ttl's of cached records that are preventing delivery.

	// If we failed due to requiretls not being satisfied, make the delivery permanent.
	// It is unlikely the recipient domain will implement requiretls during our retry
	// period. Best to let the sender know immediately.
	if len(hostPrefs) > 0 && nmissingRequireTLS == len(hostPrefs) {
		qlog.Info("marking delivery as permanently failed because recipient domain does not implement requiretls")
		err := smtpclient.Error{
			Permanent: true,
			Code:      smtp.C554TransactionFailed,
			Secode:    smtp.SePol7MissingReqTLS30,
			Err:       fmt.Errorf("destination servers do not support requiretls"),
		}
		failMsgsDB(qlog, msgs, m0.DialedIPs, backoff, remoteMTA, err)
		return
	}

	failMsgsDB(qlog, msgs, m0.DialedIPs, backoff, remoteMTA, lastErr)
	return
}

type deliverResult struct {
	tlsDANE    bool
	remoteIP   net.IP
	hostResult tlsrpt.Result

	// If err is set, no messages were delivered but delivered and failed are still
	// nil. If err is not set, delivered and always add up to all msgs requested to be
	// sent. All messages can be in failed.
	delivered []*msgResp
	failed    []*msgResp
	err       error
}

// deliverHost attempts to deliver msgs to host. All msgs must have the same
// delivery requirements (e.g. requiretls). Depending on tlsMode we'll do
// opportunistic or required STARTTLS or skip TLS entirely. Based on tlsPKIX we do
// PKIX/WebPKI verification (for MTA-STS). If we encounter DANE records, we verify
// those. If the message has a message header "TLS-Required: No", we ignore TLS
// verification errors.
//
// deliverHost updates DialedIPs of msgs, which must be saved in case of failure to
// deliver.
//
// The haveMX and next-hop-authentic fields are used to determine if DANE is
// applicable. The next-hop fields themselves are used to determine valid names
// during DANE TLS certificate verification.
//
// The returned hostResult holds TLSRPT reporting results for the connection
// attempt. Its policy type can be the zero value, indicating there was no finding
// (e.g. internal error).
//
// deliverHost may send a message multiple times: if the server doesn't accept
// multiple recipients for a message.
func deliverHost(log mlog.Log, resolver dns.Resolver, dialer smtpclient.Dialer, ourHostname dns.Domain, transportName string, transportDirect *config.TransportDirect, host dns.IPDomain, enforceMTASTS, haveMX, origNextHopAuthentic bool, origNextHop dns.Domain, expandedNextHopAuthentic bool, expandedNextHop dns.Domain, msgResps []*msgResp, tlsMode smtpclient.TLSMode, tlsPKIX bool, recipientDomainResult *tlsrpt.Result) (result deliverResult) {
	// About attempting delivery to multiple addresses of a host: ../rfc/5321:3898

	m0 := msgResps[0].msg
	tlsRequiredNo := m0.RequireTLS != nil && !*m0.RequireTLS

	var tlsDANE bool
	var remoteIP net.IP
	var hostResult tlsrpt.Result
	start := time.Now()
	defer func() {
		result.tlsDANE = tlsDANE
		result.remoteIP = remoteIP
		result.hostResult = hostResult

		mode := string(tlsMode)
		if tlsPKIX {
			mode += "+mtasts"
		}
		if tlsDANE {
			mode += "+dane"
		}

		r := deliveryResult(result.err, len(result.delivered), len(result.failed))
		d := float64(time.Since(start)) / float64(time.Second)
		metricDelivery.WithLabelValues(fmt.Sprintf("%d", m0.Attempts), transportName, mode, r).Observe(d)

		log.Debugx("queue deliverhost result", result.err,
			slog.Any("host", host),
			slog.String("result", r),
			slog.Int("delivered", len(result.delivered)),
			slog.Int("failed", len(result.failed)),
			slog.Any("tlsmode", tlsMode),
			slog.Bool("tlspkix", tlsPKIX),
			slog.Bool("tlsdane", tlsDANE),
			slog.Bool("tlsrequiredno", tlsRequiredNo),
			slog.Bool("badtls", result.err != nil && errors.Is(result.err, smtpclient.ErrTLS)),
			slog.Duration("duration", time.Since(start)))
	}()

	// Open message to deliver.
	f, err := os.Open(m0.MessagePath())
	if err != nil {
		return deliverResult{err: fmt.Errorf("open message file: %v", err)}
	}
	msgr := store.FileMsgReader(m0.MsgPrefix, f)
	defer func() {
		err := msgr.Close()
		log.Check(err, "closing message after delivery attempt")
	}()

	ctx, cancel := context.WithTimeout(mox.Shutdown, 30*time.Second)
	defer cancel()

	// We must lookup the IPs for the host name before checking DANE TLSA records. And
	// only check TLSA records for secure responses. This prevents problems with old
	// name servers returning an error for TLSA requests or letting it timeout (not
	// sending a response). ../rfc/7672:879
	var daneRecords []adns.TLSA
	var tlsHostnames []dns.Domain
	if host.IsDomain() {
		tlsHostnames = []dns.Domain{host.Domain}
	}
	for _, mr := range msgResps {
		if mr.msg.DialedIPs == nil {
			mr.msg.DialedIPs = map[string][]net.IP{}
		}
	}

	countResultFailure := func() {
		recipientDomainResult.Summary.TotalFailureSessionCount++
		hostResult.Summary.TotalFailureSessionCount++
	}

	metricDestinations.Inc()
	network := "ip"
	if transportDirect != nil {
		if network != transportDirect.IPFamily {
			log.Debug("set custom IP network family for direct transport", slog.Any("network", transportDirect.IPFamily))
			network = transportDirect.IPFamily
		}
	}
	authentic, expandedAuthentic, expandedHost, ips, dualstack, err := smtpclient.GatherIPs(ctx, log.Logger, resolver, network, host, m0.DialedIPs)
	destAuthentic := err == nil && authentic && origNextHopAuthentic && (!haveMX || expandedNextHopAuthentic) && host.IsDomain()
	if !destAuthentic {
		log.Debugx("not attempting verification with dane", err, slog.Bool("authentic", authentic), slog.Bool("expandedauthentic", expandedAuthentic))

		// Track a DNSSEC error if found.
		var errCode adns.ErrorCode
		if err != nil {
			if errors.As(err, &errCode) && errCode.IsAuthentication() {
				// Result: ../rfc/8460:567
				reasonCode := fmt.Sprintf("dns-extended-error-%d-%s", errCode, strings.ReplaceAll(errCode.String(), " ", "-"))
				fd := tlsrpt.Details(tlsrpt.ResultValidationFailure, reasonCode)
				hostResult = tlsrpt.MakeResult(tlsrpt.TLSA, host.Domain, fd)
				countResultFailure()
			}
		} else {
			// todo: we could lookup tlsa records, and log an error when they are not dnssec-signed. this should be interpreted simply as "not doing dane", but it could be useful to warn domain owners about, they may be under the impression they are dane-protected.
			hostResult = tlsrpt.MakeResult(tlsrpt.NoPolicyFound, host.Domain)
		}
	} else if tlsMode == smtpclient.TLSSkip {
		metricDestinationsAuthentic.Inc()

		// TLSSkip is used to fallback to plaintext, which is used with a TLS-Required: No
		// header to ignore the recipient domain's DANE policy.

		// possible err is propagated to below.
	} else {
		metricDestinationsAuthentic.Inc()

		// Look for TLSA records in either the expandedHost, or otherwise the original
		// host. ../rfc/7672:912
		var tlsaBaseDomain dns.Domain
		tlsDANE, daneRecords, tlsaBaseDomain, err = smtpclient.GatherTLSA(ctx, log.Logger, resolver, host.Domain, expandedNextHopAuthentic && expandedAuthentic, expandedHost)
		if tlsDANE {
			metricDestinationDANERequired.Inc()
		}
		if err != nil {
			metricDestinationDANEGatherTLSAErrors.Inc()
		}
		if err == nil && tlsDANE {
			tlsMode = smtpclient.TLSRequiredStartTLS
			hostResult = tlsrpt.Result{Policy: tlsrpt.TLSAPolicy(daneRecords, tlsaBaseDomain)}
			if len(daneRecords) == 0 {
				// If there are no usable DANE records, we still have to use TLS, but without
				// verifying its certificate. At least when there is no MTA-STS. Why? Perhaps to
				// prevent ossification? The SMTP TLSA specification has different behaviour than
				// the generic TLSA. "Usable" means different things in different places.
				// ../rfc/7672:718 ../rfc/6698:1845 ../rfc/6698:660
				log.Debug("no usable dane records, requiring starttls but not verifying with dane")
				metricDestinationDANESTARTTLSUnverified.Inc()
				daneRecords = nil
				// Result: ../rfc/8460:576 (this isn't technicall invalid, only all-unusable...)
				hostResult.FailureDetails = []tlsrpt.FailureDetails{
					{
						ResultType:          tlsrpt.ResultTLSAInvalid,
						ReceivingMXHostname: host.XString(false),
						FailureReasonCode:   "all-unusable-records+ignored",
					},
				}
			} else {
				log.Debug("delivery with required starttls with dane verification", slog.Any("allowedtlshostnames", tlsHostnames))
			}
			// Based on CNAMEs followed and DNSSEC-secure status, we must allow up to 4 host
			// names.
			tlsHostnames = smtpclient.GatherTLSANames(haveMX, expandedNextHopAuthentic, expandedAuthentic, origNextHop, expandedNextHop, host.Domain, tlsaBaseDomain)
		} else if !tlsDANE {
			log.Debugx("not doing opportunistic dane after gathering tlsa records", err)
			err = nil
			hostResult = tlsrpt.MakeResult(tlsrpt.NoPolicyFound, tlsaBaseDomain)
		} else if err != nil {
			fd := tlsrpt.Details(tlsrpt.ResultTLSAInvalid, "")
			var errCode adns.ErrorCode
			if errors.As(err, &errCode) {
				fd.FailureReasonCode = fmt.Sprintf("extended-dns-error-%d-%s", errCode, strings.ReplaceAll(errCode.String(), " ", "-"))
				if errCode.IsAuthentication() {
					// Result: ../rfc/8460:580
					fd.ResultType = tlsrpt.ResultDNSSECInvalid
					countResultFailure()
				}
			}
			hostResult = tlsrpt.Result{
				Policy:         tlsrpt.TLSAPolicy(daneRecords, tlsaBaseDomain),
				FailureDetails: []tlsrpt.FailureDetails{fd},
			}

			if tlsRequiredNo {
				log.Debugx("error gathering dane tlsa records with dane required, but continuing without validation due to tls-required-no message header", err)
				err = nil
				metricTLSRequiredNoIgnored.WithLabelValues("badtlsa").Inc()
			}
		}
		// else, err is propagated below.
	}

	// todo: for requiretls, should an MTA-STS policy in mode testing be treated as good enough for requiretls? let's be strict and assume not.
	// todo: ../rfc/8689:276 seems to specify stricter requirements on name in certificate than DANE (which allows original recipient domain name and cname-expanded name, and hints at following CNAME for MX targets as well, allowing both their original and expanded names too). perhaps the intent was just to say the name must be validated according to the relevant specifications?
	// todo: for requiretls, should we allow no usable dane records with requiretls? dane allows it, but doesn't seem in spirit of requiretls, so not allowing it.
	if err == nil && m0.RequireTLS != nil && *m0.RequireTLS && !(tlsDANE && len(daneRecords) > 0) && !enforceMTASTS {
		log.Info("verified tls is required, but destination has no usable dane records and no mta-sts policy, canceling delivery attempt to host")
		metricRequireTLSUnsupported.WithLabelValues("nopolicy").Inc()
		// Resond with proper enhanced status code. ../rfc/8689:301
		smtpErr := smtpclient.Error{
			Code:   smtp.C554TransactionFailed,
			Secode: smtp.SePol7MissingReqTLS30,
			Err:    fmt.Errorf("missing required tls verification mechanism"),
		}
		return deliverResult{err: smtpErr}
	}

	// Dial the remote host given the IPs if no error yet.
	var conn net.Conn
	if err == nil {
		connectionCounter.Add(1)
		conn, remoteIP, err = smtpclient.Dial(ctx, log.Logger, dialer, host, ips, 25, m0.DialedIPs, mox.Conf.Static.SpecifiedSMTPListenIPs)
	}
	cancel()

	// Set error for metrics.
	var dialResult string
	switch {
	case err == nil:
		dialResult = "ok"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		dialResult = "timeout"
	case errors.Is(err, context.Canceled):
		dialResult = "canceled"
	default:
		dialResult = "error"
	}
	metricConnection.WithLabelValues(dialResult).Inc()
	if err != nil {
		log.Debugx("connecting to remote smtp", err, slog.Any("host", host))
		return deliverResult{err: fmt.Errorf("dialing smtp server: %v", err)}
	}

	var mailFrom string
	if m0.SenderLocalpart != "" || !m0.SenderDomain.IsZero() {
		mailFrom = m0.Sender().XString(m0.SMTPUTF8)
	}

	// todo future: get closer to timeouts specified in rfc? ../rfc/5321:3610
	log = log.With(slog.Any("remoteip", remoteIP))
	ctx, cancel = context.WithTimeout(mox.Shutdown, 30*time.Minute)
	defer cancel()
	mox.Connections.Register(conn, "smtpclient", "queue")

	// Initialize SMTP session, sending EHLO/HELO and STARTTLS with specified tls mode.
	var firstHost dns.Domain
	var moreHosts []dns.Domain
	if len(tlsHostnames) > 0 {
		// For use with DANE-TA.
		firstHost = tlsHostnames[0]
		moreHosts = tlsHostnames[1:]
	}
	var verifiedRecord adns.TLSA
	opts := smtpclient.Opts{
		IgnoreTLSVerifyErrors: tlsRequiredNo,
		RootCAs:               mox.Conf.Static.TLS.CertPool,
		DANERecords:           daneRecords,
		DANEMoreHostnames:     moreHosts,
		DANEVerifiedRecord:    &verifiedRecord,
		RecipientDomainResult: recipientDomainResult,
		HostResult:            &hostResult,
	}
	sc, err := smtpclient.New(ctx, log.Logger, conn, tlsMode, tlsPKIX, ourHostname, firstHost, opts)
	defer func() {
		if sc == nil {
			err := conn.Close()
			log.Check(err, "closing smtp tcp connection")
		} else {
			err := sc.Close()
			log.Check(err, "closing smtp connection")
		}
		mox.Connections.Unregister(conn)
	}()
	if err == nil && m0.SenderAccount != "" {
		// Remember the STARTTLS and REQUIRETLS support for this recipient domain.
		// It is used in the webmail client, to show the recipient domain security mechanisms.
		// We always save only the last connection we actually encountered. There may be
		// multiple MX hosts, perhaps only some support STARTTLS and REQUIRETLS. We may not
		// be accurate for the whole domain, but we're only storing a hint.
		rdt := store.RecipientDomainTLS{
			Domain:     m0.RecipientDomain.Domain.Name(),
			STARTTLS:   sc.TLSConnectionState() != nil,
			RequireTLS: sc.SupportsRequireTLS(),
		}
		if err = updateRecipientDomainTLS(ctx, log, m0.SenderAccount, rdt); err != nil {
			err = fmt.Errorf("storing recipient domain tls status: %w", err)
		}
	}

	inspectError := func(err error) error {
		if cerr, ok := err.(smtpclient.Error); ok {
			// If we are being rejected due to policy reasons on the first
			// attempt and remote has both IPv4 and IPv6, we'll give it
			// another try. Our first IP may be in a block list, the address for
			// the other family perhaps is not.

			if cerr.Permanent && m0.Attempts == 1 && dualstack && strings.HasPrefix(cerr.Secode, "7.") {
				log.Debugx("change error type from permanent to transient", err, slog.Any("host", host), slog.Any("secode", cerr.Secode))
				cerr.Permanent = false
			}
			// If server does not implement requiretls, respond with that code. ../rfc/8689:301
			if errors.Is(cerr.Err, smtpclient.ErrRequireTLSUnsupported) {
				cerr.Secode = smtp.SePol7MissingReqTLS30
				metricRequireTLSUnsupported.WithLabelValues("norequiretls").Inc()
			}
			return cerr
		}
		return err
	}

	if err != nil {
		return deliverResult{err: inspectError(err)}
	}

	// SMTP session is ready. Finally try to actually deliver.
	has8bit := m0.Has8bit
	smtputf8 := m0.SMTPUTF8
	var msg io.Reader = msgr
	resetReader := msgr.Reset
	size := m0.Size
	if m0.DSNUTF8 != nil && sc.Supports8BITMIME() && sc.SupportsSMTPUTF8() {
		has8bit = true
		smtputf8 = true
		size = int64(len(m0.DSNUTF8))
		msg = bytes.NewReader(m0.DSNUTF8)
		resetReader = func() {
			msg = bytes.NewReader(m0.DSNUTF8)
		}
	}

	// Try to deliver messages. We'll do multiple transactions if the smtp server responds
	// with "too many recipients".
	todo := msgResps
	var delivered, failed []*msgResp
	for len(todo) > 0 {
		resetReader()

		// SMTP server may limit number of recipients in single transaction.
		n := len(todo)
		if sc.ExtLimitRcptMax > 0 && sc.ExtLimitRcptMax < len(todo) {
			n = sc.ExtLimitRcptMax
		}

		rcpts := make([]string, n)
		for i, mr := range todo[:n] {
			rcpts[i] = mr.msg.Recipient().XString(m0.SMTPUTF8)
		}

		// Only require that remote announces 8bitmime extension when in pedantic mode. All
		// relevant systems nowadays should accept "8-bit" messages, some unfortunately
		// don't announce support. In theory we could rewrite the submitted message to be
		// 7-bit-only, but the trouble likely isn't worth it.
		req8bit := has8bit && mox.Pedantic

		resps, err := sc.DeliverMultiple(ctx, mailFrom, rcpts, size, msg, req8bit, smtputf8, m0.RequireTLS != nil && *m0.RequireTLS)
		if err != nil && (len(resps) == 0 && n == len(msgResps) || len(resps) == len(msgResps)) {
			// If error and it applies to all recipients, return a single error.
			return deliverResult{err: inspectError(err)}
		}
		var ntodo []*msgResp
		for i, mr := range todo[:n] {
			if err != nil {
				if cerr, ok := err.(smtpclient.Error); ok {
					mr.resp = smtpclient.Response(cerr)
				} else {
					mr.resp = smtpclient.Response{Err: err}
				}
				failed = append(failed, mr)
			} else if i > 0 && (resps[i].Code == smtp.C452StorageFull || resps[i].Code == smtp.C552MailboxFull) {
				ntodo = append(ntodo, mr)
			} else if resps[i].Code == smtp.C250Completed {
				mr.resp = resps[i]
				delivered = append(delivered, mr)
			} else {
				failed = append(failed, mr)
			}
		}
		todo = append(ntodo, todo[n:]...)

		// We don't take LIMITS MAILMAX into account. Multiple MAIL commands are normal in
		// SMTP. If the server doesn't support that, it will likely return a temporary
		// error. So at least we'll try again. This would be quite unusual. And wasteful,
		// because we would immediately dial again, do the TLS handshake, EHLO, etc. Let's
		// implement such a limit when we see it in practice.
	}

	return deliverResult{delivered: delivered, failed: failed}
}

// Update (overwite) last known starttls/requiretls support for recipient domain.
func updateRecipientDomainTLS(ctx context.Context, log mlog.Log, senderAccount string, rdt store.RecipientDomainTLS) error {
	acc, err := store.OpenAccount(log, senderAccount, false)
	if err != nil {
		return fmt.Errorf("open account: %w", err)
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()
	err = acc.DB.Write(ctx, func(tx *bstore.Tx) error {
		// First delete any existing record.
		if err := tx.Delete(&store.RecipientDomainTLS{Domain: rdt.Domain}); err != nil && err != bstore.ErrAbsent {
			return fmt.Errorf("removing previous recipient domain tls status: %w", err)
		}
		// Insert new record.
		return tx.Insert(&rdt)
	})
	if err != nil {
		return fmt.Errorf("adding recipient domain tls status to account database: %w", err)
	}
	return nil
}
