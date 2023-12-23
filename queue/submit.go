package queue

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// todo: reuse connection? do fewer concurrently (other than with direct delivery).

// deliver via another SMTP server, e.g. relaying to a smart host, possibly
// with authentication (submission).
func deliverSubmit(qlog mlog.Log, resolver dns.Resolver, dialer smtpclient.Dialer, m Msg, backoff time.Duration, transportName string, transport *config.TransportSMTP, dialTLS bool, defaultPort int) {
	// todo: configurable timeouts

	port := transport.Port
	if port == 0 {
		port = defaultPort
	}

	tlsMode := smtpclient.TLSRequiredStartTLS
	tlsPKIX := true
	if dialTLS {
		tlsMode = smtpclient.TLSImmediate
	} else if transport.STARTTLSInsecureSkipVerify {
		tlsMode = smtpclient.TLSRequiredStartTLS
		tlsPKIX = false
	} else if transport.NoSTARTTLS {
		tlsMode = smtpclient.TLSSkip
		tlsPKIX = false
	}
	start := time.Now()
	var deliveryResult string
	var permanent bool
	var secodeOpt string
	var errmsg string
	var success bool
	defer func() {
		metricDelivery.WithLabelValues(fmt.Sprintf("%d", m.Attempts), transportName, string(tlsMode), deliveryResult).Observe(float64(time.Since(start)) / float64(time.Second))
		qlog.Debug("queue deliversubmit result",
			slog.Any("host", transport.DNSHost),
			slog.Int("port", port),
			slog.Int("attempt", m.Attempts),
			slog.Bool("permanent", permanent),
			slog.String("secodeopt", secodeOpt),
			slog.String("errmsg", errmsg),
			slog.Bool("ok", success),
			slog.Duration("duration", time.Since(start)))
	}()

	// todo: SMTP-DANE should be used when relaying on port 25.
	// ../rfc/7672:1261

	// todo: for submission, understand SRV records, and even DANE.

	ctx := mox.Shutdown

	// If submit was done with REQUIRETLS extension for SMTP, we must verify TLS
	// certificates. If our submission connection is not configured that way, abort.
	requireTLS := m.RequireTLS != nil && *m.RequireTLS
	if requireTLS && (tlsMode != smtpclient.TLSRequiredStartTLS && tlsMode != smtpclient.TLSImmediate || !tlsPKIX) {
		errmsg = fmt.Sprintf("transport %s: message requires verified tls but transport does not verify tls", transportName)
		fail(ctx, qlog, m, backoff, true, dsn.NameIP{}, smtp.SePol7MissingReqTLS, errmsg)
		return
	}

	dialctx, dialcancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialcancel()
	if m.DialedIPs == nil {
		m.DialedIPs = map[string][]net.IP{}
	}
	_, _, _, ips, _, err := smtpclient.GatherIPs(dialctx, qlog.Logger, resolver, dns.IPDomain{Domain: transport.DNSHost}, m.DialedIPs)
	var conn net.Conn
	if err == nil {
		if m.DialedIPs == nil {
			m.DialedIPs = map[string][]net.IP{}
		}
		conn, _, err = smtpclient.Dial(dialctx, qlog.Logger, dialer, dns.IPDomain{Domain: transport.DNSHost}, ips, port, m.DialedIPs, mox.Conf.Static.SpecifiedSMTPListenIPs)
	}
	addr := net.JoinHostPort(transport.Host, fmt.Sprintf("%d", port))
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
		if conn != nil {
			err := conn.Close()
			qlog.Check(err, "closing connection")
		}
		qlog.Errorx("dialing for submission", err, slog.String("remote", addr))
		errmsg = fmt.Sprintf("transport %s: dialing %s for submission: %v", transportName, addr, err)
		fail(ctx, qlog, m, backoff, false, dsn.NameIP{}, "", errmsg)
		return
	}
	dialcancel()

	var auth func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error)
	if transport.Auth != nil {
		a := transport.Auth
		auth = func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
			var supportsscramsha1plus, supportsscramsha256plus bool
			for _, mech := range a.EffectiveMechanisms {
				if !slices.Contains(mechanisms, mech) {
					switch mech {
					case "SCRAM-SHA-1-PLUS":
						supportsscramsha1plus = cs != nil
					case "SCRAM-SHA-256-PLUS":
						supportsscramsha256plus = cs != nil
					}
					continue
				}
				if mech == "SCRAM-SHA-256-PLUS" && cs != nil {
					return sasl.NewClientSCRAMSHA256PLUS(a.Username, a.Password, *cs), nil
				} else if mech == "SCRAM-SHA-256" {
					return sasl.NewClientSCRAMSHA256(a.Username, a.Password, supportsscramsha256plus), nil
				} else if mech == "SCRAM-SHA-1-PLUS" && cs != nil {
					return sasl.NewClientSCRAMSHA1PLUS(a.Username, a.Password, *cs), nil
				} else if mech == "SCRAM-SHA-1" {
					return sasl.NewClientSCRAMSHA1(a.Username, a.Password, supportsscramsha1plus), nil
				} else if mech == "CRAM-MD5" {
					return sasl.NewClientCRAMMD5(a.Username, a.Password), nil
				} else if mech == "PLAIN" {
					return sasl.NewClientPlain(a.Username, a.Password), nil
				}
				return nil, fmt.Errorf("internal error: unrecognized authentication mechanism %q for transport %s", mech, transportName)
			}

			// No mutually supported algorithm.
			return nil, nil
		}
	}
	clientctx, clientcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer clientcancel()
	opts := smtpclient.Opts{
		Auth:    auth,
		RootCAs: mox.Conf.Static.TLS.CertPool,
	}
	client, err := smtpclient.New(clientctx, qlog.Logger, conn, tlsMode, tlsPKIX, mox.Conf.Static.HostnameDomain, transport.DNSHost, opts)
	if err != nil {
		smtperr, ok := err.(smtpclient.Error)
		var remoteMTA dsn.NameIP
		if ok {
			remoteMTA.Name = transport.Host
		}
		qlog.Errorx("establishing smtp session for submission", err, slog.String("remote", addr))
		errmsg = fmt.Sprintf("transport %s: establishing smtp session with %s for submission: %v", transportName, addr, err)
		secodeOpt = smtperr.Secode
		fail(ctx, qlog, m, backoff, false, remoteMTA, secodeOpt, errmsg)
		return
	}
	defer func() {
		err := client.Close()
		qlog.Check(err, "closing smtp client after delivery")
	}()
	clientcancel()

	var msgr io.ReadCloser
	var size int64
	var req8bit, reqsmtputf8 bool
	if len(m.DSNUTF8) > 0 && client.SupportsSMTPUTF8() {
		msgr = io.NopCloser(bytes.NewReader(m.DSNUTF8))
		reqsmtputf8 = true
		size = int64(len(m.DSNUTF8))
	} else {
		req8bit = m.Has8bit // todo: not require this, but just try to submit?
		size = m.Size

		p := m.MessagePath()
		f, err := os.Open(p)
		if err != nil {
			qlog.Errorx("opening message for delivery", err, slog.String("remote", addr), slog.String("path", p))
			errmsg = fmt.Sprintf("transport %s: opening message file for submission: %v", transportName, err)
			fail(ctx, qlog, m, backoff, false, dsn.NameIP{}, "", errmsg)
			return
		}
		msgr = store.FileMsgReader(m.MsgPrefix, f)
		defer func() {
			err := msgr.Close()
			qlog.Check(err, "closing message after delivery attempt")
		}()
	}

	deliverctx, delivercancel := context.WithTimeout(context.Background(), time.Duration(60+size/(1024*1024))*time.Second)
	defer delivercancel()
	err = client.Deliver(deliverctx, m.Sender().String(), m.Recipient().String(), size, msgr, req8bit, reqsmtputf8, requireTLS)
	if err != nil {
		qlog.Infox("delivery failed", err)
	}
	var cerr smtpclient.Error
	switch {
	case err == nil:
		deliveryResult = "ok"
		success = true
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
	if err != nil {
		smtperr, ok := err.(smtpclient.Error)
		var remoteMTA dsn.NameIP
		if ok {
			remoteMTA.Name = transport.Host
		}
		qlog.Errorx("submitting email", err, slog.String("remote", addr))
		permanent = smtperr.Permanent
		secodeOpt = smtperr.Secode
		errmsg = fmt.Sprintf("transport %s: submitting email to %s: %v", transportName, addr, err)
		fail(ctx, qlog, m, backoff, permanent, remoteMTA, secodeOpt, errmsg)
		return
	}
	qlog.Info("delivered from queue with transport")
	if err := queueDelete(context.Background(), m.ID); err != nil {
		qlog.Errorx("deleting message from queue after delivery", err)
	}
}
