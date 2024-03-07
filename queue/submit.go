package queue

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"

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
func deliverSubmit(qlog mlog.Log, resolver dns.Resolver, dialer smtpclient.Dialer, msgs []*Msg, backoff time.Duration, transportName string, transport *config.TransportSMTP, dialTLS bool, defaultPort int) {
	// todo: configurable timeouts

	// For convenience, all messages share the same relevant values.
	m0 := msgs[0]

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

	// Prepare values for logging/metrics. They are updated for various error
	// conditions later on.
	start := time.Now()
	var submiterr error // Of whole operation, nil for partial failure/success.
	var delivered int
	failed := len(msgs) // Reset and updated after smtp transaction.
	defer func() {
		r := deliveryResult(submiterr, delivered, failed)
		d := float64(time.Since(start)) / float64(time.Second)
		metricDelivery.WithLabelValues(fmt.Sprintf("%d", m0.Attempts), transportName, string(tlsMode), r).Observe(d)

		qlog.Debugx("queue deliversubmit result", submiterr,
			slog.Any("host", transport.DNSHost),
			slog.Int("port", port),
			slog.Int("attempt", m0.Attempts),
			slog.String("result", r),
			slog.Int("delivered", delivered),
			slog.Int("failed", failed),
			slog.Any("tlsmode", tlsMode),
			slog.Bool("tlspkix", tlsPKIX),
			slog.Duration("duration", time.Since(start)))
	}()

	// todo: SMTP-DANE should be used when relaying on port 25.
	// ../rfc/7672:1261

	// todo: for submission, understand SRV records, and even DANE.

	ctx := mox.Shutdown

	// If submit was done with REQUIRETLS extension for SMTP, we must verify TLS
	// certificates. If our submission connection is not configured that way, abort.
	requireTLS := m0.RequireTLS != nil && *m0.RequireTLS
	if requireTLS && (tlsMode != smtpclient.TLSRequiredStartTLS && tlsMode != smtpclient.TLSImmediate || !tlsPKIX) {
		submiterr = smtpclient.Error{
			Permanent: true,
			Code:      smtp.C554TransactionFailed,
			Secode:    smtp.SePol7MissingReqTLS30,
			Err:       fmt.Errorf("transport %s: message requires verified tls but transport does not verify tls", transportName),
		}
		fail(ctx, qlog, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, submiterr)
		return
	}

	dialctx, dialcancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialcancel()
	if msgs[0].DialedIPs == nil {
		msgs[0].DialedIPs = map[string][]net.IP{}
		m0 = msgs[0]
	}
	_, _, _, ips, _, err := smtpclient.GatherIPs(dialctx, qlog.Logger, resolver, dns.IPDomain{Domain: transport.DNSHost}, m0.DialedIPs)
	var conn net.Conn
	if err == nil {
		conn, _, err = smtpclient.Dial(dialctx, qlog.Logger, dialer, dns.IPDomain{Domain: transport.DNSHost}, ips, port, m0.DialedIPs, mox.Conf.Static.SpecifiedSMTPListenIPs)
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
		submiterr = fmt.Errorf("transport %s: dialing %s for submission: %w", transportName, addr, err)
		fail(ctx, qlog, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, submiterr)
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
		submiterr = fmt.Errorf("transport %s: establishing smtp session with %s for submission: %w", transportName, addr, err)
		if ok {
			remoteMTA.Name = transport.Host
			smtperr.Err = submiterr
			submiterr = smtperr
		}
		qlog.Errorx("establishing smtp session for submission", submiterr, slog.String("remote", addr))
		fail(ctx, qlog, msgs, m0.DialedIPs, backoff, remoteMTA, submiterr)
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
	if len(m0.DSNUTF8) > 0 && client.SupportsSMTPUTF8() {
		msgr = io.NopCloser(bytes.NewReader(m0.DSNUTF8))
		reqsmtputf8 = true
		size = int64(len(m0.DSNUTF8))
	} else {
		req8bit = m0.Has8bit // todo: not require this, but just try to submit?
		size = m0.Size

		p := m0.MessagePath()
		f, err := os.Open(p)
		if err != nil {
			qlog.Errorx("opening message for delivery", err, slog.String("remote", addr), slog.String("path", p))
			submiterr = fmt.Errorf("transport %s: opening message file for submission: %w", transportName, err)
			fail(ctx, qlog, msgs, m0.DialedIPs, backoff, dsn.NameIP{}, submiterr)
			return
		}
		msgr = store.FileMsgReader(m0.MsgPrefix, f)
		defer func() {
			err := msgr.Close()
			qlog.Check(err, "closing message after delivery attempt")
		}()
	}

	deliverctx, delivercancel := context.WithTimeout(context.Background(), time.Duration(60+size/(1024*1024))*time.Second)
	defer delivercancel()
	rcpts := make([]string, len(msgs))
	for i, m := range msgs {
		rcpts[i] = m.Recipient().String()
	}
	rcptErrs, submiterr := client.DeliverMultiple(deliverctx, m0.Sender().String(), rcpts, size, msgr, req8bit, reqsmtputf8, requireTLS)
	if submiterr != nil {
		qlog.Infox("smtp transaction for delivery failed", submiterr)
	}
	failed = 0 // Reset, we are looking at the SMTP results below.
	var delIDs []int64
	for i, m := range msgs {
		qmlog := qlog.With(
			slog.Int64("msgid", m.ID),
			slog.Any("recipient", m.Recipient()))

		err := submiterr
		if err == nil && len(rcptErrs) > i {
			if rcptErrs[i].Code != smtp.C250Completed {
				err = smtpclient.Error(rcptErrs[i])
			}
		}
		if err != nil {
			smtperr, ok := err.(smtpclient.Error)
			err = fmt.Errorf("transport %s: submitting message to %s: %w", transportName, addr, err)
			var remoteMTA dsn.NameIP
			if ok {
				remoteMTA.Name = transport.Host
				smtperr.Err = err
				err = smtperr
			}
			qmlog.Errorx("submitting message", err, slog.String("remote", addr))
			fail(ctx, qmlog, []*Msg{m}, m0.DialedIPs, backoff, remoteMTA, err)
			failed++
		} else {
			delIDs = append(delIDs, m.ID)
			qmlog.Info("delivered from queue with transport")
			delivered++
		}
	}
	if len(delIDs) > 0 {
		if err := queueDelete(context.Background(), delIDs...); err != nil {
			qlog.Errorx("deleting message from queue after delivery", err)
		}
	}
}
