package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dsn"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// todo: reuse connection? do fewer concurrently (other than with direct delivery).

// deliver via another SMTP server, e.g. relaying to a smart host, possibly
// with authentication (submission).
func deliverSubmit(cid int64, qlog *mlog.Log, resolver dns.Resolver, dialer contextDialer, m Msg, backoff time.Duration, transportName string, transport *config.TransportSMTP, dialTLS bool, defaultPort int) {
	// todo: configurable timeouts

	port := transport.Port
	if port == 0 {
		port = defaultPort
	}

	tlsMode := smtpclient.TLSStrictStartTLS
	if dialTLS {
		tlsMode = smtpclient.TLSStrictImmediate
	} else if transport.STARTTLSInsecureSkipVerify {
		tlsMode = smtpclient.TLSOpportunistic
	} else if transport.NoSTARTTLS {
		tlsMode = smtpclient.TLSSkip
	}
	start := time.Now()
	var deliveryResult string
	var permanent bool
	var secodeOpt string
	var errmsg string
	var success bool
	defer func() {
		metricDelivery.WithLabelValues(fmt.Sprintf("%d", m.Attempts), transportName, string(tlsMode), deliveryResult).Observe(float64(time.Since(start)) / float64(time.Second))
		qlog.Debug("queue deliversubmit result", mlog.Field("host", transport.DNSHost), mlog.Field("port", port), mlog.Field("attempt", m.Attempts), mlog.Field("permanent", permanent), mlog.Field("secodeopt", secodeOpt), mlog.Field("errmsg", errmsg), mlog.Field("ok", success), mlog.Field("duration", time.Since(start)))
	}()

	dialctx, dialcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialcancel()
	addr := net.JoinHostPort(transport.Host, fmt.Sprintf("%d", port))
	conn, _, _, err := dialHost(dialctx, qlog, resolver, dialer, dns.IPDomain{Domain: transport.DNSHost}, port, &m)
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
		qlog.Errorx("dialing for submission", err, mlog.Field("remote", addr))
		errmsg = fmt.Sprintf("transport %s: dialing %s for submission: %v", transportName, addr, err)
		fail(qlog, m, backoff, false, dsn.NameIP{}, "", errmsg)
		return
	}
	dialcancel()

	var auth []sasl.Client
	if transport.Auth != nil {
		a := transport.Auth
		for _, mech := range a.EffectiveMechanisms {
			switch mech {
			case "PLAIN":
				auth = append(auth, sasl.NewClientPlain(a.Username, a.Password))
			case "CRAM-MD5":
				auth = append(auth, sasl.NewClientCRAMMD5(a.Username, a.Password))
			case "SCRAM-SHA-1":
				auth = append(auth, sasl.NewClientSCRAMSHA1(a.Username, a.Password))
			case "SCRAM-SHA-256":
				auth = append(auth, sasl.NewClientSCRAMSHA256(a.Username, a.Password))
			default:
				// Should not happen.
				qlog.Error("missing smtp authentication mechanisms implementation", mlog.Field("mechanism", mech))
				errmsg = fmt.Sprintf("transport %s: authentication mechanisms %q not implemented", transportName, mech)
				fail(qlog, m, backoff, false, dsn.NameIP{}, "", errmsg)
				return
			}
		}
	}
	clientctx, clientcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer clientcancel()
	client, err := smtpclient.New(clientctx, qlog, conn, tlsMode, mox.Conf.Static.HostnameDomain, transport.DNSHost, auth)
	if err != nil {
		smtperr, ok := err.(smtpclient.Error)
		var remoteMTA dsn.NameIP
		if ok {
			remoteMTA.Name = transport.Host
		}
		qlog.Errorx("establishing smtp session for submission", err, mlog.Field("remote", addr))
		errmsg = fmt.Sprintf("transport %s: establishing smtp session with %s for submission: %v", transportName, addr, err)
		secodeOpt = smtperr.Secode
		fail(qlog, m, backoff, false, remoteMTA, secodeOpt, errmsg)
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
			qlog.Errorx("opening message for delivery", err, mlog.Field("remote", addr), mlog.Field("path", p))
			errmsg = fmt.Sprintf("transport %s: opening message file for submission: %v", transportName, err)
			fail(qlog, m, backoff, false, dsn.NameIP{}, "", errmsg)
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
	err = client.Deliver(deliverctx, m.Sender().String(), m.Recipient().String(), size, msgr, req8bit, reqsmtputf8)
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
		qlog.Errorx("submitting email", err, mlog.Field("remote", addr))
		permanent = smtperr.Permanent
		secodeOpt = smtperr.Secode
		errmsg = fmt.Sprintf("transport %s: submitting email to %s: %v", transportName, addr, err)
		fail(qlog, m, backoff, permanent, remoteMTA, secodeOpt, errmsg)
		return
	}
	qlog.Info("delivered from queue with transport")
	if err := queueDelete(context.Background(), m.ID); err != nil {
		qlog.Errorx("deleting message from queue after delivery", err)
	}
}
