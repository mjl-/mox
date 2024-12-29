package admin

import (
	"fmt"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
)

type TLSMode uint8

const (
	TLSModeImmediate TLSMode = 0
	TLSModeSTARTTLS  TLSMode = 1
	TLSModeNone      TLSMode = 2
)

type ProtocolConfig struct {
	Host           dns.Domain
	Port           int
	TLSMode        TLSMode
	EnabledOnHTTPS bool
}

type ClientConfig struct {
	IMAP       ProtocolConfig
	Submission ProtocolConfig
}

// ClientConfigDomain returns a single IMAP and Submission client configuration for
// a domain.
func ClientConfigDomain(d dns.Domain) (rconfig ClientConfig, rerr error) {
	var haveIMAP, haveSubmission bool

	domConf, ok := mox.Conf.Domain(d)
	if !ok {
		return ClientConfig{}, fmt.Errorf("%w: unknown domain", ErrRequest)
	}

	gather := func(l config.Listener) (done bool) {
		host := mox.Conf.Static.HostnameDomain
		if l.Hostname != "" {
			host = l.HostnameDomain
		}
		if domConf.ClientSettingsDomain != "" {
			host = domConf.ClientSettingsDNSDomain
		}
		if !haveIMAP && l.IMAPS.Enabled {
			rconfig.IMAP.Host = host
			rconfig.IMAP.Port = config.Port(l.IMAPS.Port, 993)
			rconfig.IMAP.TLSMode = TLSModeImmediate
			rconfig.IMAP.EnabledOnHTTPS = l.IMAPS.EnabledOnHTTPS
			haveIMAP = true
		}
		if !haveIMAP && l.IMAP.Enabled {
			rconfig.IMAP.Host = host
			rconfig.IMAP.Port = config.Port(l.IMAP.Port, 143)
			rconfig.IMAP.TLSMode = TLSModeSTARTTLS
			if l.TLS == nil {
				rconfig.IMAP.TLSMode = TLSModeNone
			}
			haveIMAP = true
		}
		if !haveSubmission && l.Submissions.Enabled {
			rconfig.Submission.Host = host
			rconfig.Submission.Port = config.Port(l.Submissions.Port, 465)
			rconfig.Submission.TLSMode = TLSModeImmediate
			rconfig.Submission.EnabledOnHTTPS = l.Submissions.EnabledOnHTTPS
			haveSubmission = true
		}
		if !haveSubmission && l.Submission.Enabled {
			rconfig.Submission.Host = host
			rconfig.Submission.Port = config.Port(l.Submission.Port, 587)
			rconfig.Submission.TLSMode = TLSModeSTARTTLS
			if l.TLS == nil {
				rconfig.Submission.TLSMode = TLSModeNone
			}
			haveSubmission = true
		}
		return haveIMAP && haveSubmission
	}

	// Look at the public listener first. Most likely the intended configuration.
	if public, ok := mox.Conf.Static.Listeners["public"]; ok {
		if gather(public) {
			return
		}
	}
	// Go through the other listeners in consistent order.
	names := maps.Keys(mox.Conf.Static.Listeners)
	sort.Strings(names)
	for _, name := range names {
		if gather(mox.Conf.Static.Listeners[name]) {
			return
		}
	}
	return ClientConfig{}, fmt.Errorf("%w: no listeners found for imap and/or submission", ErrRequest)
}

// ClientConfigs holds the client configuration for IMAP/Submission for a
// domain.
type ClientConfigs struct {
	Entries []ClientConfigsEntry
}

type ClientConfigsEntry struct {
	Protocol string
	Host     dns.Domain
	Port     int
	Listener string
	Note     string
}

// ClientConfigsDomain returns the client configs for IMAP/Submission for a
// domain.
func ClientConfigsDomain(d dns.Domain) (ClientConfigs, error) {
	domConf, ok := mox.Conf.Domain(d)
	if !ok {
		return ClientConfigs{}, fmt.Errorf("%w: unknown domain", ErrRequest)
	}

	c := ClientConfigs{}
	c.Entries = []ClientConfigsEntry{}
	var listeners []string

	for name := range mox.Conf.Static.Listeners {
		listeners = append(listeners, name)
	}
	sort.Slice(listeners, func(i, j int) bool {
		return listeners[i] < listeners[j]
	})

	note := func(tls bool, requiretls bool) string {
		if !tls {
			return "plain text, no STARTTLS configured"
		}
		if requiretls {
			return "STARTTLS required"
		}
		return "STARTTLS optional"
	}

	for _, name := range listeners {
		l := mox.Conf.Static.Listeners[name]
		host := mox.Conf.Static.HostnameDomain
		if l.Hostname != "" {
			host = l.HostnameDomain
		}
		if domConf.ClientSettingsDomain != "" {
			host = domConf.ClientSettingsDNSDomain
		}
		if l.Submissions.Enabled {
			c.Entries = append(c.Entries, ClientConfigsEntry{"Submission (SMTP)", host, config.Port(l.Submissions.Port, 465), name, "with TLS"})
		}
		if l.IMAPS.Enabled {
			c.Entries = append(c.Entries, ClientConfigsEntry{"IMAP", host, config.Port(l.IMAPS.Port, 993), name, "with TLS"})
		}
		if l.Submission.Enabled {
			c.Entries = append(c.Entries, ClientConfigsEntry{"Submission (SMTP)", host, config.Port(l.Submission.Port, 587), name, note(l.TLS != nil, !l.Submission.NoRequireSTARTTLS)})
		}
		if l.IMAP.Enabled {
			c.Entries = append(c.Entries, ClientConfigsEntry{"IMAP", host, config.Port(l.IMAPS.Port, 143), name, note(l.TLS != nil, !l.IMAP.NoRequireSTARTTLS)})
		}
	}

	return c, nil
}
