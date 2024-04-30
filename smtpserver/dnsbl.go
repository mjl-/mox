package smtpserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/mlog"
)

var dnsblHealth = struct {
	sync.Mutex
	zones map[dns.Domain]dnsblStatus
}{
	zones: map[dns.Domain]dnsblStatus{},
}

type dnsblStatus struct {
	last time.Time
	err  error // nil, dnsbl.ErrDNS or other
}

// checkDNSBLHealth checks healthiness of DNSBL "zone", keeping the result cached for 4 hours.
func checkDNSBLHealth(ctx context.Context, log mlog.Log, resolver dns.Resolver, zone dns.Domain) (rok bool) {
	dnsblHealth.Lock()
	defer dnsblHealth.Unlock()
	status, ok := dnsblHealth.zones[zone]
	if !ok || time.Since(status.last) > 4*time.Hour {
		status.err = dnsbl.CheckHealth(ctx, log.Logger, resolver, zone)
		status.last = time.Now()
		dnsblHealth.zones[zone] = status
	}
	return status.err == nil || errors.Is(status.err, dnsbl.ErrDNS)
}
