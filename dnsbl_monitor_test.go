//go:build !windows

package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
)

// dnsblMetricValue returns the value of the mox_dnsbl_ips_success gauge for the
// given zone and ip.
func dnsblMetricValue(t *testing.T, zoneName, ip string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metricDNSBL)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "mox_dnsbl_ips_success" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["zone"] == zoneName && labels["ip"] == ip {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Fatalf("mox_dnsbl_ips_success{zone=%q,ip=%q} not found", zoneName, ip)
	return 0
}

func TestMonitorDNSBLTemperror(t *testing.T) {
	zone := dns.Domain{ASCII: "sbl.spamhaus.org."}
	ip := "1.2.3.4"
	zoneName := zone.Name()

	// Set a previous value, as a previous successful check would have.
	metricDNSBL.WithLabelValues(zoneName, ip).Set(1)

	if got := dnsblMetricValue(t, zoneName, ip); got != 1 {
		t.Fatalf("initial gauge value is %v, expected 1", got)
	}

	// A temporary DNS error, e.g. "server misbehaving", is not an indication that
	// our IP is in the block list, it should not update the gauge.
	updateDNSBLMetric(zone, ip, dnsbl.StatusTemperr)

	if got := dnsblMetricValue(t, zoneName, ip); got != 1 {
		t.Fatalf("gauge is %v after temperror, expected it to keep the previous value 1", got)
	}

	// A successful lookup resets the gauge to 1.
	updateDNSBLMetric(zone, ip, dnsbl.StatusPass)
	if got := dnsblMetricValue(t, zoneName, ip); got != 1 {
		t.Fatalf("gauge is %v after pass, expected 1", got)
	}

	// Being in the block list sets the gauge to 0.
	updateDNSBLMetric(zone, ip, dnsbl.StatusFail)
	if got := dnsblMetricValue(t, zoneName, ip); got != 0 {
		t.Fatalf("gauge is %v after fail, expected 0", got)
	}
}
