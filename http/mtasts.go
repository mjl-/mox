package http

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
)

func mtastsPolicyHandle(w http.ResponseWriter, r *http.Request) {
	log := func() mlog.Log {
		return pkglog.WithContext(r.Context())
	}

	host := strings.ToLower(r.Host)
	if !strings.HasPrefix(host, "mta-sts.") {
		http.NotFound(w, r)
		return
	}
	host = strings.TrimPrefix(host, "mta-sts.")
	nhost, _, err := net.SplitHostPort(host)
	if err == nil {
		// Only relevant for when host has a port.
		host = nhost
	}
	domain, err := dns.ParseDomain(host)
	if err != nil {
		log().Errorx("mtasts policy request: bad domain", err, slog.String("host", host))
		http.NotFound(w, r)
		return
	}

	conf, _ := mox.Conf.Domain(domain)
	sts := conf.MTASTS
	if sts == nil {
		http.NotFound(w, r)
		return
	}

	var mxs []mtasts.STSMX
	for _, s := range sts.MX {
		var mx mtasts.STSMX
		if strings.HasPrefix(s, "*.") {
			mx.Wildcard = true
			s = s[2:]
		}
		d, err := dns.ParseDomain(s)
		if err != nil {
			log().Errorx("bad domain in mtasts config", err, slog.String("domain", s))
			http.Error(w, "500 - internal server error - invalid domain in configuration", http.StatusInternalServerError)
			return
		}
		mx.Domain = d
		mxs = append(mxs, mx)
	}
	if len(mxs) == 0 {
		mxs = []mtasts.STSMX{{Domain: mox.Conf.Static.HostnameDomain}}
	}

	policy := mtasts.Policy{
		Version:       "STSv1",
		Mode:          sts.Mode,
		MaxAgeSeconds: int(sts.MaxAge / time.Second),
		MX:            mxs,
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	_, _ = w.Write([]byte(policy.String()))
}
