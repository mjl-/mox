package mtastsdb

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand"
	"runtime/debug"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
)

func refresh() int {
	interval := 24 * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var refreshed int

	// Pro-actively refresh policies every 24 hours. ../rfc/8461:583
	for {
		ticker.Reset(interval)

		ctx := context.WithValue(mox.Context, mlog.CidKey, mox.Cid())
		n, err := refresh1(ctx, dns.StrictResolver{Pkg: "mtastsdb"}, time.Sleep)
		if err != nil {
			xlog.WithContext(ctx).Errorx("periodic refresh of cached mtasts policies", err)
		}
		if n > 0 {
			refreshed += n
		}

		select {
		case <-mox.Shutdown.Done():
			return refreshed
		case <-ticker.C:
		}
	}
}

// refresh policies that have not been updated in the past 12 hours and remove
// policies not used for 180 days. We start with the first domain immediately, so
// an admin can see any (configuration) issues that are logged. We spread the
// refreshes evenly over the next 3 hours, randomizing the domains, and we add some
// jitter to the timing. Each refresh is done in a new goroutine, so a single slow
// refresh doesn't mess up the timing.
func refresh1(ctx context.Context, resolver dns.Resolver, sleep func(d time.Duration)) (int, error) {
	db, err := database(ctx)
	if err != nil {
		return 0, err
	}

	now := timeNow()
	qdel := bstore.QueryDB[PolicyRecord](ctx, db)
	qdel.FilterLess("LastUse", now.Add(-180*24*time.Hour))
	if _, err := qdel.Delete(); err != nil {
		return 0, fmt.Errorf("deleting old unused policies: %s", err)
	}

	qup := bstore.QueryDB[PolicyRecord](ctx, db)
	qup.FilterLess("LastUpdate", now.Add(-12*time.Hour))
	prs, err := qup.List()
	if err != nil {
		return 0, fmt.Errorf("querying policies to refresh: %s", err)
	}

	if len(prs) == 0 {
		// Nothing to do.
		return 0, nil
	}

	// Randomize list.
	rand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	for i := range prs {
		if i == 0 {
			continue
		}
		j := rand.Intn(i + 1)
		prs[i], prs[j] = prs[j], prs[i]
	}

	// Launch goroutine with the refresh.
	xlog.WithContext(ctx).Debug("will refresh mta-sts policies over next 3 hours", mlog.Field("count", len(prs)))
	start := timeNow()
	for i, pr := range prs {
		go refreshDomain(ctx, db, resolver, pr)
		if i < len(prs)-1 {
			interval := 3 * int64(time.Hour) / int64(len(prs)-1)
			extra := time.Duration(rand.Int63n(interval) - interval/2)
			next := start.Add(time.Duration(int64(i+1)*interval) + extra)
			d := next.Sub(timeNow())
			if d > 0 {
				sleep(d)
			}
		}
	}
	return len(prs), nil
}

func refreshDomain(ctx context.Context, db *bstore.DB, resolver dns.Resolver, pr PolicyRecord) {
	log := xlog.WithContext(ctx)
	defer func() {
		x := recover()
		if x != nil {
			// Should not happen, but make sure errors don't take down the application.
			log.Error("refresh1", mlog.Field("panic", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Mtastsdb)
		}
	}()

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	d, err := dns.ParseDomain(pr.Domain)
	if err != nil {
		log.Errorx("refreshing mta-sts policy: parsing policy domain", err, mlog.Field("domain", d))
		return
	}
	log.Debug("refreshing mta-sts policy for domain", mlog.Field("domain", d))
	record, _, _, err := mtasts.LookupRecord(ctx, resolver, d)
	if err == nil && record.ID == pr.RecordID {
		qup := bstore.QueryDB[PolicyRecord](ctx, db)
		qup.FilterNonzero(PolicyRecord{Domain: pr.Domain, LastUpdate: pr.LastUpdate})
		now := timeNow()
		update := PolicyRecord{
			LastUpdate: now,
			ValidEnd:   now.Add(time.Duration(pr.MaxAgeSeconds) * time.Second),
		}
		if n, err := qup.UpdateNonzero(update); err != nil {
			log.Errorx("updating refreshed, unmodified policy in database", err)
		} else if n != 1 {
			log.Info("expected to update 1 policy after refresh", mlog.Field("count", n))
		}
		return
	}
	// ../rfc/8461:587
	if err != nil && pr.Mode == mtasts.ModeNone {
		return
	} else if err != nil {
		log.Errorx("looking up mta-sts record for domain", err, mlog.Field("domain", d))
		// Try to fetch new policy. It could be just DNS that is down. We don't want to let our policy expire.
	}

	p, _, err := mtasts.FetchPolicy(ctx, d)
	if err != nil {
		if !errors.Is(err, mtasts.ErrNoPolicy) || pr.Mode != mtasts.ModeNone {
			log.Errorx("refreshing mtasts policy for domain", err, mlog.Field("domain", d))
		}
		return
	}
	now := timeNow()
	update := map[string]any{
		"LastUpdate": now,
		"ValidEnd":   now.Add(time.Duration(p.MaxAgeSeconds) * time.Second),
		"Backoff":    false,
		"Policy":     *p,
	}
	if record != nil {
		update["RecordID"] = record.ID
	}
	qup := bstore.QueryDB[PolicyRecord](ctx, db)
	qup.FilterNonzero(PolicyRecord{Domain: pr.Domain, LastUpdate: pr.LastUpdate})
	if n, err := qup.UpdateFields(update); err != nil {
		log.Errorx("updating refreshed, modified policy in database", err)
	} else if n != 1 {
		log.Info("updating refreshed, did not update 1 policy", mlog.Field("count", n))
	}
}
