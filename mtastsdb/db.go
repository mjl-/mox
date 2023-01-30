// Package mtastsdb stores MTA-STS policies for later use.
//
// An MTA-STS policy can specify how long it may be cached. By storing a
// policy, it does not have to be fetched again during email delivery, which
// makes it harder for attackers to intervene.
package mtastsdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtasts"
)

var xlog = mlog.New("mtastsdb")

var (
	metricGet = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_mtastsdb_get_total",
			Help: "Number of Get by result.",
		},
		[]string{"result"},
	)
)

var timeNow = time.Now // Tests override this.

// PolicyRecord is a cached policy or absence of a policy.
type PolicyRecord struct {
	Domain        string    // Domain name, with unicode characters.
	Inserted      time.Time `bstore:"default now"`
	ValidEnd      time.Time
	LastUpdate    time.Time // Policies are refreshed on use and periodically.
	LastUse       time.Time `bstore:"index"`
	Backoff       bool
	RecordID      string // As retrieved from DNS.
	mtasts.Policy        // As retrieved from the well-known HTTPS url.
}

var (
	// No valid non-expired policy in database.
	ErrNotFound = errors.New("mtastsdb: policy not found")

	// Indicates an MTA-STS TXT record was fetched recently, but fetching the policy
	// failed and should not yet be retried.
	ErrBackoff = errors.New("mtastsdb: policy fetch failed recently")
)

var mtastsDB *bstore.DB
var mutex sync.Mutex

func database() (rdb *bstore.DB, rerr error) {
	mutex.Lock()
	defer mutex.Unlock()
	if mtastsDB == nil {
		p := mox.DataDirPath("mtasts.db")
		os.MkdirAll(filepath.Dir(p), 0770)
		db, err := bstore.Open(p, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, PolicyRecord{})
		if err != nil {
			return nil, err
		}
		mtastsDB = db
	}
	return mtastsDB, nil
}

// Init opens the database and starts a goroutine that refreshes policies in
// the database, and keeps doing so periodically.
func Init(refresher bool) error {
	_, err := database()
	if err != nil {
		return err
	}

	if refresher {
		// todo: allow us to shut down cleanly?
		go refresh()
	}

	return nil
}

// Close closes the database.
func Close() {
	mutex.Lock()
	defer mutex.Unlock()
	if mtastsDB != nil {
		mtastsDB.Close()
		mtastsDB = nil
	}
}

// Lookup looks up a policy for the domain in the database.
//
// Only non-expired records are returned.
func lookup(ctx context.Context, domain dns.Domain) (*PolicyRecord, error) {
	log := xlog.WithContext(ctx)
	db, err := database()
	if err != nil {
		return nil, err
	}

	if domain.IsZero() {
		return nil, fmt.Errorf("empty domain")
	}
	now := timeNow()
	q := bstore.QueryDB[PolicyRecord](db)
	q.FilterNonzero(PolicyRecord{Domain: domain.Name()})
	q.FilterGreater("ValidEnd", now)
	pr, err := q.Get()
	if err == bstore.ErrAbsent {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	pr.LastUse = now
	if err := db.Update(&pr); err != nil {
		log.Errorx("marking cached mta-sts policy as used in database", err)
	}
	if pr.Backoff {
		return nil, ErrBackoff
	}
	return &pr, nil
}

// Upsert adds the policy to the database, overwriting an existing policy for the domain.
// Policy can be nil, indicating a failure to fetch the policy.
func Upsert(domain dns.Domain, recordID string, policy *mtasts.Policy) error {
	db, err := database()
	if err != nil {
		return err
	}

	return db.Write(func(tx *bstore.Tx) error {
		pr := PolicyRecord{Domain: domain.Name()}
		err := tx.Get(&pr)
		if err != nil && err != bstore.ErrAbsent {
			return err
		}

		now := timeNow()

		var p mtasts.Policy
		if policy != nil {
			p = *policy
		} else {
			// ../rfc/8461:552
			p.Mode = mtasts.ModeNone
			p.MaxAgeSeconds = 5 * 60
		}
		backoff := policy == nil
		validEnd := now.Add(time.Duration(p.MaxAgeSeconds) * time.Second)

		if err == bstore.ErrAbsent {
			pr = PolicyRecord{domain.Name(), now, validEnd, now, now, backoff, recordID, p}
			return tx.Insert(&pr)
		}

		pr.ValidEnd = validEnd
		pr.LastUpdate = now
		pr.LastUse = now
		pr.Backoff = backoff
		pr.RecordID = recordID
		pr.Policy = p
		return tx.Update(&pr)
	})
}

// PolicyRecords returns all policies in the database, sorted descending by last
// use, domain.
func PolicyRecords(ctx context.Context) ([]PolicyRecord, error) {
	db, err := database()
	if err != nil {
		return nil, err
	}
	return bstore.QueryDB[PolicyRecord](db).SortDesc("LastUse", "Domain").List()
}

// Get retrieves an MTA-STS policy for domain and whether it is fresh.
//
// If an error is returned, it should be considered a transient error, e.g. a
// temporary DNS lookup failure.
//
// The returned policy can be nil also when there is no error. In this case, the
// domain does not implement MTA-STS.
//
// If a policy is present in the local database, it is refreshed if needed. If no
// policy is present for the domain, an attempt is made to fetch the policy and
// store it in the local database.
//
// Some errors are logged but not otherwise returned, e.g. if a new policy is
// supposedly published but could not be retrieved.
func Get(ctx context.Context, resolver dns.Resolver, domain dns.Domain) (policy *mtasts.Policy, fresh bool, err error) {
	log := xlog.WithContext(ctx)
	defer func() {
		result := "ok"
		if err != nil && errors.Is(err, ErrBackoff) {
			result = "backoff"
		} else if err != nil && errors.Is(err, ErrNotFound) {
			result = "notfound"
		} else if err != nil {
			result = "error"
		}
		metricGet.WithLabelValues(result).Inc()
		log.Debugx("mtastsdb get result", err, mlog.Field("domain", domain), mlog.Field("fresh", fresh))
	}()

	cachedPolicy, err := lookup(ctx, domain)
	if err != nil && errors.Is(err, ErrNotFound) {
		// We don't have a policy for this domain, not even a record that we tried recently
		// and should backoff. So attempt to fetch policy.
		nctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		record, p, err := mtasts.Get(nctx, resolver, domain)
		if err != nil {
			switch {
			case errors.Is(err, mtasts.ErrNoRecord) || errors.Is(err, mtasts.ErrMultipleRecords) || errors.Is(err, mtasts.ErrRecordSyntax) || errors.Is(err, mtasts.ErrNoPolicy) || errors.Is(err, mtasts.ErrPolicyFetch) || errors.Is(err, mtasts.ErrPolicySyntax):
				// Remote is not doing MTA-STS, continue below. ../rfc/8461:333 ../rfc/8461:574
			default:
				// Interpret as temporary error, e.g. mtasts.ErrDNS, try again later.
				return nil, false, fmt.Errorf("lookup up mta-sts policy: %w", err)
			}
		}
		// Insert policy into database. If we could not fetch the policy itself, we back
		// off for 5 minutes. ../rfc/8461:555
		if err == nil || errors.Is(err, mtasts.ErrNoPolicy) || errors.Is(err, mtasts.ErrPolicyFetch) || errors.Is(err, mtasts.ErrPolicySyntax) {
			var recordID string
			if record != nil {
				recordID = record.ID
			}
			if err := Upsert(domain, recordID, p); err != nil {
				log.Errorx("inserting policy into cache, continuing", err)
			}
		}
		return p, true, nil
	} else if err != nil && errors.Is(err, ErrBackoff) {
		// ../rfc/8461:552
		// We recently failed to fetch a policy, act as if MTA-STS is not implemented.
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("looking up mta-sts policy in cache: %w", err)
	}

	// Policy was found in database. Check in DNS it is still fresh.
	policy = &cachedPolicy.Policy
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	record, _, _, err := mtasts.LookupRecord(ctx, resolver, domain)
	if err != nil {
		if !errors.Is(err, mtasts.ErrNoRecord) {
			// Could be a temporary DNS or configuration error.
			log.Errorx("checking for freshness of cached mta-sts dns txt record for domain, continuing with previously cached policy", err)
		}
		return policy, false, nil
	} else if record.ID == cachedPolicy.RecordID {
		return policy, true, nil
	}
	// New policy should be available.
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, _, err := mtasts.FetchPolicy(ctx, domain)
	if err != nil {
		log.Errorx("fetching updated policy for domain, continuing with previously cached policy", err)
		return policy, false, nil
	}
	if err := Upsert(domain, record.ID, p); err != nil {
		log.Errorx("inserting refreshed policy into cache, continuing with fresh policy", err)
	}
	return p, true, nil
}
