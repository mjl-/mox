// Package updates implements a mechanism for checking if software updates are
// available, and fetching a changelog.
//
// Given a domain, the latest version of the software is queried in DNS from
// "_updates.<domain>" as a TXT record. If a new version is available, the
// changelog compared to a last known version can be retrieved. A changelog base
// URL and public key for signatures has to be specified explicitly.
//
// Downloading or upgrading to the latest version is not part of this package.
package updates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/stub"
)

var (
	MetricLookup         stub.HistogramVec                                                                                           = stub.HistogramVecIgnore{}
	MetricFetchChangelog stub.HistogramVec                                                                                           = stub.HistogramVecIgnore{}
	HTTPClientObserve    func(ctx context.Context, log *slog.Logger, pkg, method string, statusCode int, err error, start time.Time) = stub.HTTPClientObserveIgnore
)

var (
	// Lookup errors.
	ErrDNS             = errors.New("updates: dns error")
	ErrRecordSyntax    = errors.New("updates: dns record syntax")
	ErrNoRecord        = errors.New("updates: no dns record")
	ErrMultipleRecords = errors.New("updates: multiple dns records")
	ErrBadVersion      = errors.New("updates: malformed version")

	// Fetch changelog errors.
	ErrChangelogFetch = errors.New("updates: fetching changelog")
)

// Change is a an entry in the changelog, a released version.
type Change struct {
	PubKey []byte // Key used for signing.
	Sig    []byte // Signature over text, with ed25519.
	Text   string // Signed changelog entry, starts with header similar to email, with at least fields "version" and "date".
}

// Changelog is returned as JSON.
//
// The changelog itself is not signed, only individual changes. The goal is to
// prevent a potential future different domain owner from notifying users about
// new versions.
type Changelog struct {
	Changes []Change // Newest first.
}

// Lookup looks up the updates DNS TXT record at "_updates.<domain>" and returns
// the parsed form.
func Lookup(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, domain dns.Domain) (rversion Version, rrecord *Record, rerr error) {
	log := mlog.New("updates", elog)
	start := time.Now()
	defer func() {
		var result = "ok"
		if rerr != nil {
			result = "error"
		}
		MetricLookup.ObserveLabels(float64(time.Since(start))/float64(time.Second), result)
		log.Debugx("updates lookup result", rerr,
			slog.Any("domain", domain),
			slog.Any("version", rversion),
			slog.Any("record", rrecord),
			slog.Duration("duration", time.Since(start)))
	}()

	nctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "_updates." + domain.ASCII + "."
	txts, _, err := dns.WithPackage(resolver, "updates").LookupTXT(nctx, name)
	if dns.IsNotFound(err) {
		return Version{}, nil, ErrNoRecord
	} else if err != nil {
		return Version{}, nil, fmt.Errorf("%w: %s", ErrDNS, err)
	}
	var record *Record
	for _, txt := range txts {
		r, isupdates, err := ParseRecord(txt)
		if !isupdates {
			continue
		} else if err != nil {
			return Version{}, nil, err
		}
		if record != nil {
			return Version{}, nil, ErrMultipleRecords
		}
		record = r
	}

	if record == nil {
		return Version{}, nil, ErrNoRecord
	}
	return record.Latest, record, nil
}

// FetchChangelog fetches the changelog compared against the base version, which
// can be the Version zero value.
//
// The changelog is requested using HTTP GET from baseURL with optional "from"
// query string parameter.
//
// Individual changes are verified using pubKey. If any signature is invalid, an
// error is returned.
//
// A changelog can be maximum 1 MB.
func FetchChangelog(ctx context.Context, elog *slog.Logger, baseURL string, base Version, pubKey []byte) (changelog *Changelog, rerr error) {
	log := mlog.New("updates", elog)
	start := time.Now()
	defer func() {
		var result = "ok"
		if rerr != nil {
			result = "error"
		}
		MetricFetchChangelog.ObserveLabels(float64(time.Since(start))/float64(time.Second), result)
		log.Debugx("updates fetch changelog result", rerr,
			slog.String("baseurl", baseURL),
			slog.Any("base", base),
			slog.Duration("duration", time.Since(start)))
	}()

	url := baseURL + "?from=" + base.String()
	nctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(nctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("making request: %v", err)
	}
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if resp == nil {
		resp = &http.Response{StatusCode: 0}
	}
	HTTPClientObserve(ctx, log.Logger, "updates", req.Method, resp.StatusCode, err, start)
	if err != nil {
		return nil, fmt.Errorf("%w: making http request: %s", ErrChangelogFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: http status: %s", ErrChangelogFetch, resp.Status)
	}
	var cl Changelog
	if err := json.NewDecoder(&moxio.LimitReader{R: resp.Body, Limit: 1024 * 1024}).Decode(&cl); err != nil {
		return nil, fmt.Errorf("%w: parsing changelog: %s", ErrChangelogFetch, err)
	}
	for _, c := range cl.Changes {
		if !bytes.Equal(c.PubKey, pubKey) {
			return nil, fmt.Errorf("%w: verifying change: signed with unknown public key %x instead of %x", ErrChangelogFetch, c.PubKey, pubKey)
		}
		if !ed25519.Verify(c.PubKey, []byte(c.Text), c.Sig) {
			return nil, fmt.Errorf("%w: verifying change: invalid signature for change", ErrChangelogFetch)
		}
	}

	return &cl, nil
}

// Check checks for an updated version through DNS and fetches a
// changelog if so.
//
// Check looks up a TXT record at _updates.<domain>, and parses the record. If the
// latest version is more recent than lastKnown, an update is available, and Check
// will fetch the signed changes since lastKnown, verify the signatures, and
// return the changelog. The latest version and parsed DNS record is returned
// regardless of whether a new version was found. A non-nil changelog is only
// returned when a new version was found and a changelog could be fetched and
// verified.
func Check(ctx context.Context, elog *slog.Logger, resolver dns.Resolver, domain dns.Domain, lastKnown Version, changelogBaseURL string, pubKey []byte) (rversion Version, rrecord *Record, changelog *Changelog, rerr error) {
	log := mlog.New("updates", elog)
	start := time.Now()
	defer func() {
		log.Debugx("updates check result", rerr,
			slog.Any("domain", domain),
			slog.Any("lastknown", lastKnown),
			slog.String("changelogbaseurl", changelogBaseURL),
			slog.Any("version", rversion),
			slog.Any("record", rrecord),
			slog.Duration("duration", time.Since(start)))
	}()

	latest, record, err := Lookup(ctx, log.Logger, resolver, domain)
	if err != nil {
		return latest, record, nil, err
	}

	if latest.After(lastKnown) {
		changelog, err = FetchChangelog(ctx, log.Logger, changelogBaseURL, lastKnown, pubKey)
	}
	return latest, record, changelog, err
}

// Version is a specified version in an updates records.
type Version struct {
	Major int
	Minor int
	Patch int
}

// After returns if v comes after ov.
func (v Version) After(ov Version) bool {
	return v.Major > ov.Major || v.Major == ov.Major && v.Minor > ov.Minor || v.Major == ov.Major && v.Minor == ov.Minor && v.Patch > ov.Patch
}

// String returns a human-reasonable version, also for use in the updates
// record.
func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a version as used in an updates records.
//
// Rules:
//   - Optionally start with "v"
//   - A dash and anything after it is ignored, e.g. for non-release modifiers.
//   - Remaining string must be three dot-separated numbers.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	s = strings.Split(s, "-")[0]
	t := strings.Split(s, ".")
	if len(t) != 3 {
		return Version{}, fmt.Errorf("%w: %v", ErrBadVersion, t)
	}
	nums := make([]int, 3)
	for i, v := range t {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return Version{}, fmt.Errorf("%w: parsing int %q: %s", ErrBadVersion, v, err)
		}
		nums[i] = int(n)
	}
	return Version{nums[0], nums[1], nums[2]}, nil
}

// Record is an updates DNS record.
type Record struct {
	Version string  // v=UPDATES0, required and must always be first.
	Latest  Version // l=<version>, required.
}

// ParseRecord parses an updates DNS TXT record as served at
func ParseRecord(txt string) (record *Record, isupdates bool, err error) {
	l := strings.Split(txt, ";")
	vkv := strings.SplitN(strings.TrimSpace(l[0]), "=", 2)
	if len(vkv) != 2 || vkv[0] != "v" || !strings.EqualFold(vkv[1], "UPDATES0") {
		return nil, false, nil
	}

	r := &Record{Version: "UPDATES0"}
	seen := map[string]bool{}
	for _, t := range l[1:] {
		kv := strings.SplitN(strings.TrimSpace(t), "=", 2)
		if len(kv) != 2 {
			return nil, true, ErrRecordSyntax
		}
		k := strings.ToLower(kv[0])
		if seen[k] {
			return nil, true, fmt.Errorf("%w: duplicate key %q", ErrRecordSyntax, k)
		}
		seen[k] = true
		switch k {
		case "l":
			v, err := ParseVersion(kv[1])
			if err != nil {
				return nil, true, fmt.Errorf("%w: %s", ErrRecordSyntax, err)
			}
			r.Latest = v
		default:
			continue
		}
	}
	return r, true, nil
}
