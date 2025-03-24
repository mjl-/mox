// Package rdap is a basic client for checking the age of domains through RDAP.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

var ErrNoRegistration = errors.New("registration date not found")
var ErrNoRDAP = errors.New("rdap not available for top-level domain")
var ErrNoDomain = errors.New("domain not found in registry")
var ErrSyntax = errors.New("bad rdap response syntax")

// https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml
// ../rfc/9224:115
const rdapBoostrapDNSURL = "https://data.iana.org/rdap/dns.json"

// Example data: ../rfc/9224:192

// Bootstrap data, parsed from JSON at the IANA DNS bootstrap URL.
type Bootstrap struct {
	Version     string    `json:"version"` // Should be "1.0".
	Description string    `json:"description"`
	Publication time.Time `json:"publication"` // RFC3339

	// Each entry has two elements: First a list of TLDs, then a list of RDAP service
	// base URLs ending with a slash.
	Services [][2][]string `json:"services"`
}

// todo: when using this more regularly in the admin web interface, store the iana bootstrap response in a database file, including cache-controle results (max-age it seems) and the etag, and do conditional requests when asking for a new version. same for lookups of domains at registries.

// LookupLastDomainRegistration looks up the most recent (re)registration of a
// domain through RDAP.
//
// Not all TLDs have RDAP services yet at the time of writing.
func LookupLastDomainRegistration(ctx context.Context, log mlog.Log, dom dns.Domain) (time.Time, error) {
	// ../rfc/9224:434 Against advice, we do not cache the bootstrap data. This is
	// currently used by the quickstart, which is run once, or run from the cli without
	// a place to keep state.
	req, err := http.NewRequestWithContext(ctx, "GET", rdapBoostrapDNSURL, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("new request for iana dns bootstrap data: %v", err)
	}
	// ../rfc/9224:588
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("http get of iana dns bootstrap data: %v", err)
	}
	defer func() {
		err := resp.Body.Close()
		log.Check(err, "closing http response body")
	}()
	if resp.StatusCode/100 != 2 {
		return time.Time{}, fmt.Errorf("http get resulted in status %q, expected 200 ok", resp.Status)
	}
	var bootstrap Bootstrap
	if err := json.NewDecoder(resp.Body).Decode(&bootstrap); err != nil {
		return time.Time{}, fmt.Errorf("%w: parsing iana dns bootstrap data: %v", ErrSyntax, err)
	}

	// Note: We don't verify version numbers. If the format change incompatibly,
	// decoding above would have failed. We'll try to work with what we got.

	// ../rfc/9224:184 The bootstrap JSON has A-labels we must match against.
	// ../rfc/9224:188 Names are lower-case, like our dns.Domain.
	var urls []string
	var tldmatch string
	for _, svc := range bootstrap.Services {
		for _, s := range svc[0] {
			// ../rfc/9224:225 We match the longest domain suffix. In practice, there are
			// currently only single labels, top level domains, in the bootstrap database.
			if len(s) > len(tldmatch) && (s == dom.ASCII || strings.HasSuffix(dom.ASCII, "."+s)) {
				urls = svc[1]
				tldmatch = s
			}
		}
	}
	// ../rfc/9224:428
	if len(urls) == 0 {
		return time.Time{}, ErrNoRDAP
	}
	// ../rfc/9224:172 We must try secure transports before insecure (https before http). In practice, there is just a single https URL.
	sort.Slice(urls, func(i, j int) bool {
		return strings.HasPrefix(urls[i], "https://")
	})
	var lastErr error
	for _, u := range urls {
		var reg time.Time
		reg, lastErr = rdapDomainRequest(ctx, log, u, dom)
		if lastErr == nil {
			return reg, nil
		}
	}
	return time.Time{}, lastErr
}

// ../rfc/9083:284 We must match json fields case-sensitively, so explicitly.
// Example domain object: ../rfc/9083:945

// Domain is the RDAP response for a domain request.
//
// More fields are available in RDAP responses, we only parse the one(s) a few.
type Domain struct {
	// ../rfc/9083:1172

	RDAPConformance []string `json:"rdapConformance"` // E.g. "rdap_level_0"
	LDHName         string   `json:"ldhName"`         // Domain.
	Events          []Event  `json:"events"`
}

// Event is a historic or future change to the domain.
type Event struct {
	// ../rfc/9083:573

	EventAction string    `json:"eventAction"` // Required. See https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml.
	EventDate   time.Time `json:"eventDate"`   // Required. RFC3339. May be in the future, e.g. date of expiry.
}

// rdapDomainRequest looks up a the most recent registration time of a at an RDAP
// service base URL.
func rdapDomainRequest(ctx context.Context, log mlog.Log, rdapURL string, dom dns.Domain) (time.Time, error) {
	// ../rfc/9082:316
	// ../rfc/9224:177 base URLs have a trailing slash.
	rdapURL += "domain/" + dom.ASCII
	req, err := http.NewRequestWithContext(ctx, "GET", rdapURL, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("making http request for rdap service: %v", err)
	}
	// ../rfc/9083:2372 ../rfc/7480:273
	req.Header.Add("Accept", "application/rdap+json")
	// ../rfc/7480:319 Redirects are handled by net/http.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("http domain rdap get request: %v", err)
	}
	defer func() {
		err := resp.Body.Close()
		log.Check(err, "closing http response body")
	}()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// ../rfc/7480:189 ../rfc/7480:359
		return time.Time{}, ErrNoDomain

	case resp.StatusCode/100 != 2:
		// We try to read an error message, perhaps a bit too hard, but we may still
		// truncate utf-8 in the middle of a rune...
		var msg string
		var response struct {
			// For errors, optional fields.
			Title       string   `json:"title"`
			Description []string `json:"description"`
			// ../rfc/9083:2123
		}
		buf, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		if err != nil {
			msg = fmt.Sprintf("(error reading response: %v)", err)
		} else if err := json.Unmarshal(buf, &response); err == nil && (response.Title != "" || len(response.Description) > 0) {
			s := response.Title
			if s != "" && len(response.Description) > 0 {
				s += "; "
			}
			s += strings.Join(response.Description, " ")
			if len(s) > 200 {
				s = s[:150] + "..."
			}
			msg = fmt.Sprintf("message from remote: %q", s)
		} else {
			var s string
			if len(buf) > 200 {
				s = string(buf[:150]) + "..."
			} else {
				s = string(buf)
			}
			msg = fmt.Sprintf("raw response: %q", s)
		}
		return time.Time{}, fmt.Errorf("status %q, expected 200 ok: %s", resp.Status, msg)
	}

	var domain Domain
	if err := json.NewDecoder(resp.Body).Decode(&domain); err != nil {
		return time.Time{}, fmt.Errorf("parse domain rdap response: %v", err)
	}

	sort.Slice(domain.Events, func(i, j int) bool {
		return domain.Events[i].EventDate.Before(domain.Events[j].EventDate)
	})

	now := time.Now()
	for i := len(domain.Events) - 1; i >= 0; i-- {
		ev := domain.Events[i]
		if ev.EventDate.After(now) {
			continue
		}
		switch ev.EventAction {
		// ../rfc/9083:2690
		case "registration", "reregistration", "reinstantiation":
			return ev.EventDate, nil
		}
	}
	return time.Time{}, ErrNoRegistration
}
