package adns

// Result has additional information about a DNS lookup.
type Result struct {
	// Authentic indicates whether the response was DNSSEC-signed and verified.
	// This package is a security-aware non-validating stub-resolver, sending requests
	// with the "authentic data" bit set to its recursive resolvers, but only if the
	// resolvers are trusted. Resolvers are trusted either if explicitly marked with
	// "options trust-ad" in /etc/resolv.conf, or if all resolver IP addresses are
	// loopback IP's. If the response from the resolver has the "authentic data" bit
	// set, the DNS name and all indirections towards the name, were signed and the
	// recursive resolver has verified them.
	Authentic bool

	// todo: possibly add followed cname's
	// todo: possibly add lowest TTL encountered in lookup (gathered after following cname's)
}
