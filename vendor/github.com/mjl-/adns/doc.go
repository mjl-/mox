/*
adns is a copy of the Go standard library, modified to provide details about
the DNSSEC status of responses.

The MX, NS, SRV types from the "net" package are used to make to prevent churn
when switching from net to adns.

Modifications

  - Each Lookup* also returns a Result with the "Authentic" field representing if
    the response had the "authentic data" bit (and is trusted), i.e. was
    DNSSEC-signed according to the recursive resolver.
  - Resolver are also trusted if all name servers have loopback IPs. Resolvers
    are still also trusted if /etc/resolv.conf has "trust-ad" in the "options".
  - New function LookupTLSA, to support DANE which uses DNS records of type TLSA.
  - Support Extended DNS Errors (EDE) for details about DNSSEC errors.
  - adns uses its own DNSError type, with an additional "Underlying error" field
    and Unwrap function, so callers can check for the new ExtendedError type.
*/
package adns
