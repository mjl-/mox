// Package tlsrpt implements SMTP TLS Reporting, RFC 8460.
//
// TLSRPT allows a domain to publish a policy requesting feedback of TLS
// connectivity to its SMTP servers. Reports can be sent to an address defined
// in the TLSRPT DNS record. These reports can be parsed by tlsrpt.
package tlsrpt
