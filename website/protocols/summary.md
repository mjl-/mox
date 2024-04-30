# Protocols

## Summary

First a high-level description of protocols and implementation status. Each
topic links to the second table with more detailed implementation status per
RFC.

<table>
<tr><th>Topic</th><th>Implemented</th><th>Description</th></tr>
<tr><td><a href="#topic-internet-message-format">Internet Message Format</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>The format of email messages</td></tr>
<tr><td><a href="#topic-smtp">SMTP</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Delivering email</td></tr>
<tr><td><a href="#topic-spf">SPF</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Message authentication based on sending IP</td></tr>
<tr><td><a href="#topic-dkim">DKIM</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Message authentication based on message header</td></tr>
<tr><td><a href="#topic-dmarc">DMARC</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Reject/accept policy for incoming messages that pass/fail DKIM and/or SPF message authentication</td></tr>
<tr><td><a href="#topic-arc">ARC</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>Signed message authentication results from forwarding server</td></tr>
<tr><td><a href="#topic-dane">DANE</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Verification of TLS certificates through DNSSEC-protected DNS records</td></tr>
<tr><td><a href="#topic-mta-sts">MTA-STS</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>PKIX-based protection of TLS certificates and MX records</td></tr>
<tr><td><a href="#topic-tls-reporting">TLS Reporting</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Reporting about TLS interoperability issues</td></tr>
<tr><td><a href="#topic-arf">ARF</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>Abuse reporting format</td></tr>
<tr><td><a href="#topic-imap">IMAP</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Email access protocol</td></tr>
<tr><td><a href="#topic-sieve">Sieve</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>Scripts to run on incoming messages</td></tr>
<tr><td><a href="#topic-jmap">JMAP</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>HTTP/JSON-based email access protocol</td></tr>
<tr><td><a href="#topic-caldav-ical">CalDAV/iCal</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>Calendaring</td></tr>
<tr><td><a href="#topic-carddav-vcard">CardDAV/vCard</a></td> <td style="text-align: center"><span class="roadmap">Roadmap</span></td> <td>Contacts</td></tr>
<tr><td><a href="#topic-sasl">SASL</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Authentication mechanisms</td></tr>
<tr><td><a href="#topic-internationalization">Internationalization</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Internationalization of domain names.</td></tr>
<tr><td><a href="#topic-tls">TLS</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>TLS, for encrypted and authenticated communication.</td></tr>
<tr><td><a href="#topic-acme">ACME</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>Automatically manage PKIX TLS certificates</td></tr>
<tr><td><a href="#topic-caa">CAA</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>CAA DNS reords specify which certificate authorities (CAs) are allowed to sign certificates for a domain.</td></tr>
<tr><td><a href="#topic-http">HTTP</a></td> <td style="text-align: center"><span class="implemented">Yes</span></td> <td>HTTP for webservers. Required for automatic account configuration and MTA-STS. Also relevant for the built-in webserver.</td></tr>
</table>

## RFCs

The mox source code is quite heavily annotated with references to the RFCs.
This makes the implementation more maintainable, and makes it easier for new
developers to make changes. See [cross-referenced code and RFCs](../xr/dev/) to
navigate RFCs and source code side by side.

Implementation status per RFC, grouped by topic.

### Statuses
