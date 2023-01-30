This file lists RFC's by number and title. "make" fetches the RFC's and adds references back to the source code where they are referenced.

Also see IANA assignments, https://www.iana.org/protocols

# Mail, message format, MIME
822	Standard for ARPA Internet Text Messages
2045	Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies
2046	Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types
2047	MIME (Multipurpose Internet Mail Extensions) Part Three: Message Header Extensions for Non-ASCII Text
2049	Multipurpose Internet Mail Extensions (MIME) Part Five: Conformance Criteria and Examples
2231	MIME Parameter Value and Encoded Word Extensions: Character Sets, Languages, and Continuations
3629	UTF-8, a transformation format of ISO 10646
3834	Recommendations for Automatic Responses to Electronic Mail
5234	Augmented BNF for Syntax Specifications: ABNF
5322	Internet Message Format
5598	Internet Mail Architecture
7405	Case-Sensitive String Support in ABNF

# SMTP

821	(obsoleted by RFC 2821) SIMPLE MAIL TRANSFER PROTOCOL
2821	(obsoleted by RFC 5321) Simple Mail Transfer Protocol
5321	Simple Mail Transfer Protocol

1870	SMTP Service Extension for Message Size Declaration
1985	SMTP Service Extension for Remote Message Queue Starting
2034	SMTP Service Extension for Returning Enhanced Error Codes
2852	Deliver By SMTP Service Extension
2920	SMTP Service Extension for Command Pipelining
2505	Anti-Spam Recommendations for SMTP MTAs
2852	Deliver By SMTP Service Extension
3207	SMTP Service Extension for Secure SMTP over Transport Layer Security (STARTTLS)
3030	SMTP Service Extensions for Transmission of Large and Binary MIME Messages
3461	Simple Mail Transfer Protocol (SMTP) Service Extension for Delivery Status Notifications (DSNs)
3462	(obsoleted by RFC 6522) The Multipart/Report Content Type for the Reporting of Mail System Administrative Messages
3463	Enhanced Mail System Status Codes
3464	An Extensible Message Format for Delivery Status Notifications
3798	(obsoleted by RFC 8098) Message Disposition Notification
3848	ESMTP and LMTP Transmission Types Registration
3865	A No Soliciting Simple Mail Transfer Protocol (SMTP) Service Extension
3885	SMTP Service Extension for Message Tracking
3974	SMTP Operational Experience in Mixed IPv4/v6 Environments
4409	(obsoleted by RFC 6409) Message Submission for Mail
4865	SMTP Submission Service Extension for Future Message Release
4954	SMTP Service Extension for Authentication
5068	Email Submission Operations: Access and Accountability Requirements
5248	A Registry for SMTP Enhanced Mail System Status Codes
5335	(obsoleted by RFC 6532) Internationalized Email Headers
5336	(obsoleted by RFC 6531) SMTP Extension for Internationalized Email Addresses
5337	(obsoleted by RFC 6533) Internationalized Delivery Status and Disposition Notifications
6008	Authentication-Results Registration for Differentiating among Cryptographic Results
6152	SMTP Service Extension for 8-bit MIME Transport
6409	Message Submission for Mail
6522	The Multipart/Report Media Type for the Reporting of Mail System Administrative Messages
6530	Overview and Framework for Internationalized Email
6531	SMTP Extension for Internationalized Email
6532	Internationalized Email Headers
6533	Internationalized Delivery Status and Disposition Notifications
6729	Indicating Email Handling States in Trace Fields
7293	The Require-Recipient-Valid-Since Header Field and SMTP Service Extension
7372	Email Authentication Status Codes
7435	Opportunistic Security: Some Protection Most of the Time
7504	SMTP 521 and 556 Reply Codes
7505	A "Null MX" No Service Resource Record for Domains That Accept No Mail
8098	Message Disposition Notification
8601	Message Header Field for Indicating Message Authentication Status
8689	SMTP Require TLS Option

# SPF
4408	(obsoleted by RFC 7208) Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1
6652	Sender Policy Framework (SPF) Authentication Failure Reporting Using the Abuse Reporting Format
7208	Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1
7208-eid5436	errata: header-field FWS
7208-eid6721	errata: corrected smtp example response
7208-eid4751	errata (not verified): ptr mechanism
7208-eid5227	errata (not verified): ptr lookup order
7208-eid6595	errata (not verified): 2 void lookups vs exists
7208-eid6216	errata (not verified): ptr in multiple requirements example from appendix A.4

# DKIM
6376	DomainKeys Identified Mail (DKIM) Signatures
6376-eid4810	errata: q= qp-hdr-value
6376-eid5070	errata: tag-spec

4686	Analysis of Threats Motivating DomainKeys Identified Mail (DKIM)
4871	(obsoleted by RFC 6376) DomainKeys Identified Mail (DKIM) Signatures
5016	Requirements for a DomainKeys Identified Mail (DKIM) Signing Practices Protocol
5585	DomainKeys Identified Mail (DKIM) Service Overview
5672	(obsoleted by RFC 6376) DomainKeys Identified Mail (DKIM) Signatures -- Update
5863	DomainKeys Identified Mail (DKIM) Development, Deployment, and Operations
6377	DomainKeys Identified Mail (DKIM) and Mailing Lists
8032	Edwards-Curve Digital Signature Algorithm (EdDSA)
8301	Cryptographic Algorithm and Key Usage Update to DomainKeys Identified Mail (DKIM)
8463	A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM)

# DMARC
7489	Domain-based Message Authentication, Reporting, and Conformance (DMARC)
7489-eid5440	errata: valid dmarc records with(out) semicolon
7489-eid6729	errata (not verified): publicsuffix list only for ICANN DOMAINS
7960	Interoperability Issues between Domain-based Message Authentication, Reporting, and Conformance (DMARC) and Indirect Email Flows
9091	Experimental Domain-Based Message Authentication, Reporting, and Conformance (DMARC) Extension for Public Suffix Domains

# DKIM/SPF/DMARC
8616	Email Authentication for Internationalized Mail

# Greylisting
6647	Email Greylisting: An Applicability Statement for SMTP

# DNSBL/DNSWL
5782	DNS Blacklists and Whitelists
8904	DNS Whitelist (DNSWL) Email Authentication Method Extension

# DANE
6698	The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
7218	Adding Acronyms to Simplify Conversations about DNS-Based Authentication of Named Entities (DANE)
7671	The DNS-Based Authentication of Named Entities (DANE) Protocol: Updates and Operational Guidance
7672	SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS)

# TLS-RPT
8460	SMTP TLS Reporting
8460-eid6241	Wrong example for JSON field "mx-host".

# MTA-STS
8461	SMTP MTA Strict Transport Security (MTA-STS)

# ARC
8617	The Authenticated Received Chain (ARC) Protocol

# ARF
5965	An Extensible Format for Email Feedback Reports
6650	Creation and Use of Email Feedback Reports: An Applicability Statement for the Abuse Reporting Format (ARF)
6591	Authentication Failure Reporting Using the Abuse Reporting Format
6692	Source Ports in Abuse Reporting Format (ARF) Reports

# IMAP

1730	(obsoleted by RFC 2060) INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4
2060	(obsoleted by RFC 3501) INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1
3501	(obsoleted by RFC 9051) INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1
9051	Internet Message Access Protocol (IMAP) - Version 4rev2

1733	DISTRIBUTED ELECTRONIC MAIL MODELS IN IMAP4
2087	IMAP4 QUOTA extension
2088	(obsoleted by RFC 7888) IMAP4 non-synchronizing literals
2152	UTF-7 A Mail-Safe Transformation Format of Unicode
2177	IMAP4 IDLE command
2180	IMAP4 Multi-Accessed Mailbox Practice
2193	IMAP4 Mailbox Referrals
2342	IMAP4 Namespace
2683	IMAP4 Implementation Recommendations
2971	IMAP4 ID extension
3348	(obsoleted by RFC 5258) The Internet Message Action Protocol (IMAP4) Child Mailbox Extension
3502	Internet Message Access Protocol (IMAP) - MULTIAPPEND Extension
3503	Message Disposition Notification (MDN) profile for Internet Message Access Protocol (IMAP)
3516	IMAP4 Binary Content Extension
3691	Internet Message Access Protocol (IMAP) UNSELECT command
4314	IMAP4 Access Control List (ACL) Extension
4315	Internet Message Access Protocol (IMAP) - UIDPLUS extension
4466	Collected Extensions to IMAP4 ABNF
4467	Internet Message Access Protocol (IMAP) - URLAUTH Extension
4469	Internet Message Access Protocol (IMAP) CATENATE Extension
4549	Synchronization Operations for Disconnected IMAP4 Clients
4550	(obsoleted by RFC 5550) Internet Email to Support Diverse Service Environments (Lemonade) Profile
4551	(obsoleted by RFC 7162) IMAP Extension for Conditional STORE Operation or Quick Flag Changes Resynchronization
4731	IMAP4 Extension to SEARCH Command for Controlling What Kind of Information Is Returned
4978	The IMAP COMPRESS Extension
4959	IMAP Extension for Simple Authentication and Security Layer (SASL) Initial Client Response
5032	WITHIN Search Extension to the IMAP Protocol
5092	IMAP URL Scheme
5161	The IMAP ENABLE Extension
5162	(obsoleted by RFC 7162) IMAP4 Extensions for Quick Mailbox Resynchronization
5182	IMAP Extension for Referencing the Last SEARCH Result
5255	Internet Message Access Protocol Internationalization
5256	Internet Message Access Protocol - SORT and THREAD Extensions
5257	Internet Message Access Protocol - ANNOTATE Extension
5258	Internet Message Access Protocol version 4 - LIST Command Extensions
5259	Internet Message Access Protocol - CONVERT Extension
5267	Contexts for IMAP4
5464	The IMAP METADATA Extension
5465	The IMAP NOTIFY Extension
5466	IMAP4 Extension for Named Searches (Filters)
5530	IMAP Response Codes
5550	The Internet Email to Support Diverse Service Environments (Lemonade) Profile
5738	(obsoleted by RFC 6855) IMAP Support for UTF-8
5788	IMAP4 Keyword Registry
5819	IMAP4 Extension for Returning STATUS Information in Extended LIST
5957	Display-Based Address Sorting for the IMAP4 SORT Extension
6154	IMAP LIST Extension for Special-Use Mailboxes
6203	IMAP4 Extension for Fuzzy Search
6237	(obsoleted by RFC 7377) IMAP4 Multimailbox SEARCH Extension
6851	Internet Message Access Protocol (IMAP) - MOVE Extension
6855	IMAP Support for UTF-8
6858	Simplified POP and IMAP Downgrading for Internationalized Email
7162	IMAP Extensions: Quick Flag Changes Resynchronization (CONDSTORE) and Quick Mailbox Resynchronization (QRESYNC)
7377	IMAP4 Multimailbox SEARCH Extension
7888	IMAP4 Non-synchronizing Literals
7889	The IMAP APPENDLIMIT Extension
8437	IMAP UNAUTHENTICATE Extension for Connection Reuse
8474	IMAP Extension for Object Identifiers
8438	IMAP Extension for STATUS=SIZE
8457	IMAP "$Important" Keyword and "\Important" Special-Use Attribute
8508	IMAP REPLACE Extension
8514	Internet Message Access Protocol (IMAP) - SAVEDATE Extension
8970	IMAP4 Extension: Message Preview Generation

5198 	Unicode Format for Network Interchange

# Mailing list
2369	The Use of URLs as Meta-Syntax for Core Mail List Commands and their Transport through Message Header Fields
2919	List-Id: A Structured Field and Namespace for the Identification of Mailing Lists

# Sieve
5228	Sieve: An Email Filtering Language
and many more, see http://sieve.info/documents


# Vouch by reference
5518	Vouch By Reference

# TLS
6125	Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)
7525	Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
8314	Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access
8996	Deprecating TLS 1.0 and TLS 1.1
8997	Deprecation of TLS 1.1 for Email Submission and Access

# SASL

4013	(obsoleted by RFC 7613) SASLprep: Stringprep Profile for User Names and Passwords
4422	Simple Authentication and Security Layer (SASL)
4505	Anonymous Simple Authentication and Security Layer (SASL) Mechanism
4616	The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
5802	Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
6331	Moving DIGEST-MD5 to Historic
7613	(obsoleted by RFC 8265) Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords
7677	SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms
8265	Preparation, Enforcement, and Comparison of Internationalized Strings Representing Usernames and Passwords

# IDNA
3492	Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)
5890	Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework
5891	Internationalized Domain Names in Applications (IDNA): Protocol
5892	The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)
5893	Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)
5894	Internationalized Domain Names for Applications (IDNA): Background, Explanation, and Rationale

# ACME
8555	Automatic Certificate Management Environment (ACME)
8737	Automated Certificate Management Environment (ACME) TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension

# DNS
1034	DOMAIN NAMES - CONCEPTS AND FACILITIES
1035	DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
1101	DNS Encoding of Network Names and Other Types
1536	Common DNS Implementation Errors and Suggested Fixes
2181	Clarifications to the DNS Specification
2308	Negative Caching of DNS Queries (DNS NCACHE)
3363	Representing Internet Protocol version 6 (IPv6) Addresses in the Domain Name System (DNS)
3596	DNS Extensions to Support IP Version 6
3597	Handling of Unknown DNS Resource Record (RR) Types
4343	Domain Name System (DNS) Case Insensitivity Clarification
4592	The Role of Wildcards in the Domain Name System
5452	Measures for Making DNS More Resilient against Forged Answers
6604	xNAME RCODE and Status Bits Clarification
6672	DNAME Redirection in the DNS
6891	Extension Mechanisms for DNS (EDNS(0))
6895	Domain Name System (DNS) IANA Considerations
7766	DNS Transport over TCP - Implementation Requirements
8020	NXDOMAIN: There Really Is Nothing Underneath
8482	Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY
8490	DNS Stateful Operations
8767	Serving Stale Data to Improve DNS Resiliency
9210	DNS Transport over TCP - Operational Requirements

# DNSSEC
3225	Indicating Resolver Support of DNSSEC
3658	Delegation Signer (DS) Resource Record (RR)
4033	DNS Security Introduction and Requirements
4034	Resource Records for the DNS Security Extensions
4035	Protocol Modifications for the DNS Security Extensions
4470	Minimally Covering NSEC Records and DNSSEC On-line Signing
4956	DNS Security (DNSSEC) Opt-In
5155	DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
5702	Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
5933	Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC
6014	Cryptographic Algorithm Identifier Allocation for DNSSEC
6781	DNSSEC Operational Practices, Version 2
6840	Clarifications and Implementation Notes for DNS Security (DNSSEC)
8198	Aggressive Use of DNSSEC-Validated Cache
8624	Algorithm Implementation Requirements and Usage Guidance for DNSSEC
8749	Moving DNSSEC Lookaside Validation (DLV) to Historic Status
9077	NSEC and NSEC3: TTLs and Aggressive Use
9157	Revised IANA Considerations for DNSSEC
9276	Guidance for NSEC3 Parameter Settings

# More

3986	Uniform Resource Identifier (URI): Generic Syntax
5617	(Historic) DomainKeys Identified Mail (DKIM) Author Domain Signing Practices (ADSP)
6186	(not used in practice) Use of SRV Records for Locating Email Submission/Access Services
7817	Updated Transport Layer Security (TLS) Server Identity Check Procedure for Email-Related Protocols
