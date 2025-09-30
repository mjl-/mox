#!/bin/sh
set -eu

# we rewrite some dmarcprt and tlsrpt enums into untyped strings: real-world
# reports have invalid values, and our loose Go typed strings accept all values,
# but we don't want the typescript runtime checker to fail on those unrecognized
# values.
(cd webadmin && go tool sherpadoc -adjust-function-names none -rename 'config Domain ConfigDomain,dmarc Policy DMARCPolicy,mtasts MX STSMX,tlsrptdb Record TLSReportRecord,tlsrptdb SuppressAddress TLSRPTSuppressAddress,dmarcrpt DKIMResult string,dmarcrpt SPFResult string,dmarcrpt SPFDomainScope string,dmarcrpt DMARCResult string,dmarcrpt PolicyOverride string,dmarcrpt Alignment string,dmarcrpt Disposition string,tlsrpt PolicyType string,tlsrpt ResultType string' Admin) >webadmin/api.json
(cd webaccount && go tool sherpadoc -adjust-function-names none Account) >webaccount/api.json
(cd webmail && go tool sherpadoc -adjust-function-names none Webmail) >webmail/api.json
