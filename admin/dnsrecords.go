package admin

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/mjl-/adns"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
	"github.com/mjl-/mox/tlsrpt"
	"slices"
)

// todo: find a way to automatically create the dns records as it would greatly simplify setting up email for a domain. we could also dynamically make changes, e.g. providing grace periods after disabling a dkim key, only automatically removing the dkim dns key after a few days. but this requires some kind of api and authentication to the dns server. there doesn't appear to be a single commonly used api for dns management. each of the numerous cloud providers have their own APIs and rather large SKDs to use them. we don't want to link all of them in.

// DomainRecords returns text lines describing DNS records required for configuring
// a domain.
//
// If certIssuerDomainName is set, CAA records to limit TLS certificate issuance to
// that caID will be suggested. If acmeAccountURI is also set, CAA records also
// restricting issuance to that account ID will be suggested.
func DomainRecords(domConf config.Domain, domain dns.Domain, hasDNSSEC bool, certIssuerDomainName, acmeAccountURI string) ([]string, error) {
	d := domain.ASCII
	h := mox.Conf.Static.HostnameDomain.ASCII

	// The first line with ";" is used by ../testdata/integration/moxacmepebble.sh and
	// ../testdata/integration/moxmail2.sh for selecting DNS records
	records := []string{
		"; Time To Live of 5 minutes, may be recognized if importing as a zone file.",
		"; Once your setup is working, you may want to increase the TTL.",
		"$TTL 300",
		"",
	}

	if public, ok := mox.Conf.Static.Listeners["public"]; ok && public.TLS != nil && (len(public.TLS.HostPrivateRSA2048Keys) > 0 || len(public.TLS.HostPrivateECDSAP256Keys) > 0) {
		records = append(records,
			`; DANE: These records indicate that a remote mail server trying to deliver email`,
			`; with SMTP (TCP port 25) must verify the TLS certificate with DANE-EE (3), based`,
			`; on the certificate public key ("SPKI", 1) that is SHA2-256-hashed (1) to the`,
			`; hexadecimal hash. DANE-EE verification means only the certificate or public`,
			`; key is verified, not whether the certificate is signed by a (centralized)`,
			`; certificate authority (CA), is expired, or matches the host name.`,
			`;`,
			`; NOTE: Create the records below only once: They are for the machine, and apply`,
			`; to all hosted domains.`,
		)
		if !hasDNSSEC {
			records = append(records,
				";",
				"; WARNING: Domain does not appear to be DNSSEC-signed. To enable DANE, first",
				"; enable DNSSEC on your domain, then add the TLSA records. Records below have been",
				"; commented out.",
			)
		}
		addTLSA := func(privKey crypto.Signer) error {
			spkiBuf, err := x509.MarshalPKIXPublicKey(privKey.Public())
			if err != nil {
				return fmt.Errorf("marshal SubjectPublicKeyInfo for DANE record: %v", err)
			}
			sum := sha256.Sum256(spkiBuf)
			tlsaRecord := adns.TLSA{
				Usage:     adns.TLSAUsageDANEEE,
				Selector:  adns.TLSASelectorSPKI,
				MatchType: adns.TLSAMatchTypeSHA256,
				CertAssoc: sum[:],
			}
			var s string
			if hasDNSSEC {
				s = fmt.Sprintf("_25._tcp.%-*s TLSA %s", 20+len(d)-len("_25._tcp."), h+".", tlsaRecord.Record())
			} else {
				s = fmt.Sprintf(";; _25._tcp.%-*s TLSA %s", 20+len(d)-len(";; _25._tcp."), h+".", tlsaRecord.Record())
			}
			records = append(records, s)
			return nil
		}
		for _, privKey := range public.TLS.HostPrivateECDSAP256Keys {
			if err := addTLSA(privKey); err != nil {
				return nil, err
			}
		}
		for _, privKey := range public.TLS.HostPrivateRSA2048Keys {
			if err := addTLSA(privKey); err != nil {
				return nil, err
			}
		}
		records = append(records, "")
	}

	if d != h {
		records = append(records,
			"; For the machine, only needs to be created once, for the first domain added:",
			"; ",
			"; SPF-allow host for itself, resulting in relaxed DMARC pass for (postmaster)",
			"; messages (DSNs) sent from host:",
			fmt.Sprintf(`%-*s TXT "v=spf1 a -all"`, 20+len(d), h+"."), // ../rfc/7208:2263 ../rfc/7208:2287
			"",
		)
	}
	if d != h && mox.Conf.Static.HostTLSRPT.ParsedLocalpart != "" {
		uri := url.URL{
			Scheme: "mailto",
			Opaque: smtp.NewAddress(mox.Conf.Static.HostTLSRPT.ParsedLocalpart, mox.Conf.Static.HostnameDomain).Pack(false),
		}
		tlsrptr := tlsrpt.Record{Version: "TLSRPTv1", RUAs: [][]tlsrpt.RUA{{tlsrpt.RUA(uri.String())}}}
		records = append(records,
			"; For the machine, only needs to be created once, for the first domain added:",
			"; ",
			"; Request reporting about success/failures of TLS connections to (MX) host, for DANE.",
			fmt.Sprintf(`_smtp._tls.%-*s         TXT "%s"`, 20+len(d)-len("_smtp._tls."), h+".", tlsrptr.String()),
			"",
		)
	}

	records = append(records,
		"; Deliver email for the domain to this host.",
		fmt.Sprintf("%s.                    MX 10 %s.", d, h),
		"",

		"; Outgoing messages will be signed with the first two DKIM keys. The other two",
		"; configured for backup, switching to them is just a config change.",
	)
	var selectors []string
	for name := range domConf.DKIM.Selectors {
		selectors = append(selectors, name)
	}
	slices.Sort(selectors)
	for _, name := range selectors {
		sel := domConf.DKIM.Selectors[name]
		dkimr := dkim.Record{
			Version:   "DKIM1",
			Hashes:    []string{"sha256"},
			PublicKey: sel.Key.Public(),
		}
		if _, ok := sel.Key.(ed25519.PrivateKey); ok {
			dkimr.Key = "ed25519"
		} else if _, ok := sel.Key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("unrecognized private key for DKIM selector %q: %T", name, sel.Key)
		}
		txt, err := dkimr.Record()
		if err != nil {
			return nil, fmt.Errorf("making DKIM DNS TXT record: %v", err)
		}

		if len(txt) > 100 {
			records = append(records,
				"; NOTE: The following is a single long record split over several lines for use",
				"; in zone files. When adding through a DNS operator web interface, combine the",
				"; strings into a single string, without ().",
			)
		}
		s := fmt.Sprintf("%s._domainkey.%s.   TXT %s", name, d, mox.TXTStrings(txt))
		records = append(records, s)

	}
	dmarcr := dmarc.DefaultRecord
	dmarcr.Policy = "reject"
	if domConf.DMARC != nil {
		uri := url.URL{
			Scheme: "mailto",
			Opaque: smtp.NewAddress(domConf.DMARC.ParsedLocalpart, domConf.DMARC.DNSDomain).Pack(false),
		}
		dmarcr.AggregateReportAddresses = []dmarc.URI{
			{Address: uri.String(), MaxSize: 10, Unit: "m"},
		}
	}
	dspfr := spf.Record{Version: "spf1"}
	for _, ip := range mox.DomainSPFIPs() {
		mech := "ip4"
		if ip.To4() == nil {
			mech = "ip6"
		}
		dspfr.Directives = append(dspfr.Directives, spf.Directive{Mechanism: mech, IP: ip})
	}
	dspfr.Directives = append(dspfr.Directives,
		spf.Directive{Mechanism: "mx"},
		spf.Directive{Qualifier: "~", Mechanism: "all"},
	)
	dspftxt, err := dspfr.Record()
	if err != nil {
		return nil, fmt.Errorf("making domain spf record: %v", err)
	}
	records = append(records,
		"",

		"; Specify the MX host is allowed to send for our domain and for itself (for DSNs).",
		"; ~all means softfail for anything else, which is done instead of -all to prevent older",
		"; mail servers from rejecting the message because they never get to looking for a dkim/dmarc pass.",
		fmt.Sprintf(`%s.                    TXT "%s"`, d, dspftxt),
		"",

		"; Emails that fail the DMARC check (without aligned DKIM and without aligned SPF)",
		"; should be rejected, and request reports. If you email through mailing lists that",
		"; strip DKIM-Signature headers and don't rewrite the From header, you may want to",
		"; set the policy to p=none.",
		fmt.Sprintf(`_dmarc.%s.             TXT "%s"`, d, dmarcr.String()),
		"",
	)

	if sts := domConf.MTASTS; sts != nil {
		records = append(records,
			"; Remote servers can use MTA-STS to verify our TLS certificate with the",
			"; WebPKI pool of CA's (certificate authorities) when delivering over SMTP with",
			"; STARTTLS.",
			fmt.Sprintf(`mta-sts.%s.            CNAME %s.`, d, h),
			fmt.Sprintf(`_mta-sts.%s.           TXT "v=STSv1; id=%s"`, d, sts.PolicyID),
			"",
		)
	} else {
		records = append(records,
			"; Note: No MTA-STS to indicate TLS should be used. Either because disabled for the",
			"; domain or because mox.conf does not have a listener with MTA-STS configured.",
			"",
		)
	}

	if domConf.TLSRPT != nil {
		uri := url.URL{
			Scheme: "mailto",
			Opaque: smtp.NewAddress(domConf.TLSRPT.ParsedLocalpart, domConf.TLSRPT.DNSDomain).Pack(false),
		}
		tlsrptr := tlsrpt.Record{Version: "TLSRPTv1", RUAs: [][]tlsrpt.RUA{{tlsrpt.RUA(uri.String())}}}
		records = append(records,
			"; Request reporting about TLS failures.",
			fmt.Sprintf(`_smtp._tls.%s.         TXT "%s"`, d, tlsrptr.String()),
			"",
		)
	}

	if domConf.ClientSettingsDomain != "" && domConf.ClientSettingsDNSDomain != mox.Conf.Static.HostnameDomain {
		records = append(records,
			"; Client settings will reference a subdomain of the hosted domain, making it",
			"; easier to migrate to a different server in the future by not requiring settings",
			"; in all clients to be updated.",
			fmt.Sprintf(`%-*s CNAME %s.`, 20+len(d), domConf.ClientSettingsDNSDomain.ASCII+".", h),
			"",
		)
	}

	records = append(records,
		"; Autoconfig is used by Thunderbird. Autodiscover is (in theory) used by Microsoft.",
		fmt.Sprintf(`autoconfig.%s.         CNAME %s.`, d, h),
		fmt.Sprintf(`_autodiscover._tcp.%s. SRV 0 1 443 %s.`, d, h),
		"",

		// ../rfc/6186:133 ../rfc/8314:692
		"; For secure IMAP and submission autoconfig, point to mail host.",
		fmt.Sprintf(`_imaps._tcp.%s.        SRV 0 1 993 %s.`, d, h),
		fmt.Sprintf(`_submissions._tcp.%s.  SRV 0 1 465 %s.`, d, h),
		"",
		// ../rfc/6186:242
		"; Next records specify POP3 and non-TLS ports are not to be used.",
		"; These are optional and safe to leave out (e.g. if you have to click a lot in a",
		"; DNS admin web interface).",
		fmt.Sprintf(`_imap._tcp.%s.         SRV 0 0 0 .`, d),
		fmt.Sprintf(`_submission._tcp.%s.   SRV 0 0 0 .`, d),
		fmt.Sprintf(`_pop3._tcp.%s.         SRV 0 0 0 .`, d),
		fmt.Sprintf(`_pop3s._tcp.%s.        SRV 0 0 0 .`, d),
	)

	if certIssuerDomainName != "" {
		// ../rfc/8659:18 for CAA records.
		records = append(records,
			"",
			"; Optional:",
			"; You could mark Let's Encrypt as the only Certificate Authority allowed to",
			"; sign TLS certificates for your domain.",
			fmt.Sprintf(`%s.                    CAA 0 issue "%s"`, d, certIssuerDomainName),
		)
		if acmeAccountURI != "" {
			// ../rfc/8657:99 for accounturi.
			// ../rfc/8657:147 for validationmethods.
			records = append(records,
				";",
				"; Optionally limit certificates for this domain to the account ID and methods used by mox.",
				fmt.Sprintf(`;; %s.                 CAA 0 issue "%s; accounturi=%s; validationmethods=tls-alpn-01,http-01"`, d, certIssuerDomainName, acmeAccountURI),
				";",
				"; Or alternatively only limit for email-specific subdomains, so you can use",
				"; other accounts/methods for other subdomains.",
				fmt.Sprintf(`;; autoconfig.%s.      CAA 0 issue "%s; accounturi=%s; validationmethods=tls-alpn-01,http-01"`, d, certIssuerDomainName, acmeAccountURI),
				fmt.Sprintf(`;; mta-sts.%s.         CAA 0 issue "%s; accounturi=%s; validationmethods=tls-alpn-01,http-01"`, d, certIssuerDomainName, acmeAccountURI),
			)
			if domConf.ClientSettingsDomain != "" && domConf.ClientSettingsDNSDomain != mox.Conf.Static.HostnameDomain {
				records = append(records,
					fmt.Sprintf(`;; %-*s CAA 0 issue "%s; accounturi=%s; validationmethods=tls-alpn-01,http-01"`, 20-3+len(d), domConf.ClientSettingsDNSDomain.ASCII, certIssuerDomainName, acmeAccountURI),
				)
			}
			if strings.HasSuffix(h, "."+d) {
				records = append(records,
					";",
					"; And the mail hostname.",
					fmt.Sprintf(`;; %-*s CAA 0 issue "%s; accounturi=%s; validationmethods=tls-alpn-01,http-01"`, 20-3+len(d), h+".", certIssuerDomainName, acmeAccountURI),
				)
			}
		} else {
			// The string "will be suggested" is used by
			// ../testdata/integration/moxacmepebble.sh and ../testdata/integration/moxmail2.sh
			// as end of DNS records.
			records = append(records,
				";",
				"; Note: After starting up, once an ACME account has been created, CAA records",
				"; that restrict issuance to the account will be suggested.",
			)
		}
	}
	return records, nil
}
