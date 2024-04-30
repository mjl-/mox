package message

import (
	"testing"

	"github.com/mjl-/mox/dns"
)

func TestAuthResultsPack(t *testing.T) {
	dom, err := dns.ParseDomain("møx.example")
	if err != nil {
		t.Fatalf("parsing domain: %v", err)
	}
	authRes := AuthResults{
		Hostname: dom.XName(true),
		Comment:  dom.ASCIIExtra(true),
		Methods: []AuthMethod{
			{"dkim", "", "pass", "", "", []AuthProp{{"header", "d", dom.XName(true), true, dom.ASCIIExtra(true)}}},
		},
	}
	s := authRes.Header()
	const exp = "Authentication-Results: (xn--mx-lka.example) møx.example;\r\n\tdkim=pass header.d=møx.example (xn--mx-lka.example)\r\n"
	if s != exp {
		t.Fatalf("got %q, expected %q", s, exp)
	}
}

func TestAuthResultsParse(t *testing.T) {
	ar, err := ParseAuthResults("(xn--mx-lka.example) møx.example;\r\n\tdkim=pass header.d=møx.example (xn--mx-lka.example)\r\n")
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "møx.example",
		Methods: []AuthMethod{
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "møx.example"},
				},
			},
		},
	})

	const localhost = `localhost;
	auth=pass smtp.mailfrom=mox+qvpVtG6ZQg-vJmN_beaGyQ@localhost
`
	ar, err = ParseAuthResults(localhost)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "localhost",
		Methods: []AuthMethod{
			{
				Method: "auth",
				Result: "pass",
				Props: []AuthProp{
					{Type: "smtp", Property: "mailfrom", IsAddrLike: true, Value: "mox+qvpVtG6ZQg-vJmN_beaGyQ@localhost"},
				},
			},
		},
	})

	const other = `komijn.test.xmox.nl;
	iprev=pass (without dnssec) policy.iprev=198.2.145.102;
	dkim=pass (2048 bit rsa, without dnssec) header.d=mandrillapp.com
	header.s=mte1 header.a=rsa-sha256 header.b="CfNW8cht1/v3";
	dkim=pass (2048 bit rsa, without dnssec) header.d=letsencrypt.org
	header.s=mte1 header.a=rsa-sha256 header.b=F9lCi4OC77su
	header.i=expiry@letsencrypt.org;
	spf=pass (without dnssec) smtp.mailfrom=delivery.letsencrypt.org;
	dmarc=pass (without dnssec) header.from=letsencrypt.org
`

	ar, err = ParseAuthResults(other)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "komijn.test.xmox.nl",
		Methods: []AuthMethod{
			{
				Method: "iprev",
				Result: "pass",
				Props: []AuthProp{
					{Type: "policy", Property: "iprev", Value: "198.2.145.102"},
				},
			},
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "mandrillapp.com"},
					{Type: "header", Property: "s", Value: "mte1"},
					{Type: "header", Property: "a", Value: "rsa-sha256"},
					{Type: "header", Property: "b", Value: "CfNW8cht1/v3"},
				},
			},
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "letsencrypt.org"},
					{Type: "header", Property: "s", Value: "mte1"},
					{Type: "header", Property: "a", Value: "rsa-sha256"},
					{Type: "header", Property: "b", Value: "F9lCi4OC77su"},
					{Type: "header", Property: "i", IsAddrLike: true, Value: "expiry@letsencrypt.org"},
				},
			},
			{
				Method: "spf",
				Result: "pass",
				Props: []AuthProp{
					{Type: "smtp", Property: "mailfrom", Value: "delivery.letsencrypt.org"},
				},
			},
			{
				Method: "dmarc",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "from", Value: "letsencrypt.org"},
				},
			},
		},
	})

	const google = `mx.google.com;
       dkim=pass header.i=@test.xmox.nl header.s=2022b header.b="Z9k/yZIA";
       spf=pass (google.com: domain of mjl@test.xmox.nl designates 2a02:2770::21a:4aff:feba:bde0 as permitted sender) smtp.mailfrom=mjl@test.xmox.nl;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=test.xmox.nl
`

	ar, err = ParseAuthResults(google)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mx.google.com",
		Methods: []AuthMethod{
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "i", IsAddrLike: true, Value: "@test.xmox.nl"},
					{Type: "header", Property: "s", Value: "2022b"},
					{Type: "header", Property: "b", Value: "Z9k/yZIA"},
				},
			},
			{
				Method: "spf",
				Result: "pass",
				Props: []AuthProp{
					{Type: "smtp", Property: "mailfrom", IsAddrLike: true, Value: "mjl@test.xmox.nl"},
				},
			},
			{
				Method: "dmarc",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "from", Value: "test.xmox.nl"},
				},
			},
		},
	})

	const yahoo = `atlas220.free.mail.bf1.yahoo.com;
 dkim=perm_fail header.i=@ueber.net header.s=2023a;
 dkim=pass header.i=@ueber.net header.s=2023b;
 spf=pass smtp.mailfrom=ueber.net;
 dmarc=pass(p=REJECT) header.from=ueber.net;
`
	ar, err = ParseAuthResults(yahoo)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "atlas220.free.mail.bf1.yahoo.com",
		Methods: []AuthMethod{
			{
				Method: "dkim",
				Result: "perm_fail",
				Props: []AuthProp{
					{Type: "header", Property: "i", IsAddrLike: true, Value: "@ueber.net"},
					{Type: "header", Property: "s", Value: "2023a"},
				},
			},
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "i", IsAddrLike: true, Value: "@ueber.net"},
					{Type: "header", Property: "s", Value: "2023b"},
				},
			},
			{
				Method: "spf",
				Result: "pass",
				Props: []AuthProp{
					{Type: "smtp", Property: "mailfrom", Value: "ueber.net"},
				},
			},
			{
				Method: "dmarc",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "from", Value: "ueber.net"},
				},
			},
		},
	})

	const proton0 = `mail.protonmail.ch; dkim=pass (Good
    ed25519-sha256 signature) header.d=ueber.net header.i=mechiel@ueber.net
    header.a=ed25519-sha256; dkim=pass (Good 2048 bit rsa-sha256 signature)
    header.d=ueber.net header.i=mechiel@ueber.net header.a=rsa-sha256
`
	ar, err = ParseAuthResults(proton0)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mail.protonmail.ch",
		Methods: []AuthMethod{
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "ueber.net"},
					{Type: "header", Property: "i", IsAddrLike: true, Value: "mechiel@ueber.net"},
					{Type: "header", Property: "a", Value: "ed25519-sha256"},
				},
			},
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "ueber.net"},
					{Type: "header", Property: "i", IsAddrLike: true, Value: "mechiel@ueber.net"},
					{Type: "header", Property: "a", Value: "rsa-sha256"},
				},
			},
		},
	})

	const proton1 = `mail.protonmail.ch; dmarc=pass (p=reject dis=none)
 header.from=ueber.net
`
	ar, err = ParseAuthResults(proton1)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mail.protonmail.ch",
		Methods: []AuthMethod{
			{
				Method: "dmarc",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "from", Value: "ueber.net"},
				},
			},
		},
	})
	const proton2 = `mail.protonmail.ch; spf=pass smtp.mailfrom=ueber.net
`
	ar, err = ParseAuthResults(proton2)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mail.protonmail.ch",
		Methods: []AuthMethod{
			{
				Method: "spf",
				Result: "pass",
				Props: []AuthProp{
					{Type: "smtp", Property: "mailfrom", Value: "ueber.net"},
				},
			},
		},
	})
	const proton3 = `mail.protonmail.ch; arc=none smtp.remote-ip=84.22.96.237
`
	ar, err = ParseAuthResults(proton3)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mail.protonmail.ch",
		Methods: []AuthMethod{
			{
				Method: "arc",
				Result: "none",
				Props: []AuthProp{
					{Type: "smtp", Property: "remote-ip", Value: "84.22.96.237"},
				},
			},
		},
	})
	const proton4 = `mail.protonmail.ch; dkim=permerror (0-bit key) header.d=ueber.net
 header.i=mechiel@ueber.net header.b="a4SMWyJ7"; dkim=pass (2048-bit key)
 header.d=ueber.net header.i=mechiel@ueber.net header.b="mQickWQ7"
`
	ar, err = ParseAuthResults(proton4)
	tcheck(t, err, "parsing auth results header")
	tcompare(t, ar, AuthResults{
		Hostname: "mail.protonmail.ch",
		Methods: []AuthMethod{
			{
				Method: "dkim",
				Result: "permerror",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "ueber.net"},
					{Type: "header", Property: "i", IsAddrLike: true, Value: "mechiel@ueber.net"},
					{Type: "header", Property: "b", Value: "a4SMWyJ7"},
				},
			},
			{
				Method: "dkim",
				Result: "pass",
				Props: []AuthProp{
					{Type: "header", Property: "d", Value: "ueber.net"},
					{Type: "header", Property: "i", IsAddrLike: true, Value: "mechiel@ueber.net"},
					{Type: "header", Property: "b", Value: "mQickWQ7"},
				},
			},
		},
	})

	// Outlook adds an invalid line, missing required hostname at the start. And their
	// dmarc "action=none" is invalid. Nothing to be done.
	const outlook = `x; spf=pass (sender IP is 84.22.96.237)
 smtp.mailfrom=ueber.net; dkim=pass (signature was verified)
 header.d=ueber.net;dmarc=pass action=none header.from=ueber.net;compauth=pass
 reason=100
`
	_, err = ParseAuthResults(outlook)
	if err == nil {
		t.Fatalf("missing error while parsing authresults header from outlook")
	}
}
