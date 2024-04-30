package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

var submitconf struct {
	LocalHostname      string           `sconf-doc:"Hosts don't always have an FQDN, set it explicitly, for EHLO."`
	Host               string           `sconf-doc:"Host to dial for delivery, e.g. mail.<domain>."`
	Port               int              `sconf-doc:"Port to dial for delivery, e.g. 465 for submissions, 587 for submission, or perhaps 25 for smtp."`
	TLS                bool             `sconf-doc:"Connect with TLS. Usually for connections to port 465."`
	STARTTLS           bool             `sconf-doc:"After starting in plain text, use STARTTLS to enable TLS. For port 587 and 25."`
	Username           string           `sconf-doc:"For SMTP authentication."`
	Password           string           `sconf-doc:"For password-based SMTP authentication, e.g. SCRAM-SHA-256-PLUS, CRAM-MD5, PLAIN."`
	AuthMethod         string           `sconf-doc:"If set, only attempt this authentication mechanism. E.g. SCRAM-SHA-256-PLUS, SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5, PLAIN. If not set, any mutually supported algorithm can be used, in order listed, from most to least secure. It is recommended to specify the strongest authentication mechanism known to be implemented by the server, to prevent mechanism downgrade attacks."`
	From               string           `sconf-doc:"Address for MAIL FROM in SMTP and From-header in message."`
	DefaultDestination string           `sconf:"optional" sconf-doc:"Used when specified address does not contain an @ and may be a local user (eg root)."`
	RequireTLS         RequireTLSOption `sconf:"optional" sconf-doc:"If yes, submission server must implement SMTP REQUIRETLS extension, and connection to submission server must use verified TLS. If no, a TLS-Required header with value no is added to the message, allowing fallback to unverified TLS or plain text delivery despite recpient domain policies. By default, the submission server will follow the policies of the recipient domain (MTA-STS and/or DANE), and apply unverified opportunistic TLS with STARTTLS."`
}

type RequireTLSOption string

const (
	RequireTLSDefault RequireTLSOption = ""
	RequireTLSYes     RequireTLSOption = "yes"
	RequireTLSNo      RequireTLSOption = "no"
)

func cmdConfigDescribeSendmail(c *cmd) {
	c.params = ">/etc/moxsubmit.conf"
	c.help = `Describe configuration for mox when invoked as sendmail.`
	if len(c.Parse()) != 0 {
		c.Usage()
	}

	err := sconf.Describe(os.Stdout, submitconf)
	xcheckf(err, "describe config")
}

func cmdSendmail(c *cmd) {
	c.params = "[-Fname] [ignoredflags] [-t] [<message]"
	c.help = `Sendmail is a drop-in replacement for /usr/sbin/sendmail to deliver emails sent by unix processes like cron.

If invoked as "sendmail", it will act as sendmail for sending messages. Its
intention is to let processes like cron send emails. Messages are submitted to
an actual mail server over SMTP. The destination mail server and credentials are
configured in /etc/moxsubmit.conf, see mox config describe-sendmail. The From
message header is rewritten to the configured address. When the addressee
appears to be a local user, because without @, the message is sent to the
configured default address.

If submitting an email fails, it is added to a directory moxsubmit.failures in
the user's home directory.

Most flags are ignored to fake compatibility with other sendmail
implementations. A single recipient or the -t flag with a To-header is required.
With the -t flag, Cc and Bcc headers are not handled specially, so Bcc is not
removed and the addresses do not receive the email.

/etc/moxsubmit.conf should be group-readable and not readable by others and this
binary should be setgid that group:

	groupadd moxsubmit
	install -m 2755 -o root -g moxsubmit mox /usr/sbin/sendmail
	touch /etc/moxsubmit.conf
	chown root:moxsubmit /etc/moxsubmit.conf
	chmod 640 /etc/moxsubmit.conf
	# edit /etc/moxsubmit.conf
`

	// We are faking that we parse flags, this is non-standard, we want to be lax and ignore most flags.
	args := c.flagArgs
	c.flagArgs = []string{}
	c.Parse() // We still have to call Parse for the usage gathering.

	// Typical cron usage of sendmail:
	// anacron: https://salsa.debian.org/debian/anacron/-/blob/c939c8c80fc9419c11a5e6be5cbe84f03ad332fd/runjob.c#L183
	// cron: https://github.com/vixie/cron/blob/fea7a6c5421f88f034be8eef66a84d8b65b5fbe0/config.h#L41

	var from string
	var tflag bool // If set, we need to take the recipient(s) from the message headers. We only do one recipient, in To.
	o := 0
	for i, s := range args {
		if s == "--" {
			o = i + 1
			break
		}
		if !strings.HasPrefix(s, "-") {
			o = i
			break
		}
		s = s[1:]
		if strings.HasPrefix(s, "F") {
			from = s[1:]
			log.Printf("ignoring -F %q", from) // todo
		} else if s == "t" {
			tflag = true
		}
		o = i + 1
		// Ignore options otherwise.
		// todo: we may want to parse more flags. some invocations may not be about sending a message. for now, we'll assume sendmail is only invoked to send a message.
	}
	args = args[o:]

	// todo: perhaps allow configuration of config file through environment variable? have to keep in mind that mox with setgid moxsubmit would be reading the file.
	const confPath = "/etc/moxsubmit.conf"
	err := sconf.ParseFile(confPath, &submitconf)
	xcheckf(err, "parsing config")

	var recipient string
	if len(args) == 1 && !tflag {
		recipient = args[0]
		if !strings.Contains(recipient, "@") {
			if submitconf.DefaultDestination == "" {
				log.Fatalf("recipient %q has no @ and no default destination configured", recipient)
			}
			recipient = submitconf.DefaultDestination
		} else {
			_, err := smtp.ParseAddress(args[0])
			xcheckf(err, "parsing recipient address")
		}
	} else if !tflag || len(args) != 0 {
		log.Fatalln("need either exactly 1 recipient, or -t")
	}

	// Read message and build message we are going to send. We replace \n
	// with \r\n, and we replace the From header.
	// todo: should we also wrap lines that are too long? perhaps only if this is just text, no multipart?
	var sb strings.Builder
	r := bufio.NewReader(os.Stdin)
	header := true // Whether we are in the header.
	fmt.Fprintf(&sb, "From: <%s>\r\n", submitconf.From)
	var haveTo bool
	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			xcheckf(err, "reading message")
		}
		if line != "" {
			if !strings.HasSuffix(line, "\n") {
				line += "\n"
			}
			if !strings.HasSuffix(line, "\r\n") {
				line = line[:len(line)-1] + "\r\n"
			}
			if header && line == "\r\n" {
				// Bare \r\n marks end of header.
				if !haveTo {
					line = fmt.Sprintf("To: <%s>\r\n", recipient) + line
				}
				if submitconf.RequireTLS == RequireTLSNo {
					line = "TLS-Required: No\r\n" + line
				}
				header = false
			} else if header {
				t := strings.SplitN(line, ":", 2)
				if len(t) != 2 {
					log.Fatalf("invalid message, missing colon in header")
				}
				k := strings.ToLower(t[0])
				if k == "from" {
					// We already added a From header.
					if err == io.EOF {
						break
					}
					continue
				} else if tflag && k == "to" {
					if recipient != "" {
						log.Fatalf("only single To header allowed")
					}
					s := strings.TrimSpace(t[1])
					if !strings.Contains(s, "@") {
						if submitconf.DefaultDestination == "" {
							log.Fatalf("recipient %q has no @ and no default destination is configured", s)
						}
						recipient = submitconf.DefaultDestination
					} else {
						addrs, err := mail.ParseAddressList(s)
						xcheckf(err, "parsing To address list")
						if len(addrs) != 1 {
							log.Fatalf("only single address allowed in To header")
						}
						recipient = addrs[0].Address
					}
				}
				if k == "to" {
					haveTo = true
				}
			}
			sb.WriteString(line)
		}
		if err == io.EOF {
			break
		}
	}
	if header && submitconf.RequireTLS == RequireTLSNo {
		sb.WriteString("TLS-Required: No\r\n")
	}
	msg := sb.String()

	if recipient == "" {
		log.Fatalf("no recipient")
	}

	// Message seems acceptable. We'll try to deliver it from here. If that fails, we
	// store the message in the users home directory.
	// Must only use xsavecheckf for error checking in the code below.

	xsavecheckf := func(err error, format string, args ...any) {
		if err == nil {
			return
		}
		log.Printf("submit failed: %s: %s", fmt.Sprintf(format, args...), err)
		homedir, err := os.UserHomeDir()
		xcheckf(err, "finding homedir for storing message after failed delivery")
		maildir := filepath.Join(homedir, "moxsubmit.failures")
		os.Mkdir(maildir, 0700)
		f, err := os.CreateTemp(maildir, "newmsg.")
		xcheckf(err, "creating temp file for storing message after failed delivery")
		// note: not removing the partial file if writing/closing below fails.
		_, err = f.Write([]byte(msg))
		xcheckf(err, "writing message to temp file after failed delivery")
		name := f.Name()
		err = f.Close()
		xcheckf(err, "closing message in temp file after failed delivery")
		f = nil
		log.Printf("saved message in %s", name)
		os.Exit(1)
	}

	addr := net.JoinHostPort(submitconf.Host, fmt.Sprintf("%d", submitconf.Port))
	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.Dial("tcp", addr)
	xsavecheckf(err, "dial submit server")

	auth := func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
		// Check explicitly configured mechanisms.
		switch submitconf.AuthMethod {
		case "SCRAM-SHA-256-PLUS":
			if cs == nil {
				return nil, fmt.Errorf("scram plus authentication mechanism requires tls")
			}
			return sasl.NewClientSCRAMSHA256PLUS(submitconf.Username, submitconf.Password, *cs), nil
		case "SCRAM-SHA-256":
			return sasl.NewClientSCRAMSHA256(submitconf.Username, submitconf.Password, false), nil
		case "SCRAM-SHA-1-PLUS":
			if cs == nil {
				return nil, fmt.Errorf("scram plus authentication mechanism requires tls")
			}
			return sasl.NewClientSCRAMSHA1PLUS(submitconf.Username, submitconf.Password, *cs), nil
		case "SCRAM-SHA-1":
			return sasl.NewClientSCRAMSHA1(submitconf.Username, submitconf.Password, false), nil
		case "CRAM-MD5":
			return sasl.NewClientCRAMMD5(submitconf.Username, submitconf.Password), nil
		case "PLAIN":
			return sasl.NewClientPlain(submitconf.Username, submitconf.Password), nil
		}

		// Try the defaults, from more to less secure.
		if cs != nil && slices.Contains(mechanisms, "SCRAM-SHA-256-PLUS") {
			return sasl.NewClientSCRAMSHA256PLUS(submitconf.Username, submitconf.Password, *cs), nil
		} else if slices.Contains(mechanisms, "SCRAM-SHA-256") {
			return sasl.NewClientSCRAMSHA256(submitconf.Username, submitconf.Password, true), nil
		} else if cs != nil && slices.Contains(mechanisms, "SCRAM-SHA-1-PLUS") {
			return sasl.NewClientSCRAMSHA1PLUS(submitconf.Username, submitconf.Password, *cs), nil
		} else if slices.Contains(mechanisms, "SCRAM-SHA-1") {
			return sasl.NewClientSCRAMSHA1(submitconf.Username, submitconf.Password, true), nil
		} else if slices.Contains(mechanisms, "CRAM-MD5") {
			return sasl.NewClientCRAMMD5(submitconf.Username, submitconf.Password), nil
		} else if slices.Contains(mechanisms, "PLAIN") {
			return sasl.NewClientPlain(submitconf.Username, submitconf.Password), nil
		}
		// No mutually supported mechanism.
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tlsMode := smtpclient.TLSSkip
	tlsPKIX := false
	if submitconf.TLS {
		tlsMode = smtpclient.TLSImmediate
		tlsPKIX = true
	} else if submitconf.STARTTLS {
		tlsMode = smtpclient.TLSRequiredStartTLS
		tlsPKIX = true
	} else if submitconf.RequireTLS == RequireTLSYes {
		xsavecheckf(errors.New("cannot submit with requiretls enabled without tls to submission server"), "checking tls configuration")
	}

	ourHostname, err := dns.ParseDomain(submitconf.LocalHostname)
	xsavecheckf(err, "parsing our local hostname")

	var remoteHostname dns.Domain
	if net.ParseIP(submitconf.Host) == nil {
		remoteHostname, err = dns.ParseDomain(submitconf.Host)
		xsavecheckf(err, "parsing remote hostname")
	}

	// todo: implement SRV and DANE, allowing for a simpler config file (just the email address & password)
	opts := smtpclient.Opts{
		Auth:    auth,
		RootCAs: mox.Conf.Static.TLS.CertPool,
	}
	client, err := smtpclient.New(ctx, c.log.Logger, conn, tlsMode, tlsPKIX, ourHostname, remoteHostname, opts)
	xsavecheckf(err, "open smtp session")

	err = client.Deliver(ctx, submitconf.From, recipient, int64(len(msg)), strings.NewReader(msg), true, false, submitconf.RequireTLS == RequireTLSYes)
	xsavecheckf(err, "submit message")

	if err := client.Close(); err != nil {
		log.Printf("closing smtp session after message was sent: %v", err)
	}
}
