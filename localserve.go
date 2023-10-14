package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	golog "log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtpserver"
	"github.com/mjl-/mox/store"
)

func cmdLocalserve(c *cmd) {
	c.help = `Start a local SMTP/IMAP server that accepts all messages, useful when testing/developing software that sends email.

Localserve starts mox with a configuration suitable for local email-related
software development/testing. It listens for SMTP/Submission(s), IMAP(s) and
HTTP(s), on the regular port numbers + 1000.

Data is stored in the system user's configuration directory under
"mox-localserve", e.g. $HOME/.config/mox-localserve/ on linux, but can be
overridden with the -dir flag. If the directory does not yet exist, it is
automatically initialized with configuration files, an account with email
address mox@localhost and password moxmoxmox, and a newly generated self-signed
TLS certificate.

All incoming email to any address is accepted (if checks pass), unless the
recipient localpart ends with:

- "temperror": fail with a temporary error code
- "permerror": fail with a permanent error code
- [45][0-9][0-9]: fail with the specific error code
- "timeout": no response (for an hour)

If the localpart begins with "mailfrom" or "rcptto", the error is returned
during those commands instead of during "data".
`
	golog.SetFlags(0)

	userConfDir, _ := os.UserConfigDir()
	if userConfDir == "" {
		userConfDir = "."
	}

	var dir, ip string
	c.flag.StringVar(&dir, "dir", filepath.Join(userConfDir, "mox-localserve"), "configuration storage directory")
	c.flag.StringVar(&ip, "ip", "", "serve on this ip instead of default 127.0.0.1 and ::1. only used when writing configuration, at first launch.")
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	log := mlog.New("localserve")

	mox.FilesImmediate = true

	// Load config, creating a new one if needed.
	var existingConfig bool
	if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
		err := writeLocalConfig(log, dir, ip)
		if err != nil {
			log.Fatalx("creating mox localserve config", err, mlog.Field("dir", dir))
		}
	} else if err != nil {
		log.Fatalx("stat config dir", err, mlog.Field("dir", dir))
	} else if err := localLoadConfig(log, dir); err != nil {
		log.Fatalx("loading mox localserve config (hint: when creating a new config with -dir, the directory must not yet exist)", err, mlog.Field("dir", dir))
	} else if ip != "" {
		log.Fatal("can only use -ip when writing a new config file")
	} else {
		existingConfig = true
	}

	if level, ok := mlog.Levels[loglevel]; loglevel != "" && ok {
		mox.Conf.Log[""] = level
		mlog.SetConfig(mox.Conf.Log)
	} else if loglevel != "" && !ok {
		log.Fatal("unknown loglevel", mlog.Field("loglevel", loglevel))
	}

	// Initialize receivedid.
	recvidbuf, err := os.ReadFile(filepath.Join(dir, "receivedid.key"))
	if err == nil && len(recvidbuf) != 16+8 {
		err = fmt.Errorf("bad length %d, need 16+8", len(recvidbuf))
	}
	if err != nil {
		log.Errorx("reading receivedid.key", err)
		recvidbuf = make([]byte, 16+8)
		_, err := cryptorand.Read(recvidbuf)
		if err != nil {
			log.Fatalx("read random recvid key", err)
		}
	}
	if err := mox.ReceivedIDInit(recvidbuf[:16], recvidbuf[16:]); err != nil {
		log.Fatalx("init receivedid", err)
	}

	// Make smtp server accept all email and deliver to account "mox".
	smtpserver.Localserve = true
	// Tell queue it shouldn't be queuing/delivering.
	queue.Localserve = true

	const mtastsdbRefresher = false
	const skipForkExec = true
	if err := start(mtastsdbRefresher, skipForkExec); err != nil {
		log.Fatalx("starting mox", err)
	}
	golog.Printf("mox, version %s", moxvar.Version)
	golog.Print("")
	golog.Printf("the default user is mox@localhost, with password moxmoxmox")
	golog.Printf("the default admin password is moxadmin")
	golog.Printf("port numbers are those common for the services + 1000")
	golog.Printf("tls uses generated self-signed certificate %s", filepath.Join(dir, "localhost.crt"))
	golog.Printf("all incoming email to any address is accepted (if checks pass), unless the recipient localpart ends with:")
	golog.Print("")
	golog.Printf(`- "temperror": fail with a temporary error code.`)
	golog.Printf(`- "permerror": fail with a permanent error code.`)
	golog.Printf(`- [45][0-9][0-9]: fail with the specific error code.`)
	golog.Printf(`- "timeout": no response (for an hour).`)
	golog.Print("")
	golog.Printf(`if the localpart begins with "mailfrom" or "rcptto", the error is returned during those commands instead of during "data"`)
	golog.Print("")
	golog.Print(" smtp://localhost:1025                                    - receive email")
	golog.Print("smtps://mox%40localhost:moxmoxmox@localhost:1465          - send email")
	golog.Print(" smtp://mox%40localhost:moxmoxmox@localhost:1587          - send email (without tls)")
	golog.Print("imaps://mox%40localhost:moxmoxmox@localhost:1993          - read email")
	golog.Print(" imap://mox%40localhost:moxmoxmox@localhost:1143          - read email (without tls)")
	golog.Print("https://mox%40localhost:moxmoxmox@localhost:1443/account/ - account https")
	golog.Print(" http://mox%40localhost:moxmoxmox@localhost:1080/account/ - account http (without tls)")
	golog.Print("https://mox%40localhost:moxmoxmox@localhost:1443/webmail/ - webmail https")
	golog.Print(" http://mox%40localhost:moxmoxmox@localhost:1080/webmail/ - webmail http (without tls)")
	golog.Print("https://admin:moxadmin@localhost:1443/admin/              - admin https")
	golog.Print(" http://admin:moxadmin@localhost:1080/admin/              - admin http (without tls)")
	golog.Print("")
	if existingConfig {
		golog.Printf("serving from existing config dir %s/", dir)
		golog.Printf("if urls above don't work, consider resetting by removing config dir")
	} else {
		golog.Printf("serving from newly created config dir %s/", dir)
	}

	ctlpath := mox.DataDirPath("ctl")
	_ = os.Remove(ctlpath)
	ctl, err := net.Listen("unix", ctlpath)
	if err != nil {
		log.Fatalx("listen on ctl unix domain socket", err)
	}
	go func() {
		for {
			conn, err := ctl.Accept()
			if err != nil {
				log.Printx("accept for ctl", err)
				continue
			}
			cid := mox.Cid()
			ctx := context.WithValue(mox.Context, mlog.CidKey, cid)
			go servectl(ctx, log.WithCid(cid), conn, func() { shutdown(log) })
		}
	}()

	// Graceful shutdown.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	sig := <-sigc
	log.Print("shutting down, waiting max 3s for existing connections", mlog.Field("signal", sig))
	shutdown(log)
	if num, ok := sig.(syscall.Signal); ok {
		os.Exit(int(num))
	} else {
		os.Exit(1)
	}
}

func writeLocalConfig(log *mlog.Log, dir, ip string) (rerr error) {
	defer func() {
		x := recover()
		if x != nil {
			if err, ok := x.(error); ok {
				rerr = err
			}
		}
		if rerr != nil {
			err := os.RemoveAll(dir)
			log.Check(err, "removing config directory", mlog.Field("dir", dir))
		}
	}()

	xcheck := func(err error, msg string) {
		if err != nil {
			panic(fmt.Errorf("%s: %s", msg, err))
		}
	}

	os.MkdirAll(dir, 0770)

	// Generate key and self-signed certificate for use with TLS.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	xcheck(err, "generating ecdsa key for self-signed certificate")
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	xcheck(err, "marshal private key to pkcs8")
	privBlock := &pem.Block{
		Type: "PRIVATE KEY",
		Headers: map[string]string{
			"Note": "ECDSA key generated by mox localserve for self-signed certificate.",
		},
		Bytes: privKeyDER,
	}
	var privPEM bytes.Buffer
	err = pem.Encode(&privPEM, privBlock)
	xcheck(err, "pem-encoding private key")
	err = os.WriteFile(filepath.Join(dir, "localhost.key"), privPEM.Bytes(), 0660)
	xcheck(err, "writing private key for self-signed certificate")

	// Now the certificate.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()), // Required field.
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(4 * 365 * 24 * time.Hour),
		Issuer: pkix.Name{
			Organization: []string{"mox localserve"},
		},
		Subject: pkix.Name{
			Organization: []string{"mox localserve"},
			CommonName:   "localhost",
		},
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	xcheck(err, "making self-signed certificate")

	pubBlock := &pem.Block{
		Type: "CERTIFICATE",
		// Comments (header) would cause failure to parse the certificate when we load the config.
		Bytes: certDER,
	}
	var crtPEM bytes.Buffer
	err = pem.Encode(&crtPEM, pubBlock)
	xcheck(err, "pem-encoding self-signed certificate")
	err = os.WriteFile(filepath.Join(dir, "localhost.crt"), crtPEM.Bytes(), 0660)
	xcheck(err, "writing self-signed certificate")

	// Write adminpasswd.
	adminpw := "moxadmin"
	adminpwhash, err := bcrypt.GenerateFromPassword([]byte(adminpw), bcrypt.DefaultCost)
	xcheck(err, "generating hash for admin password")
	err = os.WriteFile(filepath.Join(dir, "adminpasswd"), adminpwhash, 0660)
	xcheck(err, "writing adminpasswd file")

	// Write mox.conf.
	ips := []string{"127.0.0.1", "::1"}
	if ip != "" {
		ips = []string{ip}
	}

	local := config.Listener{
		IPs: ips,
		TLS: &config.TLS{
			KeyCerts: []config.KeyCert{
				{
					CertFile: "localhost.crt",
					KeyFile:  "localhost.key",
				},
			},
		},
	}
	local.SMTP.Enabled = true
	local.SMTP.Port = 1025
	local.Submission.Enabled = true
	local.Submission.Port = 1587
	local.Submission.NoRequireSTARTTLS = true
	local.Submissions.Enabled = true
	local.Submissions.Port = 1465
	local.IMAP.Enabled = true
	local.IMAP.Port = 1143
	local.IMAP.NoRequireSTARTTLS = true
	local.IMAPS.Enabled = true
	local.IMAPS.Port = 1993
	local.AccountHTTP.Enabled = true
	local.AccountHTTP.Port = 1080
	local.AccountHTTP.Path = "/account/"
	local.AccountHTTPS.Enabled = true
	local.AccountHTTPS.Port = 1443
	local.AccountHTTPS.Path = "/account/"
	local.WebmailHTTP.Enabled = true
	local.WebmailHTTP.Port = 1080
	local.WebmailHTTP.Path = "/webmail/"
	local.WebmailHTTPS.Enabled = true
	local.WebmailHTTPS.Port = 1443
	local.WebmailHTTPS.Path = "/webmail/"
	local.AdminHTTP.Enabled = true
	local.AdminHTTP.Port = 1080
	local.AdminHTTPS.Enabled = true
	local.AdminHTTPS.Port = 1443
	local.MetricsHTTP.Enabled = true
	local.MetricsHTTP.Port = 1081
	local.WebserverHTTP.Enabled = true
	local.WebserverHTTP.Port = 1080
	local.WebserverHTTPS.Enabled = true
	local.WebserverHTTPS.Port = 1443

	uid := os.Getuid()
	if uid < 0 {
		uid = 1 // For windows.
	}
	static := config.Static{
		DataDir:           ".",
		LogLevel:          "traceauth",
		Hostname:          "localhost",
		User:              fmt.Sprintf("%d", uid),
		AdminPasswordFile: "adminpasswd",
		Pedantic:          true,
		Listeners: map[string]config.Listener{
			"local": local,
		},
	}
	tlsca := struct {
		AdditionalToSystem bool     `sconf:"optional"`
		CertFiles          []string `sconf:"optional"`
	}{true, []string{"localhost.crt"}}
	static.TLS.CA = &tlsca
	static.Postmaster.Account = "mox"
	static.Postmaster.Mailbox = "Inbox"

	var moxconfBuf bytes.Buffer
	err = sconf.WriteDocs(&moxconfBuf, static)
	xcheck(err, "making mox.conf")

	err = os.WriteFile(filepath.Join(dir, "mox.conf"), moxconfBuf.Bytes(), 0660)
	xcheck(err, "writing mox.conf")

	// Write domains.conf.
	acc := config.Account{
		RejectsMailbox: "Rejects",
		Destinations: map[string]config.Destination{
			"mox@localhost": {},
		},
	}
	acc.AutomaticJunkFlags.Enabled = true
	acc.AutomaticJunkFlags.JunkMailboxRegexp = "^(junk|spam)"
	acc.AutomaticJunkFlags.NeutralMailboxRegexp = "^(inbox|neutral|postmaster|dmarc|tlsrpt|rejects)"
	acc.JunkFilter = &config.JunkFilter{
		Threshold: 0.95,
		Params: junk.Params{
			Onegrams:    true,
			MaxPower:    .01,
			TopWords:    10,
			IgnoreWords: .1,
			RareWords:   2,
		},
	}

	dynamic := config.Dynamic{
		Domains: map[string]config.Domain{
			"localhost": {
				LocalpartCatchallSeparator: "+",
			},
		},
		Accounts: map[string]config.Account{
			"mox": acc,
		},
		WebHandlers: []config.WebHandler{
			{
				LogName:               "workdir",
				Domain:                "localhost",
				PathRegexp:            "^/workdir/",
				DontRedirectPlainHTTP: true,
				WebStatic: &config.WebStatic{
					StripPrefix: "/workdir/",
					Root:        ".",
					ListFiles:   true,
				},
			},
		},
	}
	var domainsconfBuf bytes.Buffer
	err = sconf.WriteDocs(&domainsconfBuf, dynamic)
	xcheck(err, "making domains.conf")

	err = os.WriteFile(filepath.Join(dir, "domains.conf"), domainsconfBuf.Bytes(), 0660)
	xcheck(err, "writing domains.conf")

	// Write receivedid.key.
	recvidbuf := make([]byte, 16+8)
	_, err = cryptorand.Read(recvidbuf)
	xcheck(err, "reading random recvid data")
	err = os.WriteFile(filepath.Join(dir, "receivedid.key"), recvidbuf, 0660)
	xcheck(err, "writing receivedid.key")

	// Load config, so we can access the account.
	err = localLoadConfig(log, dir)
	xcheck(err, "loading config")

	// Set password on account.
	a, _, err := store.OpenEmail("mox@localhost")
	xcheck(err, "opening account to set password")
	password := "moxmoxmox"
	err = a.SetPassword(password)
	xcheck(err, "setting password")
	err = a.Close()
	xcheck(err, "closing account")

	golog.Printf("config created in %s", dir)
	return nil
}

func localLoadConfig(log *mlog.Log, dir string) error {
	mox.ConfigStaticPath = filepath.Join(dir, "mox.conf")
	mox.ConfigDynamicPath = filepath.Join(dir, "domains.conf")
	errs := mox.LoadConfig(context.Background(), true, false)
	if len(errs) > 1 {
		log.Error("loading config generated config file: multiple errors")
		for _, err := range errs {
			log.Errorx("config error", err)
		}
		return fmt.Errorf("stopping after multiple config errors")
	} else if len(errs) == 1 {
		return fmt.Errorf("loading config file: %v", errs[0])
	}
	return nil
}
