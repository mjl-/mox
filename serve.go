package main

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/updates"
)

func monitorDNSBL(log *mlog.Log) {
	defer func() {
		// On error, don't bring down the entire server.
		x := recover()
		if x != nil {
			log.Error("monitordnsbl panic", mlog.Field("panic", x))
			debug.PrintStack()
			metrics.PanicInc("serve")
		}
	}()

	l, ok := mox.Conf.Static.Listeners["public"]
	if !ok {
		log.Info("no listener named public, not monitoring our ips at dnsbls")
		return
	}

	var zones []dns.Domain
	for _, zone := range l.SMTP.DNSBLs {
		d, err := dns.ParseDomain(zone)
		if err != nil {
			log.Fatalx("parsing dnsbls zone", err, mlog.Field("zone", zone))
		}
		zones = append(zones, d)
	}
	if len(zones) == 0 {
		return
	}

	type key struct {
		zone dns.Domain
		ip   string
	}
	metrics := map[key]prometheus.GaugeFunc{}
	var statusMutex sync.Mutex
	statuses := map[key]bool{}

	resolver := dns.StrictResolver{Pkg: "dnsblmonitor"}
	var sleep time.Duration // No sleep on first iteration.
	for {
		time.Sleep(sleep)
		sleep = 3 * time.Hour

		ips, err := mox.IPs(mox.Context)
		if err != nil {
			log.Errorx("listing ips for dnsbl monitor", err)
			continue
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() {
				continue
			}

			for _, zone := range zones {
				status, expl, err := dnsbl.Lookup(mox.Context, resolver, zone, ip)
				if err != nil {
					log.Errorx("dnsbl monitor lookup", err, mlog.Field("ip", ip), mlog.Field("zone", zone), mlog.Field("expl", expl), mlog.Field("status", status))
				}
				k := key{zone, ip.String()}

				statusMutex.Lock()
				statuses[k] = status == dnsbl.StatusPass
				statusMutex.Unlock()

				if _, ok := metrics[k]; !ok {
					metrics[k] = promauto.NewGaugeFunc(
						prometheus.GaugeOpts{
							Name: "mox_dnsbl_ips_success",
							Help: "DNSBL lookups to configured DNSBLs of our IPs.",
							ConstLabels: prometheus.Labels{
								"zone": zone.String(),
								"ip":   k.ip,
							},
						},
						func() float64 {
							statusMutex.Lock()
							defer statusMutex.Unlock()
							if statuses[k] {
								return 1
							}
							return 0
						},
					)
				}
				time.Sleep(time.Second)
			}
		}
	}
}

func cmdServe(c *cmd) {
	c.help = `Start mox, serving SMTP/IMAP/HTTPS.

Incoming email is accepted over SMTP. Email can be retrieved by users using
IMAP. HTTP listeners are started for the admin/account web interfaces, and for
automated TLS configuration. Missing essential TLS certificates are immediately
requested, other TLS certificates are requested on demand.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}
	mox.MustLoadConfig()

	mlog.Logfmt = true
	log := mlog.New("serve")

	if os.Getuid() == 0 {
		log.Fatal("refusing to run as root, please start mox as unprivileged user")
	}

	if fds := os.Getenv("MOX_RESTART_CTL_SOCKET"); fds != "" {
		log.Print("restarted")

		fd, err := strconv.ParseUint(fds, 10, 32)
		if err != nil {
			log.Fatalx("restart with invalid ctl socket", err, mlog.Field("fd", fds))
		}
		f := os.NewFile(uintptr(fd), "restartctl")
		if _, err := fmt.Fprint(f, "ok\n"); err != nil {
			log.Infox("writing ok to restart ctl socket", err)
		}
		err = f.Close()
		log.Check(err, "closing restart ctl socket")
	}
	log.Print("starting up", mlog.Field("version", moxvar.Version))

	shutdown := func() {
		// We indicate we are shutting down. Causes new connections and new SMTP commands
		// to be rejected. Should stop active connections pretty quickly.
		mox.ShutdownCancel()

		// Now we are going to wait for all connections to be gone, up to a timeout.
		done := mox.Connections.Done()
		second := time.Tick(time.Second)
		select {
		case <-done:
			log.Print("connections shutdown, waiting until 1 second passed")
			<-second

		case <-time.Tick(3 * time.Second):
			// We now cancel all pending operations, and set an immediate deadline on sockets.
			// Should get us a clean shutdown relatively quickly.
			mox.ContextCancel()
			mox.Connections.Shutdown()

			second := time.Tick(time.Second)
			select {
			case <-done:
				log.Print("no more connections, shutdown is clean, waiting until 1 second passed")
				<-second // Still wait for second, giving processes like imports a chance to clean up.
			case <-second:
				log.Print("shutting down with pending sockets")
			}
		}
		err := os.Remove(mox.DataDirPath("ctl"))
		log.Check(err, "removing ctl unix domain socket during shutdown")
	}

	if err := moxio.CheckUmask(); err != nil {
		log.Errorx("bad umask", err)
	}

	if mox.Conf.Static.CheckUpdates {
		checkUpdates := func() time.Duration {
			next := 24 * time.Hour
			current, lastknown, mtime, err := mox.LastKnown()
			if err != nil {
				log.Infox("determining own version before checking for updates, trying again in 24h", err)
				return next
			}

			// We don't want to check for updates at every startup. So we sleep based on file
			// mtime. But file won't exist initially.
			if !mtime.IsZero() && time.Since(mtime) < 24*time.Hour {
				d := 24*time.Hour - time.Since(mtime)
				log.Debug("sleeping for next check for updates", mlog.Field("sleep", d))
				time.Sleep(d)
				next = 0
			}
			now := time.Now()
			if err := os.Chtimes(mox.DataDirPath("lastknownversion"), now, now); err != nil {
				if !os.IsNotExist(err) {
					log.Infox("setting mtime on lastknownversion file, continuing", err)
				}
			}

			log.Debug("checking for updates", mlog.Field("lastknown", lastknown))
			updatesctx, updatescancel := context.WithTimeout(mox.Context, time.Minute)
			latest, _, changelog, err := updates.Check(updatesctx, dns.StrictResolver{}, dns.Domain{ASCII: changelogDomain}, lastknown, changelogURL, changelogPubKey)
			updatescancel()
			if err != nil {
				log.Infox("checking for updates", err, mlog.Field("latest", latest))
				return next
			}
			if !latest.After(lastknown) {
				log.Debug("no new version available")
				return next
			}
			if len(changelog.Changes) == 0 {
				log.Info("new version available, but changelog is empty, ignoring", mlog.Field("latest", latest))
				return next
			}

			var cl string
			for _, c := range changelog.Changes {
				cl += c.Text + "\n\n"
			}

			a, err := store.OpenAccount(mox.Conf.Static.Postmaster.Account)
			if err != nil {
				log.Infox("open account for postmaster changelog delivery", err)
				return next
			}
			defer func() {
				err := a.Close()
				log.Check(err, "closing account")
			}()
			f, err := store.CreateMessageTemp("changelog")
			if err != nil {
				log.Infox("making temporary message file for changelog delivery", err)
				return next
			}
			m := &store.Message{Received: time.Now(), Flags: store.Flags{Flagged: true}}
			n, err := fmt.Fprintf(f, "Date: %s\r\nSubject: mox update %s available, changelog\r\n\r\nHi!\r\n\r\nVersion %s of mox is available.\r\nThe changes compared to the previous update notification email:\r\n\r\n%s\r\n\r\nDon't forget to update, this install is at %s.\r\nPlease report any issues at https://github.com/mjl-/mox\r\n", time.Now().Format(message.RFC5322Z), latest, latest, strings.ReplaceAll(cl, "\n", "\r\n"), current)
			if err != nil {
				log.Infox("writing temporary message file for changelog delivery", err)
				return next
			}
			m.Size = int64(n)
			if err := a.DeliverMailbox(log, mox.Conf.Static.Postmaster.Mailbox, m, f, true); err != nil {
				log.Infox("changelog delivery", err)
				err := os.Remove(f.Name())
				log.Check(err, "removing temporary changelog message after delivery failure")
			}
			log.Info("delivered changelog", mlog.Field("current", current), mlog.Field("lastknown", lastknown), mlog.Field("latest", latest))
			if err := mox.StoreLastKnown(latest); err != nil {
				// This will be awkward, we'll keep notifying the postmaster once every 24h...
				log.Infox("updating last known version", err)
			}
			return next
		}

		go func() {
			for {
				next := checkUpdates()
				time.Sleep(next)
			}
		}()
	}

	// Initialize key and random buffer for creating opaque SMTP
	// transaction IDs based on "cid"s.
	recvidpath := mox.DataDirPath("receivedid.key")
	recvidbuf, err := os.ReadFile(recvidpath)
	if err != nil || len(recvidbuf) != 16+8 {
		recvidbuf = make([]byte, 16+8)
		if _, err := cryptorand.Read(recvidbuf); err != nil {
			log.Fatalx("reading random recvid data", err)
		}
		if err := os.WriteFile(recvidpath, recvidbuf, 0660); err != nil {
			log.Fatalx("writing recvidpath", err, mlog.Field("path", recvidpath))
		}
	}
	if err := mox.ReceivedIDInit(recvidbuf[:16], recvidbuf[16:]); err != nil {
		log.Fatalx("init receivedid", err)
	}

	// We start the network listeners first. If an instance is already running, we'll
	// get errors about address being in use. We listen to the unix domain socket
	// afterwards, which we always remove before listening. We need to do that because
	// we may not have cleaned up our control socket during unexpected shutdown. We
	// don't want to remove and listen on the unix domain socket first. If we would, we
	// would make the existing instance unreachable over its ctl socket, and then fail
	// because the network addresses are taken.
	mtastsdbRefresher := true
	if err := start(mtastsdbRefresher); err != nil {
		log.Fatalx("start", err)
	}

	go monitorDNSBL(log)

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
			go servectl(ctx, log.WithCid(cid), conn, shutdown)
		}
	}()

	// Remove old temporary files that somehow haven't been cleaned up.
	tmpdir := mox.DataDirPath("tmp")
	os.MkdirAll(tmpdir, 0770)
	tmps, err := os.ReadDir(tmpdir)
	if err != nil {
		log.Errorx("listing files in tmpdir", err)
	} else {
		now := time.Now()
		for _, e := range tmps {
			if fi, err := e.Info(); err != nil {
				log.Errorx("stat tmp file", err, mlog.Field("filename", e.Name()))
			} else if now.Sub(fi.ModTime()) > 7*24*time.Hour {
				p := filepath.Join(tmpdir, e.Name())
				if err := os.Remove(p); err != nil {
					log.Errorx("removing stale temporary file", err, mlog.Field("path", p))
				} else {
					log.Info("removed stale temporary file", mlog.Field("path", p))
				}
			}
		}
	}

	// Graceful shutdown.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	sig := <-sigc
	log.Print("shutting down, waiting max 3s for existing connections", mlog.Field("signal", sig))
	shutdown()
}
