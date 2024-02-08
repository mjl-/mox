//go:build !windows

package main

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
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
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/updates"
)

func monitorDNSBL(log mlog.Log) {
	defer func() {
		// On error, don't bring down the entire server.
		x := recover()
		if x != nil {
			log.Error("monitordnsbl panic", slog.Any("panic", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Serve)
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
			log.Fatalx("parsing dnsbls zone", err, slog.Any("zone", zone))
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

		ips, err := mox.IPs(mox.Context, false)
		if err != nil {
			log.Errorx("listing ips for dnsbl monitor", err)
			continue
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() {
				continue
			}

			for _, zone := range zones {
				status, expl, err := dnsbl.Lookup(mox.Context, log.Logger, resolver, zone, ip)
				if err != nil {
					log.Errorx("dnsbl monitor lookup", err,
						slog.Any("ip", ip),
						slog.Any("zone", zone),
						slog.String("expl", expl),
						slog.Any("status", status))
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
								"zone": zone.LogString(),
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

// also see localserve.go, code is similar or even shared.
func cmdServe(c *cmd) {
	c.help = `Start mox, serving SMTP/IMAP/HTTPS.

Incoming email is accepted over SMTP. Email can be retrieved by users using
IMAP. HTTP listeners are started for the admin/account web interfaces, and for
automated TLS configuration. Missing essential TLS certificates are immediately
requested, other TLS certificates are requested on demand.

Only implemented on unix systems, not Windows.
`
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	// Set debug logging until config is fully loaded.
	mlog.Logfmt = true
	mox.Conf.Log[""] = mlog.LevelDebug
	mlog.SetConfig(mox.Conf.Log)

	checkACMEHosts := os.Getuid() != 0

	log := c.log

	if os.Getuid() == 0 {
		mox.MustLoadConfig(true, checkACMEHosts)

		// No need to potentially start and keep multiple processes. As root, we just need
		// to start the child process.
		runtime.GOMAXPROCS(1)

		moxconf, err := filepath.Abs(mox.ConfigStaticPath)
		log.Check(err, "finding absolute mox.conf path")
		domainsconf, err := filepath.Abs(mox.ConfigDynamicPath)
		log.Check(err, "finding absolute domains.conf path")

		log.Print("starting as root, initializing network listeners",
			slog.String("version", moxvar.Version),
			slog.Any("pid", os.Getpid()),
			slog.String("moxconf", moxconf),
			slog.String("domainsconf", domainsconf))
		if os.Getenv("MOX_SOCKETS") != "" {
			log.Fatal("refusing to start as root with $MOX_SOCKETS set")
		}
		if os.Getenv("MOX_FILES") != "" {
			log.Fatal("refusing to start as root with $MOX_FILES set")
		}

		if !mox.Conf.Static.NoFixPermissions {
			// Fix permissions now that we have privilege to do so. Useful for update of v0.0.1
			// that was running directly as mox-user.
			workdir, err := os.Getwd()
			if err != nil {
				log.Printx("get working dir, continuing without potentially fixing up permissions", err)
			} else {
				configdir := filepath.Dir(mox.ConfigStaticPath)
				datadir := mox.DataDirPath(".")
				err := fixperms(log, workdir, configdir, datadir, mox.Conf.Static.UID, mox.Conf.Static.GID)
				if err != nil {
					log.Fatalx("fixing permissions", err)
				}
			}
		}
	} else {
		mox.RestorePassedFiles()
		mox.MustLoadConfig(true, checkACMEHosts)
		log.Print("starting as unprivileged user",
			slog.String("user", mox.Conf.Static.User),
			slog.Any("uid", mox.Conf.Static.UID),
			slog.Any("gid", mox.Conf.Static.GID),
			slog.Any("pid", os.Getpid()))
	}

	syscall.Umask(syscall.Umask(007) | 007)

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
			log.Fatalx("writing recvidpath", err, slog.String("path", recvidpath))
		}
		err := os.Chown(recvidpath, int(mox.Conf.Static.UID), 0)
		log.Check(err, "chown receveidid.key",
			slog.String("path", recvidpath),
			slog.Any("uid", mox.Conf.Static.UID),
			slog.Any("gid", 0))
		err = os.Chmod(recvidpath, 0640)
		log.Check(err, "chmod receveidid.key to 0640", slog.String("path", recvidpath))
	}
	if err := mox.ReceivedIDInit(recvidbuf[:16], recvidbuf[16:]); err != nil {
		log.Fatalx("init receivedid", err)
	}

	// Start mox. If running as root, this will bind/listen on network sockets, and
	// fork and exec itself as unprivileged user, then waits for the child to stop and
	// exit. When running as root, this function never returns. But the new
	// unprivileged user will get here again, with network sockets prepared.
	//
	// We listen to the unix domain ctl socket afterwards, which we always remove
	// before listening. We need to do that because we may not have cleaned up our
	// control socket during unexpected shutdown. We don't want to remove and listen on
	// the unix domain socket first. If we would, we would make the existing instance
	// unreachable over its ctl socket, and then fail because the network addresses are
	// taken.
	const mtastsdbRefresher = true
	const skipForkExec = false
	if err := start(mtastsdbRefresher, !mox.Conf.Static.NoOutgoingDMARCReports, !mox.Conf.Static.NoOutgoingTLSReports, skipForkExec); err != nil {
		log.Fatalx("start", err)
	}
	log.Print("ready to serve")

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
				log.Debug("sleeping for next check for updates", slog.Duration("sleep", d))
				time.Sleep(d)
				next = 0
			}
			now := time.Now()
			if err := os.Chtimes(mox.DataDirPath("lastknownversion"), now, now); err != nil {
				if !os.IsNotExist(err) {
					log.Infox("setting mtime on lastknownversion file, continuing", err)
				}
			}

			log.Debug("checking for updates", slog.Any("lastknown", lastknown))
			updatesctx, updatescancel := context.WithTimeout(mox.Context, time.Minute)
			latest, _, changelog, err := updates.Check(updatesctx, log.Logger, dns.StrictResolver{Log: log.Logger}, dns.Domain{ASCII: changelogDomain}, lastknown, changelogURL, changelogPubKey)
			updatescancel()
			if err != nil {
				log.Infox("checking for updates", err, slog.Any("latest", latest))
				return next
			}
			if !latest.After(lastknown) {
				log.Debug("no new version available")
				return next
			}
			if len(changelog.Changes) == 0 {
				log.Info("new version available, but changelog is empty, ignoring", slog.Any("latest", latest))
				return next
			}

			var cl string
			for _, c := range changelog.Changes {
				cl += "----\n\n" + strings.TrimSpace(c.Text) + "\n\n"
			}
			cl += "----"

			a, err := store.OpenAccount(log, mox.Conf.Static.Postmaster.Account)
			if err != nil {
				log.Infox("open account for postmaster changelog delivery", err)
				return next
			}
			defer func() {
				err := a.Close()
				log.Check(err, "closing account")
			}()
			f, err := store.CreateMessageTemp(log, "changelog")
			if err != nil {
				log.Infox("making temporary message file for changelog delivery", err)
				return next
			}
			defer store.CloseRemoveTempFile(log, f, "message for changelog delivery")

			m := &store.Message{
				Received: time.Now(),
				Flags:    store.Flags{Flagged: true},
			}
			n, err := fmt.Fprintf(f, "Date: %s\r\nSubject: mox %s available\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8-bit\r\n\r\nHi!\r\n\r\nVersion %s of mox is available, this install is at %s.\r\n\r\nChanges:\r\n\r\n%s\r\n\r\nRemember to make a backup with \"mox backup\" before upgrading.\r\nPlease report any issues at https://github.com/mjl-/mox, thanks!\r\n\r\nCheers,\r\nmox\r\n", time.Now().Format(message.RFC5322Z), latest, latest, current, strings.ReplaceAll(cl, "\n", "\r\n"))
			if err != nil {
				log.Infox("writing temporary message file for changelog delivery", err)
				return next
			}
			m.Size = int64(n)
			if err := a.DeliverMailbox(log, mox.Conf.Static.Postmaster.Mailbox, m, f); err != nil {
				log.Errorx("changelog delivery", err)
				return next
			}
			log.Info("delivered changelog",
				slog.Any("current", current),
				slog.Any("lastknown", lastknown),
				slog.Any("latest", latest))
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
			go servectl(ctx, log.WithCid(cid), conn, func() { shutdown(log) })
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
				log.Errorx("stat tmp file", err, slog.String("filename", e.Name()))
			} else if now.Sub(fi.ModTime()) > 7*24*time.Hour && !fi.IsDir() {
				p := filepath.Join(tmpdir, e.Name())
				if err := os.Remove(p); err != nil {
					log.Errorx("removing stale temporary file", err, slog.String("path", p))
				} else {
					log.Info("removed stale temporary file", slog.String("path", p))
				}
			}
		}
	}

	// Graceful shutdown.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	sig := <-sigc
	log.Print("shutting down, waiting max 3s for existing connections", slog.Any("signal", sig))
	shutdown(log)
	if num, ok := sig.(syscall.Signal); ok {
		os.Exit(int(num))
	} else {
		os.Exit(1)
	}
}

// Set correct permissions for mox working directory, binary, config and data and service file.
//
// We require being able to stat the basic non-optional paths. Then we'll try to
// fix up permissions. If an error occurs when fixing permissions, we log and
// continue (could not be an actual problem).
func fixperms(log mlog.Log, workdir, configdir, datadir string, moxuid, moxgid uint32) (rerr error) {
	type fserr struct{ Err error }
	defer func() {
		x := recover()
		if x == nil {
			return
		}
		e, ok := x.(fserr)
		if ok {
			rerr = e.Err
		} else {
			panic(x)
		}
	}()

	checkf := func(err error, format string, args ...any) {
		if err != nil {
			panic(fserr{fmt.Errorf(format, args...)})
		}
	}

	// Changes we have to make. We collect them first, then apply.
	type change struct {
		path           string
		uid, gid       *uint32
		olduid, oldgid uint32
		mode           *fs.FileMode
		oldmode        fs.FileMode
	}
	var changes []change

	ensure := func(p string, uid, gid uint32, perm fs.FileMode) bool {
		fi, err := os.Stat(p)
		checkf(err, "stat %s", p)

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			checkf(fmt.Errorf("got %T", st), "stat sys, expected syscall.Stat_t")
		}

		var ch change
		if st.Uid != uid || st.Gid != gid {
			ch.uid = &uid
			ch.gid = &gid
			ch.olduid = st.Uid
			ch.oldgid = st.Gid
		}
		if perm != fi.Mode()&(fs.ModeSetgid|0777) {
			ch.mode = &perm
			ch.oldmode = fi.Mode() & (fs.ModeSetgid | 0777)
		}
		var zerochange change
		if ch == zerochange {
			return false
		}
		ch.path = p
		changes = append(changes, ch)
		return true
	}

	xexists := func(p string) bool {
		_, err := os.Stat(p)
		if err != nil && !os.IsNotExist(err) {
			checkf(err, "stat %s", p)
		}
		return err == nil
	}

	// We ensure these permissions:
	//
	//	$workdir root:mox 0751
	//	$configdir mox:root 0750 + setgid, and recursively (but files 0640)
	//	$datadir mox:root 0750 + setgid, and recursively (but files 0640)
	//	$workdir/mox (binary, optional) root:mox 0750
	//	$workdir/mox.service (systemd service file, optional) root:root 0644

	const root = 0
	ensure(workdir, root, moxgid, 0751)
	fixconfig := ensure(configdir, moxuid, 0, fs.ModeSetgid|0750)
	fixdata := ensure(datadir, moxuid, 0, fs.ModeSetgid|0750)

	// Binary and systemd service file do not exist (there) when running under docker.
	binary := filepath.Join(workdir, "mox")
	if xexists(binary) {
		ensure(binary, root, moxgid, 0750)
	}
	svc := filepath.Join(workdir, "mox.service")
	if xexists(svc) {
		ensure(svc, root, root, 0644)
	}

	if len(changes) == 0 {
		return
	}

	// Apply changes.
	log.Print("fixing up permissions, will continue on errors")
	for _, ch := range changes {
		if ch.uid != nil {
			err := os.Chown(ch.path, int(*ch.uid), int(*ch.gid))
			log.Printx("chown, fixing uid/gid", err,
				slog.String("path", ch.path),
				slog.Any("olduid", ch.olduid),
				slog.Any("oldgid", ch.oldgid),
				slog.Any("newuid", *ch.uid),
				slog.Any("newgid", *ch.gid))
		}
		if ch.mode != nil {
			err := os.Chmod(ch.path, *ch.mode)
			log.Printx("chmod, fixing permissions", err,
				slog.String("path", ch.path),
				slog.Any("oldmode", fmt.Sprintf("%03o", ch.oldmode)),
				slog.Any("newmode", fmt.Sprintf("%03o", *ch.mode)))
		}
	}

	walkchange := func(dir string) {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Printx("walk error, continuing", err, slog.String("path", path))
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				log.Printx("stat during walk, continuing", err, slog.String("path", path))
				return nil
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				log.Printx("syscall stat during walk, continuing", err, slog.String("path", path))
				return nil
			}
			if st.Uid != moxuid || st.Gid != root {
				err := os.Chown(path, int(moxuid), root)
				log.Printx("walk chown, fixing uid/gid", err,
					slog.String("path", path),
					slog.Any("olduid", st.Uid),
					slog.Any("oldgid", st.Gid),
					slog.Any("newuid", moxuid),
					slog.Any("newgid", root))
			}
			omode := fi.Mode() & (fs.ModeSetgid | 0777)
			var nmode fs.FileMode
			if fi.IsDir() {
				nmode = fs.ModeSetgid | 0750
			} else {
				nmode = 0640
			}
			if omode != nmode {
				err := os.Chmod(path, nmode)
				log.Printx("walk chmod, fixing permissions", err,
					slog.String("path", path),
					slog.Any("oldmode", fmt.Sprintf("%03o", omode)),
					slog.Any("newmode", fmt.Sprintf("%03o", nmode)))
			}
			return nil
		})
		log.Check(err, "walking dir to fix permissions", slog.String("dir", dir))
	}

	// If config or data dir needed fixing, also set uid/gid and mode and files/dirs
	// inside, recursively. We don't always recurse, data probably contains many files.
	if fixconfig {
		log.Print("fixing permissions in config dir", slog.String("configdir", configdir))
		walkchange(configdir)
	}
	if fixdata {
		log.Print("fixing permissions in data dir", slog.String("configdir", configdir))
		walkchange(datadir)
	}
	return nil
}
