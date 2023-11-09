package main

import (
	"fmt"
	"os"
	"time"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/http"
	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtpserver"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
	"github.com/mjl-/mox/tlsrptsend"
)

func shutdown(log *mlog.Log) {
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

// start initializes all packages, starts all listeners and the switchboard
// goroutine, then returns.
func start(mtastsdbRefresher, sendDMARCReports, sendTLSReports, skipForkExec bool) error {
	smtpserver.Listen()
	imapserver.Listen()
	http.Listen()

	if !skipForkExec {
		// If we were just launched as root, fork and exec as unprivileged user, handing
		// over the bound sockets to the new process. We'll get to this same code path
		// again, skipping this if block, continuing below with the actual serving.
		if os.Getuid() == 0 {
			mox.ForkExecUnprivileged()
			panic("cannot happen")
		} else {
			mox.CleanupPassedFiles()
		}
	}

	if err := mtastsdb.Init(mtastsdbRefresher); err != nil {
		return fmt.Errorf("mtasts init: %s", err)
	}

	if err := tlsrptdb.Init(); err != nil {
		return fmt.Errorf("tlsrpt init: %s", err)
	}

	done := make(chan struct{}, 1)
	if err := queue.Start(dns.StrictResolver{Pkg: "queue"}, done); err != nil {
		return fmt.Errorf("queue start: %s", err)
	}

	// dmarcdb starts after queue because it may start sending reports through the queue.
	if err := dmarcdb.Init(); err != nil {
		return fmt.Errorf("dmarc init: %s", err)
	}
	if sendDMARCReports {
		dmarcdb.Start(dns.StrictResolver{Pkg: "dmarcdb"})
	}

	if sendTLSReports {
		tlsrptsend.Start(dns.StrictResolver{Pkg: "tlsrptsend"})
	}

	store.StartAuthCache()
	smtpserver.Serve()
	imapserver.Serve()
	http.Serve()

	go func() {
		store.Switchboard()
		<-make(chan struct{})
	}()
	return nil
}
