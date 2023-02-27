package main

import (
	"fmt"
	"os"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/http"
	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtpserver"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

// start initializes all packages, starts all listeners and the switchboard
// goroutine, then returns.
func start(mtastsdbRefresher, skipForkExec bool) error {
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
			mox.CleanupPassedSockets()
		}
	}

	if err := dmarcdb.Init(); err != nil {
		return fmt.Errorf("dmarc init: %s", err)
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

	store.StartAuthCache()
	smtpserver.Serve()
	imapserver.Serve()
	http.Serve()

	go func() {
		<-store.Switchboard()
	}()
	return nil
}
