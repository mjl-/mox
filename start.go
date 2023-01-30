package main

import (
	"fmt"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/http"
	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtpserver"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

// start initializes all packages, starts all listeners and the switchboard
// goroutine, then returns.
func start(mtastsdbRefresher bool) error {
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

	smtpserver.ListenAndServe()
	imapserver.ListenAndServe()
	http.ListenAndServe()
	go func() {
		<-store.Switchboard()
	}()
	return nil
}
