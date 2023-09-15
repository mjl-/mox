package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var metricPanic = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mox_panic_total",
		Help: "Number of unhandled panics, by package.",
	},
	[]string{
		"pkg",
	},
)

type Panic string

const (
	Ctl              Panic = "ctl"
	Import           Panic = "import"
	Serve            Panic = "serve"
	Imapserver       Panic = "imapserver"
	Mtastsdb         Panic = "mtastsdb"
	Queue            Panic = "queue"
	Smtpclient       Panic = "smtpclient"
	Smtpserver       Panic = "smtpserver"
	Dkimverify       Panic = "dkimverify"
	Spfverify        Panic = "spfverify"
	Upgradethreads   Panic = "upgradethreads"
	Importmanage     Panic = "importmanage"
	Importmessages   Panic = "importmessages"
	Webadmin         Panic = "webadmin"
	Webmailsendevent Panic = "webmailsendevent"
	Webmail          Panic = "webmail"
	Webmailrequest   Panic = "webmailrequest"
	Webmailquery     Panic = "webmailquery"
	Webmailhandle    Panic = "webmailhandle"
)

func init() {
	// Ensure the panic counts are initialized to 0, so the query for change also picks
	// up the first panic.
	names := []Panic{
		Ctl,
		Import,
		Serve,
		Imapserver,
		Mtastsdb,
		Queue,
		Smtpclient,
		Smtpserver,
		Dkimverify,
		Spfverify,
		Upgradethreads,
		Importmanage,
		Importmessages,
		Webadmin,
		Webmailsendevent,
		Webmail,
		Webmailrequest,
		Webmailquery,
		Webmailhandle,
	}
	for _, name := range names {
		metricPanic.WithLabelValues(string(name)).Add(0)
	}
}

func PanicInc(name Panic) {
	metricPanic.WithLabelValues(string(name)).Inc()
}
