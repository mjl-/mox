package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/mjl-/sconf"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/webhook"
)

func cmdExample(c *cmd) {
	c.params = "[name]"
	c.help = `List available examples, or print a specific example.`

	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	var match func() string
	for _, ex := range examples {
		if len(args) == 0 {
			fmt.Println(ex.Name)
		} else if args[0] == ex.Name {
			match = ex.Get
		}
	}
	if len(args) == 0 {
		return
	}
	if match == nil {
		log.Fatalln("not found")
	}
	fmt.Print(match())
}

func cmdConfigExample(c *cmd) {
	c.params = "[name]"
	c.help = `List available config examples, or print a specific example.`

	args := c.Parse()
	if len(args) > 1 {
		c.Usage()
	}

	var match func() string
	for _, ex := range configExamples {
		if len(args) == 0 {
			fmt.Println(ex.Name)
		} else if args[0] == ex.Name {
			match = ex.Get
		}
	}
	if len(args) == 0 {
		return
	}
	if match == nil {
		log.Fatalln("not found")
	}
	fmt.Print(match())
}

var configExamples = []struct {
	Name string
	Get  func() string
}{
	{
		"webhandlers",
		func() string {
			const webhandlers = `# Snippet of domains.conf to configure WebDomainRedirects and WebHandlers.

# Redirect all requests for mox.example to https://www.mox.example.
WebDomainRedirects:
	mox.example: www.mox.example

# Each request is matched against these handlers until one matches and serves it.
WebHandlers:
	-
		# Redirect all plain http requests to https, leaving path, query strings, etc
		# intact. When the request is already to https, the destination URL would have the
		# same scheme, host and path, causing this redirect handler to not match the
		# request (and not cause a redirect loop) and the webserver to serve the request
		# with a later handler.
		LogName: redirhttps
		Domain: www.mox.example
		PathRegexp: ^/
		# Could leave DontRedirectPlainHTTP at false if it wasn't for this being an
		# example for doing this redirect.
		DontRedirectPlainHTTP: true
		WebRedirect:
			BaseURL: https://www.mox.example
	-
		# The name of the handler, used in logging and metrics.
		LogName: staticmjl
		# With ACME configured, each configured domain will automatically get a TLS
		# certificate on first request.
		Domain: www.mox.example
		PathRegexp: ^/who/mjl/
		WebStatic:
			StripPrefix: /who/mjl
			# Requested path /who/mjl/inferno/ resolves to local web/mjl/inferno.
			# If a directory contains an index.html, it is served when a directory is requested.
			Root: web/mjl
			# With ListFiles true, if a directory does not contain an index.html, the contents are listed.
			ListFiles: true
			ResponseHeaders:
				X-Mox: hi
	-
		LogName: redir
		Domain: www.mox.example
		PathRegexp: ^/redir/a/b/c
		# Don't redirect from plain HTTP to HTTPS.
		DontRedirectPlainHTTP: true
		WebRedirect:
			# Just change the domain and add query string set fragment. No change to scheme.
			# Path will start with /redir/a/b/c (and whathever came after) because no
			# OrigPathRegexp+ReplacePath is set.
			BaseURL: //moxest.example?q=1#frag
			# Default redirection is 308 - Permanent Redirect.
			StatusCode: 307
	-
		LogName: oldnew
		Domain: www.mox.example
		PathRegexp: ^/old/
		WebRedirect:
			# Replace path, leaving rest of URL intact.
			OrigPathRegexp: ^/old/(.*)
			ReplacePath: /new/$1
	-
		LogName: app
		Domain: www.mox.example
		PathRegexp: ^/app/
		WebForward:
			# Strip the path matched by PathRegexp before forwarding the request. So original
			# request /app/api become just /api.
			StripPath: true
			# URL of backend, where requests are forwarded to. The path in the URL is kept,
			# so for incoming request URL /app/api, the outgoing request URL has path /app-v2/api.
			# Requests are made with Go's net/http DefaultTransporter, including using
			# HTTP_PROXY and HTTPS_PROXY environment variables.
			URL: http://127.0.0.1:8900/app-v2/
			# Add headers to response.
			ResponseHeaders:
				X-Frame-Options: deny
				X-Content-Type-Options: nosniff
`
			// Parse just so we know we have the syntax right.
			// todo: ideally we would have a complete config file and parse it fully.
			var conf struct {
				WebDomainRedirects map[string]string
				WebHandlers        []config.WebHandler
			}
			err := sconf.Parse(strings.NewReader(webhandlers), &conf)
			xcheckf(err, "parsing webhandlers example")
			return webhandlers
		},
	},
	{
		"transport",
		func() string {
			const moxconf = `# Snippet for mox.conf, defining a transport called Example that connects on the
# SMTP submission with TLS port 465 ("submissions"), authenticating with
# SCRAM-SHA-256-PLUS (other providers may not support SCRAM-SHA-256-PLUS, but they
# typically do support the older CRAM-MD5).:

# Transport are mechanisms for delivering messages. Transports can be referenced
# from Routes in accounts, domains and the global configuration. There is always
# an implicit/fallback delivery transport doing direct delivery with SMTP from the
# outgoing message queue. Transports are typically only configured when using
# smarthosts, i.e. when delivering through another SMTP server. Zero or one
# transport methods must be set in a transport, never multiple. When using an
# external party to send email for a domain, keep in mind you may have to add
# their IP address to your domain's SPF record, and possibly additional DKIM
# records. (optional)
Transports:
	Example:
		# Submission SMTP over a TLS connection to submit email to a remote queue.
		# (optional)
		Submissions:
			# Host name to connect to and for verifying its TLS certificate.
			Host: smtp.example.com

			# If set, authentication credentials for the remote server. (optional)
			Auth:
				Username: user@example.com
				Password: test1234
				Mechanisms:
					# Allowed authentication mechanisms. Defaults to SCRAM-SHA-256-PLUS,
					# SCRAM-SHA-256, SCRAM-SHA-1-PLUS, SCRAM-SHA-1, CRAM-MD5. Not included by default:
					# PLAIN. Specify the strongest mechanism known to be implemented by the server to
					# prevent mechanism downgrade attacks. (optional)

					- SCRAM-SHA-256-PLUS
`

			const domainsconf = `# Snippet for domains.conf, specifying a route that sends through the transport:

# Routes for delivering outgoing messages through the queue. Each delivery attempt
# evaluates account routes, domain routes and finally these global routes. The
# transport of the first matching route is used in the delivery attempt. If no
# routes match, which is the default with no configured routes, messages are
# delivered directly from the queue. (optional)
Routes:
	-
		Transport: Example
`

			var static struct {
				Transports map[string]config.Transport
			}
			var dynamic struct {
				Routes []config.Route
			}
			err := sconf.Parse(strings.NewReader(moxconf), &static)
			xcheckf(err, "parsing moxconf example")
			err = sconf.Parse(strings.NewReader(domainsconf), &dynamic)
			xcheckf(err, "parsing domainsconf example")
			return moxconf + "\n\n" + domainsconf
		},
	},
}

var exampleTime = time.Date(2024, time.March, 27, 0, 0, 0, 0, time.UTC)

var examples = []struct {
	Name string
	Get  func() string
}{
	{
		"webhook-outgoing-delivered",
		func() string {
			v := webhook.Outgoing{
				Version:       0,
				Event:         webhook.EventDelivered,
				QueueMsgID:    101,
				FromID:        base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
				MessageID:     "<QnxzgulZK51utga6agH_rg@mox.example>",
				Subject:       "subject of original message",
				WebhookQueued: exampleTime,
				Extra:         map[string]string{},
				SMTPCode:      smtp.C250Completed,
			}
			return "Example webhook HTTP POST JSON body for successful outgoing delivery:\n\n\t" + formatJSON(v)
		},
	},
	{
		"webhook-outgoing-dsn-failed",
		func() string {
			v := webhook.Outgoing{
				Version:          0,
				Event:            webhook.EventFailed,
				DSN:              true,
				Suppressing:      true,
				QueueMsgID:       102,
				FromID:           base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
				MessageID:        "<QnxzgulZK51utga6agH_rg@mox.example>",
				Subject:          "subject of original message",
				WebhookQueued:    exampleTime,
				Extra:            map[string]string{"userid": "456"},
				Error:            "timeout connecting to host",
				SMTPCode:         smtp.C554TransactionFailed,
				SMTPEnhancedCode: "5." + smtp.SeNet4Other0,
			}
			return `Example webhook HTTP POST JSON body for failed delivery based on incoming DSN
message, with custom extra data fields (from original submission), and adding address to the suppression list:

	` + formatJSON(v)
		},
	},
	{
		"webhook-incoming-basic",
		func() string {
			v := webhook.Incoming{
				Version:   0,
				From:      []webhook.NameAddress{{Address: "mox@localhost"}},
				To:        []webhook.NameAddress{{Address: "mjl@localhost"}},
				Subject:   "hi",
				MessageID: "<QnxzgulZK51utga6agH_rg@mox.example>",
				Date:      &exampleTime,
				Text:      "hello world ☺\n",
				Structure: webhook.Structure{
					ContentType:       "text/plain",
					ContentTypeParams: map[string]string{"charset": "utf-8"},
					DecodedSize:       int64(len("hello world ☺\r\n")),
					Parts:             []webhook.Structure{},
				},
				Meta: webhook.IncomingMeta{
					MsgID:               201,
					MailFrom:            "mox@localhost",
					MailFromValidated:   false,
					MsgFromValidated:    true,
					RcptTo:              "mjl@localhost",
					DKIMVerifiedDomains: []string{"localhost"},
					RemoteIP:            "127.0.0.1",
					Received:            exampleTime.Add(3 * time.Second),
					MailboxName:         "Inbox",
					Automated:           false,
				},
			}
			return "Example JSON body for webhooks for incoming delivery of basic message:\n\n\t" + formatJSON(v)
		},
	},
}

func formatJSON(v any) string {
	nv, _ := mox.FillNil(reflect.ValueOf(v))
	v = nv.Interface()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("\t", "\t")
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	xcheckf(err, "encoding to json")
	return b.String()
}
