package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/updates"
)

func cmdUpdatesAddSigned(c *cmd) {
	c.unlisted = true
	c.params = "privkey-file changes-file < message"
	c.help = "Add a signed change to the changes file."
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}

	f, err := os.Open(args[0])
	xcheckf(err, "open private key file")
	defer func() {
		err := f.Close()
		c.log.Check(err, "closing private key file")
	}()
	seed, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, f))
	xcheckf(err, "read private key file")
	if len(seed) != ed25519.SeedSize {
		log.Fatalf("private key is %d bytes, must be %d", len(seed), ed25519.SeedSize)
	}

	vf, err := os.Open(args[1])
	xcheckf(err, "open changes file")
	var changelog updates.Changelog
	err = json.NewDecoder(vf).Decode(&changelog)
	xcheckf(err, "parsing changes file")

	privKey := ed25519.NewKeyFromSeed(seed)

	fmt.Fprintln(os.Stderr, "reading changelog text from stdin")
	buf, err := io.ReadAll(os.Stdin)
	xcheckf(err, "parse message")

	if len(buf) == 0 {
		log.Fatalf("empty message")
	}
	// Message starts with headers similar to email, with "version" and "date".
	// todo future: enforce this format?
	sig := ed25519.Sign(privKey, buf)

	change := updates.Change{
		PubKey: privKey.Public().(ed25519.PublicKey),
		Sig:    sig,
		Text:   string(buf),
	}
	changelog.Changes = append([]updates.Change{change}, changelog.Changes...)

	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	err = enc.Encode(changelog)
	xcheckf(err, "encode changelog as json")
	err = os.WriteFile(args[1], b.Bytes(), 0644)
	xcheckf(err, "writing versions file")
}

func cmdUpdatesVerify(c *cmd) {
	c.unlisted = true
	c.params = "pubkey-base64 < changelog-file"
	c.help = "Verify the changelog file against the public key."
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}

	pubKey := ed25519.PublicKey(base64Decode(args[0]))

	var changelog updates.Changelog
	err := json.NewDecoder(os.Stdin).Decode(&changelog)
	xcheckf(err, "parsing changelog file")

	for i, c := range changelog.Changes {
		if !bytes.Equal(c.PubKey, pubKey) {
			log.Fatalf("change has different public key %x, expected %x", c.PubKey, pubKey)
		} else if !ed25519.Verify(pubKey, []byte(c.Text), c.Sig) {
			log.Fatalf("verification failed for change with index %d", i)
		}
	}
	fmt.Printf("%d change(s) verified\n", len(changelog.Changes))
}

func cmdUpdatesGenkey(c *cmd) {
	c.unlisted = true
	c.params = ">privkey"
	c.help = "Generate a key for signing a changelog file with."
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	buf := make([]byte, ed25519.SeedSize)
	cryptorand.Read(buf)
	enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	_, err := enc.Write(buf)
	xcheckf(err, "writing private key")
	err = enc.Close()
	xcheckf(err, "writing private key")
}

func cmdUpdatesPubkey(c *cmd) {
	c.unlisted = true
	c.params = "<privkey >pubkey"
	c.help = "Print the public key for a private key."
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	seed := make([]byte, ed25519.SeedSize)
	_, err := io.ReadFull(base64.NewDecoder(base64.StdEncoding, os.Stdin), seed)
	xcheckf(err, "reading private key")
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := []byte(privKey.Public().(ed25519.PublicKey))
	enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	_, err = enc.Write(pubKey)
	xcheckf(err, "writing public key")
	err = enc.Close()
	xcheckf(err, "writing public key")
}

var updatesTemplate = htmltemplate.Must(htmltemplate.New("changelog").Parse(`<!doctype html>
<html>
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<title>mox changelog</title>
		<style>
body, html { padding: 1em; font-size: 16px; }
* { font-size: inherit; font-family: ubuntu, lato, sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
h1, h2, h3, h4 { margin-bottom: 1ex; }
h1 { font-size: 1.2rem; }
.literal { background-color: #fdfdfd; padding: .5em 1em; border: 1px solid #eee; border-radius: 4px; white-space: pre-wrap; font-family: monospace; font-size: 15px; tab-size: 4; }
		</style>
	</head>
	<body>
		<h1>Changes{{ if .FromVersion }} since {{ .FromVersion }}{{ end }}</h1>
	{{ if not .Changes }}
		<div>No changes</div>
	{{ end }}
	{{ range .Changes }}
		<pre class="literal">{{ .Text }}</pre>
		<hr style="margin:1ex 0" />
	{{ end }}
	</body>
</html>
`))

func cmdUpdatesServe(c *cmd) {
	c.unlisted = true
	c.help = "Serve changelog.json with updates."
	var address, changelog string
	c.flag.StringVar(&address, "address", "127.0.0.1:8596", "address to serve /changelog on")
	c.flag.StringVar(&changelog, "changelog", "changelog.json", "changelog file to serve")
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}

	parseFile := func() (*updates.Changelog, error) {
		f, err := os.Open(changelog)
		if err != nil {
			return nil, err
		}
		defer func() {
			err := f.Close()
			c.log.Check(err, "closing changelog file")
		}()
		var cl updates.Changelog
		if err := json.NewDecoder(f).Decode(&cl); err != nil {
			return nil, err
		}
		return &cl, nil
	}

	_, err := parseFile()
	if err != nil {
		log.Fatalf("parsing %s: %v", changelog, err)
	}

	srv := http.NewServeMux()
	srv.HandleFunc("/changelog", func(w http.ResponseWriter, r *http.Request) {
		cl, err := parseFile()
		if err != nil {
			log.Printf("parsing %s: %v", changelog, err)
			http.Error(w, "500 - internal server error", http.StatusInternalServerError)
			return
		}
		from := r.URL.Query().Get("from")
		var fromVersion *updates.Version
		if from != "" {
			v, err := updates.ParseVersion(from)
			if err == nil {
				fromVersion = &v
			}
		}
		if fromVersion != nil {
		nextchange:
			for i, c := range cl.Changes {
				for _, line := range strings.Split(strings.Split(c.Text, "\n\n")[0], "\n") {
					if strings.HasPrefix(line, "version:") {
						v, err := updates.ParseVersion(strings.TrimSpace(strings.TrimPrefix(line, "version:")))
						if err == nil && !v.After(*fromVersion) {
							cl.Changes = cl.Changes[:i]
							break nextchange
						}
					}
				}
			}
		}

		// Check if client accepts html. If so, we'll provide a human-readable version.
		accept := r.Header.Get("Accept")
		var html bool
	accept:
		for _, ac := range strings.Split(accept, ",") {
			var ok bool
			for i, kv := range strings.Split(strings.TrimSpace(ac), ";") {
				if i == 0 {
					ct := strings.TrimSpace(kv)
					if strings.EqualFold(ct, "text/html") || strings.EqualFold(ct, "text/*") {
						ok = true
						continue
					}
					continue accept
				}
				t := strings.SplitN(strings.TrimSpace(kv), "=", 2)
				if !strings.EqualFold(t[0], "q") || len(t) != 2 {
					continue
				}
				switch t[1] {
				case "0", "0.", "0.0", "0.00", "0.000":
					ok = false
					continue accept
				}
				break
			}
			if ok {
				html = true
				break
			}
		}

		if html {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			err := updatesTemplate.Execute(w, map[string]any{
				"FromVersion": fromVersion,
				"Changes":     cl.Changes,
			})
			if err != nil && !mlog.IsClosed(err) {
				log.Printf("writing changelog html: %v", err)
			}
		} else {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if err := json.NewEncoder(w).Encode(cl); err != nil && !mlog.IsClosed(err) {
				log.Printf("writing changelog json: %v", err)
			}
		}
	})
	log.Printf("listening on %s", address)
	log.Fatalln(http.ListenAndServe(address, srv))
}
