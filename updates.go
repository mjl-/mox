package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

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
	defer f.Close()
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

	changelog.Changes = append(changelog.Changes, updates.Change{
		PubKey: privKey.Public().(ed25519.PublicKey),
		Sig:    sig,
		Text:   string(buf),
	})

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
	_, err := cryptorand.Read(buf)
	xcheckf(err, "generating key")
	enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	_, err = enc.Write(buf)
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
	n, err := io.ReadFull(base64.NewDecoder(base64.StdEncoding, os.Stdin), seed)
	log.Printf("n %d", n)
	xcheckf(err, "reading private key")
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := []byte(privKey.Public().(ed25519.PublicKey))
	enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	_, err = enc.Write(pubKey)
	xcheckf(err, "writing public key")
	err = enc.Close()
	xcheckf(err, "writing public key")
}
