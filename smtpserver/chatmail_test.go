package smtpserver

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

// setChatmail enables chatmail mode for the test config, and marks the mjl
// account as chatmail.
func setChatmail(t *testing.T, incomingEncryptedOnly bool) {
	t.Helper()
	mox.Conf.Dynamic.Chatmail.Enabled = true
	mox.Conf.Dynamic.Chatmail.IncomingEncryptedOnly = incomingEncryptedOnly
	acc := mox.Conf.Dynamic.Accounts["mjl"]
	acc.Chatmail = true
	mox.Conf.Dynamic.Accounts["mjl"] = acc
}

// validPGPPayload is the armored OpenPGP message from the filtermail tests.
const validPGPPayload = `-----BEGIN PGP MESSAGE-----

wU4DhW3gBZ/VvCYSAQdA8bMs2spwbKdGjVsL1ByPkNrqD7frpB73maeL6I6SzDYg
O5G53tv339RdKq3WRcCtEEvxjHlUx2XNwXzC04BpmfvBTgNfPUyLDzjXnxIBB0Ae
8ymwGvXMCCimHXN0Dg8Ui62KOi03h0UgheoHWovJSCDF4CKre/xtFr3nL7lq/PKI
JsjVNz7/RK9FSXF6WwfONtLCyQGEuVAsB/KXfCBEyfKhaMwGHvhujRidGW5uV1no
lMGl3ODmo29Lgeu2uSE7EpJRZoe6hU6ddmBkqxax61ZtkaFlGFFpdo2K8balNNdz
ZsJ/9mmI9x3oOJ4/l1nhQbUO9ADbs7gJhFdV5Qkp30b5fCI7bU+aoe1ccBbLe/WM
YUty1PqcuQT7XjA+XmYuL261tvW8pBetT+i33/E2d8PzzYt2IuK9qeevyS+yxdwA
kfwejFWzzsUlJaDxs1x4XOxkMgSj+jo+g12dFOb7fyClsAnq23iDb8AuaT/BScAI
+lO+gher69+6LmM7VGHLG5k762J1jTaQCaKt1s8TAWV99Eo4491vL6fyvk3l/Cfg
RXSwiWFgj19Pn0Rq7CD9v22UE2vdUMBTcV4aw79mClk1YQ23jbF0y5DCjPdJ62Zo
tskBgFt3NoWV80jZ76zIBLrrjLwCCll8JjJtFwSkt2GX5RFBsVa4A8IDht9RtEk7
rrHgbSZQfkauEi/mH3/6CDZoLqSHudUZ7d4MaJwun1TkFYGe2ORwGJd4OBj3oGJp
H8YBwCpk///L/fKjX0Gg3M8nrpM4wrRFhPKidAgO/kcm25X4+ZHlVkWBTCt5RWKI
fHh6oLDZCqCfcgMkE1KKmwfIHaUkhq5BPRigwy6i5dh1DM4+1UCLh3dxzVbqE9b9
61NB19nXdRtDA2sOUnj9ve6m/wEPyCb6/zBQZqvCBYb1/AjdXpUrFT+DbpfyxaXN
XfhDVb5mNqNM/IVj0V5fvTc6vOfYbzQtPm10H+FdWWfb+rJRfyC3MA2w2IqstFe3
w3bu2iE6CQvSqRvge+ZqLKt/NqYwOURiUmpuklbl3kPJ97+mfKWoiqk8Iz1VY+bb
NMUC7aoGv+jcoj+WS6PYO8N6BeRVUUB3ZJSf8nzjgxm1/BcM+UD3BPrlhT11ODRs
baifGbprMWwt3dhb8cQgRT8GPdpO1OsDkzL6iikMjLHWWiA99GV6ruiHsIPw6boW
A6/uSOskbDHOROotKmddGTBd0iiHXAoQsJFt1ZjUkt6EHrgWs+GAvrvKpXs1mrz8
uj3GwEFrHS+Xuf2UDgpszYT3hI2cL/kUtGakVR7m7vVMZqXBUbZdGAEb1PZNPwsI
E4aMK02+EVB+tSN4Fzj99N2YD0inVYt+oPjr2tHhUS6aSGBNS/48Ki47DOg4Sxkn
lkOWnEbCD+XTnbDd
=agR5
-----END PGP MESSAGE-----`

// encryptedMessage returns a multipart/encrypted message, with the given From
// and To header values.
func encryptedMessage(from, to string) string {
	return strings.ReplaceAll(`From: <`+from+`>
To: <`+to+`>
Subject: ...
Message-Id: <encrypted@mox.example>
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="chatmail-boundary"

--chatmail-boundary
Content-Type: application/pgp-encrypted

Version: 1

--chatmail-boundary
Content-Type: application/octet-stream

`+validPGPPayload+`

--chatmail-boundary--
`, "\n", "\r\n")
}

var chatmailSecureJoinMessage = strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: Secure join
Message-Id: <securejoin@mox.example>
Secure-Join: vc-request
Secure-Join-Invitenumber: RANDOM-TOKEN
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="chatmail-boundary"

--chatmail-boundary
Content-Type: text/plain; charset=utf-8

Secure-Join: vc-request

--chatmail-boundary--
`, "\n", "\r\n")

var chatmailAutocryptSetupMessage = strings.ReplaceAll(`From: <mjl@mox.example>
To: <mjl@mox.example>
Subject: Autocrypt Setup Message
Message-Id: <asm@mox.example>
Autocrypt-Setup-Message: v1
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="chatmail-boundary"

--chatmail-boundary
Content-Type: text/plain

This is an Autocrypt Setup Message.

--chatmail-boundary--
`, "\n", "\r\n")

func TestChatmailSubmission(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), dns.MockResolver{})
	defer ts.close()
	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = password0

	submit := func(t *testing.T, msg string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(client *smtpclient.Client) {
			err := client.Deliver(ctxbg, "mjl@mox.example", "remote@example.org", int64(len(msg)), strings.NewReader(msg), false, false, false)
			ts.smtpErr(err, expErr)
		})
	}

	// Without chatmail mode, unencrypted messages are accepted.
	submit(t, submitMessage, nil)

	// With chatmail mode and a chatmail account, unencrypted messages are rejected.
	setChatmail(t, false)
	submit(t, submitMessage, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	checkEvaluationCount(t, 0)

	// Encrypted messages are accepted.
	encrypted := encryptedMessage("mjl@mox.example", "remote@example.org")
	submit(t, encrypted, nil)

	// Secure-Join requests are accepted.
	submit(t, chatmailSecureJoinMessage, nil)

	// Autocrypt Setup Messages are accepted when sent by a user to themselves.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mjl@mox.example", "mjl@mox.example", int64(len(chatmailAutocryptSetupMessage)), strings.NewReader(chatmailAutocryptSetupMessage), false, false, false)
		tcheck(t, err, "deliver autocrypt setup message")
	})

	// But not to another recipient.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mjl@mox.example", "remote@example.org", int64(len(chatmailAutocryptSetupMessage)), strings.NewReader(chatmailAutocryptSetupMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	})

	// A non-chatmail account may still send unencrypted messages.
	c := mox.Conf.Dynamic
	acc := c.Accounts["mjl"]
	acc.Chatmail = false
	c.Accounts["mjl"] = acc
	submit(t, submitMessage, nil)

	checkEvaluationCount(t, 0)
}

func TestChatmailIncoming(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
	}
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()

	setChatmail(t, true)

	// Unencrypted incoming messages for a chatmail account are rejected.
	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
		ts.smtpErr(err, &smtpclient.Error{Permanent: true, Code: smtp.C523EncryptionNeeded, Secode: smtp.SePol7EncNeeded10})
	})

	// Encrypted incoming messages are delivered.
	ts.run(func(client *smtpclient.Client) {
		msg := encryptedMessage("remote@example.org", "mjl@mox.example")
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(msg)), strings.NewReader(msg), false, true, false)
		tcheck(t, err, "deliver encrypted message")
	})

	checkEvaluationCount(t, 0)
}
