package chatmail

import (
	"bytes"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseMessage(t *testing.T, filename string) *mail.Message {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
	return msg
}

func TestEncrypted(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"asm.eml", false},
		{"encrypted.eml", true},
		{"fake-encrypted.eml", false},
		{"literal.eml", false},
		{"mailer-daemon.eml", false},
		{"mdn.eml", false},
		{"plain.eml", false},
		{"securejoin-vc.eml", false},
		{"securejoin-vc-fake.eml", false},
	}
	for _, tc := range tests {
		msg := parseMessage(t, tc.filename)
		body := readBody(t, msg)
		// Both incoming and outgoing interpretation should agree for these messages.
		for _, incoming := range []bool{true, false} {
			if got := Encrypted(textproto.MIMEHeader(msg.Header), bytes.NewReader(body), incoming); got != tc.want {
				t.Errorf("Encrypted(%s, incoming=%t) = %t, want %t", tc.filename, incoming, got, tc.want)
			}
		}
	}
}

func TestSecureJoin(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"asm.eml", false},
		{"encrypted.eml", false},
		{"fake-encrypted.eml", false},
		{"literal.eml", false},
		{"mailer-daemon.eml", false},
		{"mdn.eml", false},
		{"plain.eml", false},
		{"securejoin-vc.eml", true},
		{"securejoin-vc-fake.eml", false},
	}
	for _, tc := range tests {
		msg := parseMessage(t, tc.filename)
		if got := SecureJoin(textproto.MIMEHeader(msg.Header), bytes.NewReader(readBody(t, msg))); got != tc.want {
			t.Errorf("SecureJoin(%s) = %t, want %t", tc.filename, got, tc.want)
		}
	}
}

func TestAutocryptSetupMessage(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"asm.eml", true},
		{"encrypted.eml", false},
		{"plain.eml", false},
	}
	for _, tc := range tests {
		msg := parseMessage(t, tc.filename)
		if got := AutocryptSetupMessage(textproto.MIMEHeader(msg.Header)); got != tc.want {
			t.Errorf("AutocryptSetupMessage(%s) = %t, want %t", tc.filename, got, tc.want)
		}
	}
}

func readBody(t *testing.T, msg *mail.Message) []byte {
	t.Helper()
	buf, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("reading message body: %v", err)
	}
	return buf
}

func TestEncryptedPayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		outgoing bool
		incoming bool
	}{
		{"valid", validPayload, true, true},
		{"gnupg", gnupgPayload, true, true},
		{"with_comment", commentPayload, false, true},
		{"invalid_base64", invalidBase64Payload, false, false},
		{"invalid_non_pgp_base64", nonPGPBase64Payload, false, false},
		{"invalid_cleartext", cleartextPayload, false, false},
		{"invalid_no_begin", "-----END PGP MESSAGE-----", false, false},
		{"invalid_no_end", "-----BEGIN PGP MESSAGE-----", false, false},
	}
	for _, tc := range tests {
		payload := strings.ReplaceAll(tc.payload, "\n", "\r\n")
		if got := encryptedPayload(payload, true); got != tc.outgoing {
			t.Errorf("encryptedPayload(%s, outgoing) = %t, want %t", tc.name, got, tc.outgoing)
		}
		if got := encryptedPayload(payload, false); got != tc.incoming {
			t.Errorf("encryptedPayload(%s, incoming) = %t, want %t", tc.name, got, tc.incoming)
		}
	}
}

const validPayload = `-----BEGIN PGP MESSAGE-----

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

// gnupg uses the legacy packet format.
const gnupgPayload = `-----BEGIN PGP MESSAGE-----

hF4DFYw3E47UG/ASAQdA3JnkJLJJALitYG/jzzEuF0p+hEBsgLTicaEJkJerInkw
SftuCMBjxv4D6rTqNkBn7IQh6gmlUKrUNBVEnq0V1InVF9o0kDpZfUUaB5ajNDMb
hF4DMiMKov7/CVgSAQdA7ib6HK7UVW2IdAM5PILbtqzuynukooXdg9YWWamjal8w
h/L0BxbtUFzI3U847dvzwtsW7A9CZXpi45OMXRC9mO3G/FAY1fW+C6PwObT7X1qK
0sDSAbyYddCihL1UEl6EigtD/YQezCTCydzstD2cRdV75lmUqzMCR8NbfvdttBbl
g04ZZtoHm1DSnXIAN4iFzW4EBgNVUDCnqO8wyYmWw4OCOt45IkTXGQUICGxeVh6g
4Pdj4OzSrg/mTZGIDjE2h/osVpPEQjwcAus73EZC4sz4n2U+OMHsq0M54Ds7wyGv
1KBzcQQ5Rc/DPPT0INnl58datm2HGKtWFWYab9/cw/fnQ+oYhmpkZbdITTmnTAyn
CHih86i0w6gXsX99iRLe6yP8BcU3rCCflsCp5zzlcFYViTPgEn1W8H32VOXulfcV
rpRFtc5yzjFj8Dvq9gI9yGIgqiS7oEAXdRBYhmBRTydMcbS1bCPDWy5w95Cp2VzR
x8cBq5e+27QTl9YNHr4xeric7del79wktJFiINzUCQPwkwM9ud2EJ1zN8Owr2Dp8
JvS2ioSEK5J2Lc95vDLmbVnMuKmVW6qD+fEdtYSHnSIc/t+iYG3GlaFyvO8t0Jav
cbsijrbYhoSOq67KseQWvfL+gL5u
=WWqc
-----END PGP MESSAGE-----`

const commentPayload = `-----BEGIN PGP MESSAGE-----
Version: 1
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

const invalidBase64Payload = `-----BEGIN PGP MESSAGE-----

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
lkOWnEbCD+XTnbDd=
=agR5
-----END PGP MESSAGE-----`

const nonPGPBase64Payload = `-----BEGIN PGP MESSAGE-----

RGVsdGEgQ2hhdCBpcyBhIHJlbGlhYmxlLCBkZWNlbnRyYWxpemVkIGFuZCBzZWN1cmUgaW5zdGFu
dCBtZXNzYWdpbmcgYXBwLCBhdmFpbGFibGUgZm9yIG1vYmlsZSBhbmQgZGVza3RvcCBwbGF0Zm9y
bXMuCgogICAgSW5zdGFudCBjcmVhdGlvbiBvZiBwcml2YXRlIGNoYXQgcHJvZmlsZXMgd2l0aCBz
ZWN1cmUgYW5kIGludGVyb3BlcmFibGUgY2hhdG1haWwgcmVsYXlzIHRoYXQgb2ZmZXIgaW5zdGFu
dCBtZXNzYWdlIGRlbGl2ZXJ5LCBhbmQgUHVzaCBOb3RpZmljYXRpb25zIGZvciBpT1MgYW5kIEFu
ZHJvaWQgZGV2aWNlcy4KCiAgICBQZXJ2YXNpdmUgbXVsdGktcHJvZmlsZSBhbmQgbXVsdGktZGV2
aWNlIHN1cHBvcnQgb24gYWxsIHBsYXRmb3JtcyBhbmQgYmV0d2VlbiBkaWZmZXJlbnQgY2hhdG1h
aWwgYXBwcy4KCiAgICBJbnRlcmFjdGl2ZSBpbi1jaGF0IGFwcHMgZm9yIGdhbWluZyBhbmQgY29s
bGFib3JhdGlvbgoKICAgIEF1ZGl0ZWQgZW5kLXRvLWVuZCBlbmNyeXB0aW9uIHNhZmUgYWdhaW5z
dCBuZXR3b3JrIGFuZCBzZXJ2ZXIgYXR0YWNrcy4KCiAgICBGcmVlIGFuZCBPcGVuIFNvdXJjZSBz
b2Z0d2FyZSwgYm90aCBhcHAgYW5kIHNlcnZlciBzaWRlLCBidWlsdCBvbiBJbnRlcm5ldCBTdGFu
ZGFyZHMuCgo=
=4cf0a3
-----END PGP MESSAGE-----`

const cleartextPayload = `-----BEGIN PGP MESSAGE-----

Definitely not base64 encoded PGP message content.
-----END PGP MESSAGE-----`
