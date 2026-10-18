// Package chatmail implements checks for messages specific to chatmail servers,
// such as requiring that messages are end-to-end encrypted.
//
// See https://delta.chat/en/chatmail.
//
// The logic is modeled on filtermail, the before-queue filter used by chatmail
// servers: https://github.com/chatmail/filtermail.
package chatmail

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// Encrypted returns whether the message is an OpenPGP encrypted message, with
// the MIME structure of RFC 3156 (multipart/encrypted with an
// application/pgp-encrypted part with "Version: 1" and an
// application/octet-stream part with an armored OpenPGP message).
//
// incoming indicates the message is received from another mail server, instead
// of submitted by local user. For outgoing messages, an armored payload with a
// "Version:" comment is rejected: Delta Chat doesn't add such comments, and
// they could be used to smuggle content past the check.
func Encrypted(header textproto.MIMEHeader, body io.Reader, incoming bool) bool {
	mediatype, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediatype, "multipart/encrypted") {
		return false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return false
	}

	mpr := multipart.NewReader(body, boundary)

	// First part must be the version identification. ../rfc/3156:373
	part, err := mpr.NextPart()
	if err != nil {
		return false
	}
	if ct, _, err := mime.ParseMediaType(part.Header.Get("Content-Type")); err != nil || !strings.EqualFold(ct, "application/pgp-encrypted") {
		return false
	}
	p, err := io.ReadAll(part)
	if err != nil || strings.TrimSpace(string(p)) != "Version: 1" {
		return false
	}

	// Second part must be the armored OpenPGP message.
	part, err = mpr.NextPart()
	if err != nil {
		return false
	}
	if ct, _, err := mime.ParseMediaType(part.Header.Get("Content-Type")); err != nil || !strings.EqualFold(ct, "application/octet-stream") {
		return false
	}
	p, err = io.ReadAll(part)
	if err != nil || !encryptedPayload(string(p), !incoming) {
		return false
	}

	// There must be no further parts.
	if _, err := mpr.NextPart(); err != io.EOF {
		return false
	}
	return true
}

// SecureJoin returns whether the message is a Delta Chat Secure-Join request.
//
// Secure-Join requests are unencrypted by necessity, they are used to establish
// an encrypted connection with a new contact.
func SecureJoin(header textproto.MIMEHeader, body io.Reader) bool {
	v := header.Get("Secure-Join")
	if v != "vc-request" && v != "vg-request" {
		return false
	}

	mediatype, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediatype, "multipart/") {
		return false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return false
	}

	mpr := multipart.NewReader(body, boundary)
	part, err := mpr.NextPart()
	if err != nil {
		return false
	}
	if ct, _, err := mime.ParseMediaType(part.Header.Get("Content-Type")); err != nil || ct != "text/plain" {
		return false
	}
	p, err := io.ReadAll(part)
	if err != nil {
		return false
	}
	payload := strings.ToLower(strings.TrimSpace(string(p)))
	if payload != "secure-join: vc-request" && payload != "secure-join: vg-request" {
		return false
	}

	// There must be no further parts.
	if _, err := mpr.NextPart(); err != io.EOF {
		return false
	}
	return true
}

// AutocryptSetupMessage returns whether the message is an Autocrypt Setup
// Message. These are sent unencrypted (but with an encrypted payload) from a
// user to themselves when adding a device, and are allowed for outgoing
// messages when sent to the sender themselves.
func AutocryptSetupMessage(header textproto.MIMEHeader) bool {
	if header.Get("Subject") != "Autocrypt Setup Message" {
		return false
	}
	mediatype, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	return err == nil && strings.EqualFold(mediatype, "multipart/mixed")
}

// encryptedPayload returns whether payload is an ASCII-armored OpenPGP message
// with a symmetrically encrypted and integrity protected data packet, i.e. the
// result of encrypting a message.
//
// outgoing disallows a "Version:" comment in the armored message.
func encryptedPayload(payload string, outgoing bool) bool {
	const prefix = "-----BEGIN PGP MESSAGE-----\r\n"
	const suffix = "-----END PGP MESSAGE-----"

	payload, ok := strings.CutPrefix(payload, prefix)
	if !ok {
		return false
	}
	payload = strings.TrimRight(payload, "\r\n")
	payload, ok = strings.CutSuffix(payload, suffix)
	if !ok {
		return false
	}

	const versionComment = "Version: "
	if strings.HasPrefix(payload, versionComment) {
		if outgoing {
			return false
		}
		if i := strings.Index(payload, "\r\n"); i >= 0 {
			payload = payload[i+2:]
		}
	}

	payload = strings.TrimLeft(payload, "\r\n")

	// Strip the optional CRC24 checksum, which follows the last "=".
	if i := strings.LastIndex(payload, "="); i >= 0 {
		payload = payload[:i]
	}

	payload = strings.NewReplacer("\r", "", "\n", "").Replace(payload)
	buf, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	return encryptedOpenPGPPayload(buf)
}

// encryptedOpenPGPPayload returns whether payload consists of OpenPGP packets
// ending in a "Symmetrically Encrypted and Integrity Protected Data Packet"
// (packet type 18). Packets before the final packet must be session key packets
// (type 1, PKESK) or literal data packets (type 3, SKESK). Both the OpenPGP and
// the legacy (GnuPG) packet formats are accepted.
func encryptedOpenPGPPayload(payload []byte) bool {
	n := int64(len(payload))
	i := int64(0)
	for i < n {
		bits := payload[i] & 0xC0
		var legacy bool
		switch bits {
		case 0xC0:
			legacy = false
		case 0x80:
			legacy = true
		default:
			return false
		}

		var packetTypeID byte
		if legacy {
			// ../rfc/9580:1159 bits 5 to 2.
			packetTypeID = (payload[i] & 0x3C) >> 2
		} else {
			// ../rfc/9580:1152 bits 5 to 0.
			packetTypeID = payload[i] & 0x3F
		}

		var bodyLen int64
		if legacy {
			lengthType := payload[i] & 0x03
			i++
			switch lengthType {
			case 0:
				if i >= n {
					return false
				}
				bodyLen = int64(payload[i])
				i++
			case 1:
				if i+1 >= n {
					return false
				}
				bodyLen = int64(payload[i])<<8 + int64(payload[i+1])
				i += 2
			case 2:
				if i+3 >= n {
					return false
				}
				bodyLen = int64(payload[i])<<24 + int64(payload[i+1])<<16 + int64(payload[i+2])<<8 + int64(payload[i+3])
				i += 4
			default:
				// Indeterminate length is not supported. ../rfc/9580:1264
				return false
			}
		} else {
			i++
			// Partial body lengths. ../rfc/9580:1234
			for i < n && payload[i] >= 224 && payload[i] < 255 {
				partialLen := int64(1) << (payload[i] & 0x1F)
				i += 1 + partialLen
			}
			if i >= n {
				return false
			}
			switch {
			case payload[i] < 192:
				bodyLen = int64(payload[i])
				i++
			case payload[i] < 224:
				if i+1 >= n {
					return false
				}
				bodyLen = (int64(payload[i])-192)<<8 + int64(payload[i+1]) + 192
				i += 2
			case payload[i] == 255:
				if i+4 >= n {
					return false
				}
				bodyLen = int64(payload[i+1])<<24 | int64(payload[i+2])<<16 | int64(payload[i+3])<<8 | int64(payload[i+4])
				i += 5
			default:
				return false
			}
		}
		i += bodyLen

		if i == n {
			// ../rfc/9580:1084
			return packetTypeID == 18
		} else if packetTypeID != 1 && packetTypeID != 3 {
			return false
		}
	}
	return false
}
