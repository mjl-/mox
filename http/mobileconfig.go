package http

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

// Apple software isn't good at autoconfig/autodiscovery, but it can import a
// device management profile containing account settings.
//
// See https://developer.apple.com/documentation/devicemanagement/mail.
type deviceManagementProfile struct {
	XMLName xml.Name `xml:"plist"`
	Version string   `xml:"version,attr"`
	Dict    dict     `xml:"dict"`
}

type array []dict

type dict map[string]any

// MarshalXML marshals as <dict> with multiple pairs of <key> and a value of various types.
func (m dict) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	// The plist format isn't that easy to generate with Go's xml package, it's leaving
	// out reasonable structure, instead just concatenating key/value pairs. Perhaps
	// there is a better way?

	if err := e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "dict"}}); err != nil {
		return err
	}
	l := maps.Keys(m)
	sort.Strings(l)
	for _, k := range l {
		tokens := []xml.Token{
			xml.StartElement{Name: xml.Name{Local: "key"}},
			xml.CharData([]byte(k)),
			xml.EndElement{Name: xml.Name{Local: "key"}},
		}
		for _, t := range tokens {
			if err := e.EncodeToken(t); err != nil {
				return err
			}
		}
		tokens = nil

		switch v := m[k].(type) {
		case string:
			tokens = []xml.Token{
				xml.StartElement{Name: xml.Name{Local: "string"}},
				xml.CharData([]byte(v)),
				xml.EndElement{Name: xml.Name{Local: "string"}},
			}
		case int:
			tokens = []xml.Token{
				xml.StartElement{Name: xml.Name{Local: "integer"}},
				xml.CharData([]byte(fmt.Sprintf("%d", v))),
				xml.EndElement{Name: xml.Name{Local: "integer"}},
			}
		case bool:
			tag := "false"
			if v {
				tag = "true"
			}
			tokens = []xml.Token{
				xml.StartElement{Name: xml.Name{Local: tag}},
				xml.EndElement{Name: xml.Name{Local: tag}},
			}
		case array:
			if err := e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "array"}}); err != nil {
				return err
			}
			for _, d := range v {
				if err := d.MarshalXML(e, xml.StartElement{Name: xml.Name{Local: "array"}}); err != nil {
					return err
				}
			}
			if err := e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "array"}}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected dict value of type %T", v)
		}
		for _, t := range tokens {
			if err := e.EncodeToken(t); err != nil {
				return err
			}
		}
	}
	if err := e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "dict"}}); err != nil {
		return err
	}
	return nil
}

// MobileConfig returns a device profile for a macOS Mail email account. The file
// should have a .mobileconfig extension. Opening the file adds it to Profiles in
// System Preferences, where it can be installed. This profile does not contain a
// password because sending opaque files containing passwords around to users seems
// like bad security practice.
//
// Multiple addresses can be passed, the first is used for IMAP/submission login,
// and likely seen as primary account by Apple software.
//
// The config is not signed, so users must ignore warnings about unsigned profiles.
func MobileConfig(addresses []string, fullName string) ([]byte, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("need at least 1 address")
	}
	addr, err := smtp.ParseAddress(addresses[0])
	if err != nil {
		return nil, fmt.Errorf("parsing address: %v", err)
	}

	config, err := mox.ClientConfigDomain(addr.Domain)
	if err != nil {
		return nil, fmt.Errorf("getting config for domain: %v", err)
	}

	// Apple software wants identifiers...
	t := strings.Split(addr.Domain.Name(), ".")
	slices.Reverse(t)
	reverseAddr := strings.Join(t, ".") + "." + addr.Localpart.String()

	// Apple software wants UUIDs... We generate them deterministically based on address
	// and our code (through key, which we must change if code changes).
	const key = "mox0"
	uuid := func(prefix string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(prefix + "\n" + "\n" + strings.Join(addresses, ",")))
		sum := mac.Sum(nil)
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
		return uuid
	}

	uuidConfig := uuid("config")
	uuidAccount := uuid("account")

	// The "UseSSL" fields are underspecified in Apple's format. They say "If true,
	// enables SSL for authentication on the incoming mail server.". I'm assuming they
	// want to know if they should start immediately with a handshake, instead of
	// starting out plain. There is no way to require STARTTLS though. You could even
	// interpret their wording as this field enable authentication through client-side
	// TLS certificates, given their "on the incoming mail server", instead of "of the
	// incoming mail server".

	var w bytes.Buffer
	p := deviceManagementProfile{
		Version: "1.0",
		Dict: dict(map[string]any{
			"PayloadDisplayName": fmt.Sprintf("%s email account", addresses[0]),
			"PayloadIdentifier":  reverseAddr + ".email",
			"PayloadType":        "Configuration",
			"PayloadUUID":        uuidConfig,
			"PayloadVersion":     1,
			"PayloadContent": array{
				dict(map[string]any{
					"EmailAccountDescription": addresses[0],
					"EmailAccountName":        fullName,
					"EmailAccountType":        "EmailTypeIMAP",
					// Comma-separated multiple addresses are not documented at Apple, but seem to
					// work.
					"EmailAddress":                           strings.Join(addresses, ","),
					"IncomingMailServerAuthentication":       "EmailAuthCRAMMD5", // SCRAM not an option at time of writing..
					"IncomingMailServerUsername":             addresses[0],
					"IncomingMailServerHostName":             config.IMAP.Host.ASCII,
					"IncomingMailServerPortNumber":           config.IMAP.Port,
					"IncomingMailServerUseSSL":               config.IMAP.TLSMode == mox.TLSModeImmediate,
					"OutgoingMailServerAuthentication":       "EmailAuthCRAMMD5", // SCRAM not an option at time of writing...
					"OutgoingMailServerHostName":             config.Submission.Host.ASCII,
					"OutgoingMailServerPortNumber":           config.Submission.Port,
					"OutgoingMailServerUsername":             addresses[0],
					"OutgoingMailServerUseSSL":               config.Submission.TLSMode == mox.TLSModeImmediate,
					"OutgoingPasswordSameAsIncomingPassword": true,
					"PayloadIdentifier":                      reverseAddr + ".email.account",
					"PayloadType":                            "com.apple.mail.managed",
					"PayloadUUID":                            uuidAccount,
					"PayloadVersion":                         1,
				}),
			},
		}),
	}
	if _, err := fmt.Fprint(&w, xml.Header); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprint(&w, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"); err != nil {
		return nil, err
	}
	enc := xml.NewEncoder(&w)
	enc.Indent("", "\t")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(&w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
