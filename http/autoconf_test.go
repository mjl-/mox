package http

import (
	"encoding/xml"
	"testing"
)

func TestAutodiscover(t *testing.T) {
	// Request by Thunderbird.
	const body = `<?xml version="1.0" encoding="utf-8"?>
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
      <Request>
        <EMailAddress>test@example.org</EMailAddress>
        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
      </Request>
    </Autodiscover>
`
	var req autodiscoverRequest
	if err := xml.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("unmarshal autodiscover request: %v", err)
	}

	if req.Request.EmailAddress != "test@example.org" {
		t.Fatalf("emailaddress: got %q, expected %q", req.Request.EmailAddress, "test@example.org")
	}
}
