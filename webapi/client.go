package webapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client can be used to call webapi methods.
// Client implements [Methods].
type Client struct {
	BaseURL    string // For example: http://localhost:1080/webapi/v0/.
	Username   string // Added as HTTP basic authentication if not empty.
	Password   string
	HTTPClient *http.Client // Optional, defaults to http.DefaultClient.
}

var _ Methods = Client{}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func transact[T any](ctx context.Context, c Client, fn string, req any) (resp T, rerr error) {
	hresp, err := httpDo(ctx, c, fn, req)
	if err != nil {
		return resp, err
	}
	defer hresp.Body.Close()

	if hresp.StatusCode == http.StatusOK {
		// Text and HTML of a message can each be 1MB. Another MB for other data would be a
		// lot.
		err := json.NewDecoder(&limitReader{hresp.Body, 3 * 1024 * 1024}).Decode(&resp)
		return resp, err
	}
	return resp, badResponse(hresp)
}

func transactReadCloser(ctx context.Context, c Client, fn string, req any) (resp io.ReadCloser, rerr error) {
	hresp, err := httpDo(ctx, c, fn, req)
	if err != nil {
		return nil, err
	}
	body := hresp.Body
	defer func() {
		if body != nil {
			body.Close()
		}
	}()
	if hresp.StatusCode == http.StatusOK {
		r := body
		body = nil
		return r, nil
	}
	return nil, badResponse(hresp)
}

func httpDo(ctx context.Context, c Client, fn string, req any) (*http.Response, error) {
	reqbuf, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %v", err)
	}
	data := url.Values{}
	data.Add("request", string(reqbuf))
	hreq, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+fn, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("new request: %v", err)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.Username != "" {
		hreq.SetBasicAuth(c.Username, c.Password)
	}
	hresp, err := c.httpClient().Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("http transaction: %v", err)
	}
	return hresp, nil
}

func badResponse(hresp *http.Response) error {
	if hresp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("http status %v, expected 200 ok", hresp.Status)
	}
	buf, err := io.ReadAll(&limitReader{R: hresp.Body, Limit: 10 * 1024})
	if err != nil {
		return fmt.Errorf("reading error from remote: %v", err)
	}
	var xerr Error
	err = json.Unmarshal(buf, &xerr)
	if err != nil {
		if len(buf) > 512 {
			buf = buf[:512]
		}
		return fmt.Errorf("error parsing error from remote: %v (first 512 bytes of response: %s)", err, string(buf))
	}
	return xerr
}

// Send composes a message and submits it to the queue for delivery for all
// recipients (to, cc, bcc).
//
// Configure your account to use unique SMTP MAIL FROM addresses ("fromid") and to
// keep history of retired messages, for better handling of transactional email,
// automatically managing a suppression list.
//
// Configure webhooks to receive updates about deliveries.
//
// If the request is a multipart/form-data, uploaded files with the form keys
// "alternativefile", "inlinefile" and/or "attachedfile" will be added to the
// message. If the uploaded file has content-type and/or content-id headers, they
// will be included. If no content-type is present in the request, and it can be
// detected, it is included automatically.
//
// Example call with a text and html message, with an inline and an attached image:
//
//	curl --user mox@localhost:moxmoxmox \
//		--form request='{"To": [{"Address": "mox@localhost"}], "Text": "hi ☺", "HTML": "<img src=\"cid:hi\" />"}' \
//		--form 'inlinefile=@hi.png;headers="Content-ID: <hi>"' \
//		--form attachedfile=@mox.png \
//		http://localhost:1080/webapi/v0/Send
//
// Error codes:
//
//   - badAddress, if an email address is invalid.
//   - missingBody, if no text and no html body was specified.
//   - multipleFrom, if multiple from addresses were specified.
//   - badFrom, if a from address was specified that isn't configured for the account.
//   - noRecipients, if no recipients were specified.
//   - messageLimitReached, if the outgoing message rate limit was reached.
//   - recipientLimitReached, if the outgoing new recipient rate limit was reached.
//   - messageTooLarge, message larger than configured maximum size.
//   - malformedMessageID, if MessageID is specified but invalid.
//   - sentOverQuota, message submitted, but not stored in Sent mailbox due to quota reached.
func (c Client) Send(ctx context.Context, req SendRequest) (resp SendResult, err error) {
	return transact[SendResult](ctx, c, "Send", req)
}

// SuppressionList returns the addresses on the per-account suppression list.
func (c Client) SuppressionList(ctx context.Context, req SuppressionListRequest) (resp SuppressionListResult, err error) {
	return transact[SuppressionListResult](ctx, c, "SuppressionList", req)
}

// SuppressionAdd adds an address to the suppression list of the account.
//
// Error codes:
//
//   - badAddress, if the email address is invalid.
func (c Client) SuppressionAdd(ctx context.Context, req SuppressionAddRequest) (resp SuppressionAddResult, err error) {
	return transact[SuppressionAddResult](ctx, c, "SuppressionAdd", req)
}

// SuppressionRemove removes an address from the suppression list of the account.
//
// Error codes:
//
//   - badAddress, if the email address is invalid.
func (c Client) SuppressionRemove(ctx context.Context, req SuppressionRemoveRequest) (resp SuppressionRemoveResult, err error) {
	return transact[SuppressionRemoveResult](ctx, c, "SuppressionRemove", req)
}

// SuppressionPresent returns whether an address is present in the suppression list of the account.
//
// Error codes:
//
//   - badAddress, if the email address is invalid.
func (c Client) SuppressionPresent(ctx context.Context, req SuppressionPresentRequest) (resp SuppressionPresentResult, err error) {
	return transact[SuppressionPresentResult](ctx, c, "SuppressionPresent", req)
}

// MessageGet returns a message from the account storage in parsed form.
//
// Use [Client.MessageRawGet] for the raw message (internet message file).
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageGet(ctx context.Context, req MessageGetRequest) (resp MessageGetResult, err error) {
	return transact[MessageGetResult](ctx, c, "MessageGet", req)
}

// MessageRawGet returns the full message in its original form, as stored on disk.
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageRawGet(ctx context.Context, req MessageRawGetRequest) (resp io.ReadCloser, err error) {
	return transactReadCloser(ctx, c, "MessageRawGet", req)
}

// MessagePartGet returns a single part from a multipart message, by a "parts
// path", a series of indices into the multipart hierarchy as seen in the parsed
// message. The initial selection is the body of the outer message (excluding
// headers).
//
// Error codes:
//   - messageNotFound, if the message does not exist.
//   - partNotFound, if the part does not exist.
func (c Client) MessagePartGet(ctx context.Context, req MessagePartGetRequest) (resp io.ReadCloser, err error) {
	return transactReadCloser(ctx, c, "MessagePartGet", req)
}

// MessageDelete permanently removes a message from the account storage (not moving
// to a Trash folder).
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageDelete(ctx context.Context, req MessageDeleteRequest) (resp MessageDeleteResult, err error) {
	return transact[MessageDeleteResult](ctx, c, "MessageDelete", req)
}

// MessageFlagsAdd adds (sets) flags on a message, like the well-known flags
// beginning with a backslash like \seen, \answered, \draft, or well-known flags
// beginning with a dollar like $junk, $notjunk, $forwarded, or custom flags.
// Existing flags are left unchanged.
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageFlagsAdd(ctx context.Context, req MessageFlagsAddRequest) (resp MessageFlagsAddResult, err error) {
	return transact[MessageFlagsAddResult](ctx, c, "MessageFlagsAdd", req)
}

// MessageFlagsRemove removes (clears) flags on a message.
// Other flags are left unchanged.
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageFlagsRemove(ctx context.Context, req MessageFlagsRemoveRequest) (resp MessageFlagsRemoveResult, err error) {
	return transact[MessageFlagsRemoveResult](ctx, c, "MessageFlagsRemove", req)
}

// MessageMove moves a message to a new mailbox name (folder). The destination
// mailbox name must already exist.
//
// Error codes:
//   - messageNotFound, if the message does not exist.
func (c Client) MessageMove(ctx context.Context, req MessageMoveRequest) (resp MessageMoveResult, err error) {
	return transact[MessageMoveResult](ctx, c, "MessageMove", req)
}
