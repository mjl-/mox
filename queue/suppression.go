package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/webapi"
)

// todo: we should be processing spam complaints and add addresses to the list.

var errSuppressed = errors.New("address is on suppression list")

func baseAddress(a smtp.Path) smtp.Path {
	s := string(a.Localpart)
	s, _, _ = strings.Cut(s, "+")
	s, _, _ = strings.Cut(s, "-")
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ToLower(s)
	return smtp.Path{Localpart: smtp.Localpart(s), IPDomain: a.IPDomain}
}

// SuppressionList returns suppression. If account is not empty, only suppression
// for that account are returned.
//
// SuppressionList does not check if an account exists.
func SuppressionList(ctx context.Context, account string) ([]webapi.Suppression, error) {
	q := bstore.QueryDB[webapi.Suppression](ctx, DB)
	if account != "" {
		q.FilterNonzero(webapi.Suppression{Account: account})
	}
	return q.List()
}

// SuppressionLookup looks up a suppression for an address for an account. Returns
// a nil suppression if not found.
//
// SuppressionLookup does not check if an account exists.
func SuppressionLookup(ctx context.Context, account string, address smtp.Path) (*webapi.Suppression, error) {
	baseAddr := baseAddress(address).XString(true)
	q := bstore.QueryDB[webapi.Suppression](ctx, DB)
	q.FilterNonzero(webapi.Suppression{Account: account, BaseAddress: baseAddr})
	sup, err := q.Get()
	if err == bstore.ErrAbsent {
		return nil, nil
	}
	return &sup, err
}

// SuppressionAdd adds a suppression for an address for an account, setting
// BaseAddress based on OriginalAddress.
//
// If the base address of original address is already present, an error is
// returned (such as from bstore).
//
// SuppressionAdd does not check if an account exists.
func SuppressionAdd(ctx context.Context, originalAddress smtp.Path, sup *webapi.Suppression) error {
	sup.BaseAddress = baseAddress(originalAddress).XString(true)
	sup.OriginalAddress = originalAddress.XString(true)
	return DB.Insert(ctx, sup)
}

// SuppressionRemove removes a suppression. The base address for the the given
// address is removed.
//
// SuppressionRemove does not check if an account exists.
func SuppressionRemove(ctx context.Context, account string, address smtp.Path) error {
	baseAddr := baseAddress(address).XString(true)
	q := bstore.QueryDB[webapi.Suppression](ctx, DB)
	q.FilterNonzero(webapi.Suppression{Account: account, BaseAddress: baseAddr})
	n, err := q.Delete()
	if err != nil {
		return err
	}
	if n == 0 {
		return bstore.ErrAbsent
	}
	return nil
}

type suppressionCheck struct {
	MsgID     int64
	Account   string
	Recipient smtp.Path
	Code      int
	Secode    string
	Source    string
}

// process failures, possibly creating suppressions.
func suppressionProcess(log mlog.Log, tx *bstore.Tx, scl ...suppressionCheck) (suppressedMsgIDs []int64, err error) {
	for _, sc := range scl {
		xlog := log.With(slog.Any("suppressioncheck", sc))
		baseAddr := baseAddress(sc.Recipient).XString(true)
		exists, err := bstore.QueryTx[webapi.Suppression](tx).FilterNonzero(webapi.Suppression{Account: sc.Account, BaseAddress: baseAddr}).Exists()
		if err != nil {
			return nil, fmt.Errorf("checking if address is in suppression list: %v", err)
		} else if exists {
			xlog.Debug("address already in suppression list")
			continue
		}

		origAddr := sc.Recipient.XString(true)
		sup := webapi.Suppression{
			Account:         sc.Account,
			BaseAddress:     baseAddr,
			OriginalAddress: origAddr,
		}

		if isImmedateBlock(sc.Code, sc.Secode) {
			sup.Reason = fmt.Sprintf("delivery failure from %s with smtp code %d, enhanced code %q", sc.Source, sc.Code, sc.Secode)
		} else {
			// If two most recent deliveries failed (excluding this one, so three most recent
			// messages including this one), we'll add the address to the list.
			q := bstore.QueryTx[MsgRetired](tx)
			q.FilterNonzero(MsgRetired{RecipientAddress: origAddr})
			q.FilterNotEqual("ID", sc.MsgID)
			q.SortDesc("LastActivity")
			q.Limit(2)
			l, err := q.List()
			if err != nil {
				xlog.Errorx("checking for previous delivery failures", err)
				continue
			}
			if len(l) < 2 || l[0].Success || l[1].Success {
				continue
			}
			sup.Reason = fmt.Sprintf("delivery failure from %s and three consecutive failures", sc.Source)
		}
		if err := tx.Insert(&sup); err != nil {
			return nil, fmt.Errorf("inserting suppression: %v", err)
		}
		suppressedMsgIDs = append(suppressedMsgIDs, sc.MsgID)
	}
	return suppressedMsgIDs, nil
}

// Decide whether an SMTP code and short enhanced code is a reason for an
// immediate suppression listing. For some errors, we don't want to bother the
// remote mail server again, or they may decide our behaviour looks spammy.
func isImmedateBlock(code int, secode string) bool {
	switch code {
	case smtp.C521HostNoMail, // Host is not interested in accepting email at all.
		smtp.C550MailboxUnavail, // Likely mailbox does not exist.
		smtp.C551UserNotLocal,   // Also not interested in accepting email for this address.
		smtp.C553BadMailbox,     // We are sending a mailbox name that server doesn't understand and won't accept email for.
		smtp.C556DomainNoMail:   // Remote is not going to accept email for this address/domain.
		return true
	}
	if code/100 != 5 {
		return false
	}
	switch secode {
	case smtp.SeAddr1UnknownDestMailbox1, // Recipient localpart doesn't exist.
		smtp.SeAddr1UnknownSystem2,    // Bad recipient domain.
		smtp.SeAddr1MailboxSyntax3,    // Remote doesn't understand syntax.
		smtp.SeAddr1DestMailboxMoved6, // Address no longer exists.
		smtp.SeMailbox2Disabled1,      // Account exists at remote, but is disabled.
		smtp.SePol7DeliveryUnauth1:    // Seems popular for saying we are on a blocklist.
		return true
	}
	return false
}
