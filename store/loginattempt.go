package store

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var loginAttemptsMaxPerAccount = 10 * 1000 // Lower during tests.

// LoginAttempt is a successful or failed login attempt, stored for auditing
// purposes.
//
// At most 10000 failed attempts are stored per account, to prevent unbounded
// growth of the database by third parties.
type LoginAttempt struct {
	// Hash of all fields after "Count" below. We store a single entry per key,
	// updating its Last and Count fields.
	Key []byte

	// Last has an index for efficient removal of entries after 30 days.
	Last  time.Time `bstore:"nonzero,default now,index"`
	First time.Time `bstore:"nonzero,default now"`
	Count int64     // Number of login attempts for the combination of fields below.

	// Admin logins use "(admin)". If no account is known, "-" is used.
	// AccountName has an index for efficiently removing failed login attempts at the
	// end of the list when there are too many, and for efficiently removing all records
	// for an account.
	AccountName string `bstore:"index AccountName+Last"`

	LoginAddress         string // Empty for attempts to login in as admin.
	RemoteIP             string
	LocalIP              string
	TLS                  string // Empty if no TLS, otherwise contains version, algorithm, properties, etc.
	TLSPubKeyFingerprint string
	Protocol             string // "submission", "imap", "webmail", "webaccount", "webadmin"
	UserAgent            string // From HTTP header, or IMAP ID command.
	AuthMech             string // "plain", "login", "cram-md5", "scram-sha-256-plus", "(unrecognized)", etc
	Result               AuthResult

	log mlog.Log // For passing the logger to the goroutine that writes and logs.
}

func (a LoginAttempt) calculateKey() []byte {
	h := sha256.New()
	l := []string{
		a.AccountName,
		a.LoginAddress,
		a.RemoteIP,
		a.LocalIP,
		a.TLS,
		a.TLSPubKeyFingerprint,
		a.Protocol,
		a.UserAgent,
		a.AuthMech,
		string(a.Result),
	}
	// We don't add field separators. It allows us to add fields in the future that are
	// empty by default without changing existing keys.
	for _, s := range l {
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// LoginAttemptState keeps track of the number of failed LoginAttempt records
// per account. For efficiently removing records beyond 10000.
type LoginAttemptState struct {
	AccountName string // "-" is used when no account is present, for unknown addresses.

	// Number of LoginAttempt records for login failures. For preventing unbounded
	// growth of logs.
	RecordsFailed int
}

// AuthResult is the result of a login attempt.
type AuthResult string

const (
	AuthSuccess           AuthResult = "ok"
	AuthBadUser           AuthResult = "baduser"
	AuthBadPassword       AuthResult = "badpassword"
	AuthBadCredentials    AuthResult = "badcreds"
	AuthBadChannelBinding AuthResult = "badchanbind"
	AuthBadProtocol       AuthResult = "badprotocol"
	AuthLoginDisabled     AuthResult = "logindisabled"
	AuthError             AuthResult = "error"
	AuthAborted           AuthResult = "aborted"
)

var writeLoginAttempt chan LoginAttempt
var writeLoginAttemptStop chan chan struct{}

func startLoginAttemptWriter() {
	writeLoginAttempt = make(chan LoginAttempt, 100)
	writeLoginAttemptStop = make(chan chan struct{})

	process := func(la *LoginAttempt) {
		var l []LoginAttempt
		if la != nil {
			l = []LoginAttempt{*la}
		}
		// Gather all that we can write now.
	All:
		for {
			select {
			case xla := <-writeLoginAttempt:
				l = append(l, xla)
			default:
				break All
			}
		}

		if len(l) > 0 {
			loginAttemptWrite(l...)
		}
	}

	go func() {
		defer func() {
			x := recover()
			if x == nil {
				return
			}

			mlog.New("store", nil).Error("unhandled panic in LoginAttemptAdd", slog.Any("err", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Store)
		}()

		for {
			select {
			case stopc := <-writeLoginAttemptStop:
				process(nil)
				stopc <- struct{}{}
				return

			case la := <-writeLoginAttempt:
				process(&la)
			}
		}
	}()
}

// LoginAttemptAdd logs a login attempt (with result), and upserts it in the
// database and possibly cleans up old entries in the database.
//
// Use account name "(admin)" for admin logins.
//
// Writes are done in a background routine, unless we are shutting down or when
// there are many pending writes.
func LoginAttemptAdd(ctx context.Context, log mlog.Log, a LoginAttempt) {
	metrics.AuthenticationInc(a.Protocol, a.AuthMech, string(a.Result))

	a.log = log
	// Send login attempt to writer. Only blocks if there are lots of login attempts.
	writeLoginAttempt <- a
}

func loginAttemptWrite(l ...LoginAttempt) {
	// Log on the way out, for "count" fetched from database.
	defer func() {
		for _, a := range l {
			if a.AuthMech == "websession" {
				// Prevent superfluous logging.
				continue
			}

			a.log.Info("login attempt",
				slog.String("address", a.LoginAddress),
				slog.String("account", a.AccountName),
				slog.String("protocol", a.Protocol),
				slog.String("authmech", a.AuthMech),
				slog.String("result", string(a.Result)),
				slog.String("remoteip", a.RemoteIP),
				slog.String("localip", a.LocalIP),
				slog.String("tls", a.TLS),
				slog.String("useragent", a.UserAgent),
				slog.String("tlspubkeyfp", a.TLSPubKeyFingerprint),
				slog.Int64("count", a.Count),
			)
		}
	}()

	for i := range l {
		if l[i].AccountName == "" {
			l[i].AccountName = "-"
		}
		l[i].Key = l[i].calculateKey()
	}

	err := AuthDB.Write(context.Background(), func(tx *bstore.Tx) error {
		for i := range l {
			err := loginAttemptWriteTx(tx, &l[i])
			l[i].log.Check(err, "adding login attempt")
		}
		return nil
	})
	l[0].log.Check(err, "storing login attempt")
}

func loginAttemptWriteTx(tx *bstore.Tx, a *LoginAttempt) error {
	xa := LoginAttempt{Key: a.Key}
	var insert bool
	if err := tx.Get(&xa); err == bstore.ErrAbsent {
		a.First = time.Time{}
		a.Count = 1
		insert = true
		if err := tx.Insert(a); err != nil {
			return fmt.Errorf("inserting login attempt: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("get loginattempt: %v", err)
	} else {
		log := a.log
		last := a.Last
		*a = xa
		a.log = log
		a.Last = last
		if a.Last.IsZero() {
			a.Last = time.Now()
		}
		a.Count++
		if err := tx.Update(a); err != nil {
			return fmt.Errorf("updating login attempt: %v", err)
		}
	}

	// Update state with its RecordsFailed.
	origstate := LoginAttemptState{AccountName: a.AccountName}
	var newstate bool
	if err := tx.Get(&origstate); err == bstore.ErrAbsent {
		newstate = true
	} else if err != nil {
		return fmt.Errorf("get login attempt state: %v", err)
	}
	state := origstate
	if insert && a.Result != AuthSuccess {
		state.RecordsFailed++
	}

	if state.RecordsFailed > loginAttemptsMaxPerAccount {
		q := bstore.QueryTx[LoginAttempt](tx)
		q.FilterNonzero(LoginAttempt{AccountName: a.AccountName})
		q.FilterNotEqual("Result", AuthSuccess)
		q.SortAsc("Last")
		q.Limit(state.RecordsFailed - loginAttemptsMaxPerAccount)
		if n, err := q.Delete(); err != nil {
			return fmt.Errorf("deleting too many failed login attempts: %v", err)
		} else {
			state.RecordsFailed -= n
		}
	}

	if state == origstate {
		return nil
	}
	if newstate {
		if err := tx.Insert(&state); err != nil {
			return fmt.Errorf("inserting login attempt state: %v", err)
		}
		return nil
	}
	if err := tx.Update(&state); err != nil {
		return fmt.Errorf("updating login attempt state: %v", err)
	}
	return nil
}

// LoginAttemptCleanup removes any LoginAttempt entries older than 30 days, for
// all accounts.
func LoginAttemptCleanup(ctx context.Context) error {
	return AuthDB.Write(ctx, func(tx *bstore.Tx) error {
		var removed []LoginAttempt
		q := bstore.QueryTx[LoginAttempt](tx)
		q.FilterLess("Last", time.Now().Add(-30*24*time.Hour))
		q.Gather(&removed)
		_, err := q.Delete()
		if err != nil {
			return fmt.Errorf("deleting old login attempts: %v", err)
		}

		deleted := map[string]int{}
		for _, r := range removed {
			if r.Result != AuthSuccess {
				deleted[r.AccountName]++
			}
		}

		for accName, n := range deleted {
			state := LoginAttemptState{AccountName: accName}
			if err := tx.Get(&state); err != nil {
				return fmt.Errorf("get login attempt state for account %v: %v", accName, err)
			}
			state.RecordsFailed -= n
			if err := tx.Update(&state); err != nil {
				return fmt.Errorf("update login attempt state for account %v: %v", accName, err)
			}
		}

		return nil
	})
}

// loginAttemptRemoveAccount removes all LoginAttempt records for an account
// (value must be non-empty).
func loginAttemptRemoveAccount(tx *bstore.Tx, accountName string) error {
	q := bstore.QueryTx[LoginAttempt](tx)
	q.FilterNonzero(LoginAttempt{AccountName: accountName})
	_, err := q.Delete()
	return err
}

// LoginAttemptList returns LoginAttempt records for the accountName. If
// accountName is empty, all records are returned. Use "(admin)" for admin
// logins. Use "-" for login attempts for which no account was found.
// If limit is greater than 0, at most limit records, most recent first, are returned.
func LoginAttemptList(ctx context.Context, accountName string, limit int) ([]LoginAttempt, error) {
	var l []LoginAttempt
	err := AuthDB.Read(ctx, func(tx *bstore.Tx) error {
		q := bstore.QueryTx[LoginAttempt](tx)
		if accountName != "" {
			q.FilterNonzero(LoginAttempt{AccountName: accountName})
		}
		q.SortDesc("Last")
		if limit > 0 {
			q.Limit(limit)
		}
		var err error
		l, err = q.List()
		return err
	})
	return l, err
}

// LoginAttemptTLS returns a string for use as LoginAttempt.TLS. Returns an empty
// string if "c" is not a TLS connection.
func LoginAttemptTLS(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}

	version, ciphersuite := moxio.TLSInfo(*state)
	return fmt.Sprintf("version=%s ciphersuite=%s sni=%s resumed=%v alpn=%s",
		version,
		ciphersuite,
		state.ServerName,
		state.DidResume,
		state.NegotiatedProtocol)
}
