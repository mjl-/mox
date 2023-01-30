package store

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

// ErrNoJunkFilter indicates user did not configure/enable a junk filter.
var ErrNoJunkFilter = errors.New("junkfilter: not configured")

// OpenJunkFilter returns an opened junk filter for the account.
// If the account does not have a junk filter enabled, ErrNotConfigured is returned.
// Do not forget to save the filter after modifying, and to always close the filter when done.
// An empty filter is initialized on first access of the filter.
func (a *Account) OpenJunkFilter(log *mlog.Log) (*junk.Filter, *config.JunkFilter, error) {
	conf, ok := mox.Conf.Account(a.Name)
	if !ok {
		return nil, nil, ErrAccountUnknown
	}
	jf := conf.JunkFilter
	if jf == nil {
		return nil, jf, ErrNoJunkFilter
	}

	basePath := mox.DataDirPath("accounts")
	dbPath := filepath.Join(basePath, a.Name, "junkfilter.db")
	bloomPath := filepath.Join(basePath, a.Name, "junkfilter.bloom")

	if _, xerr := os.Stat(dbPath); xerr != nil && os.IsNotExist(xerr) {
		f, err := junk.NewFilter(log, jf.Params, dbPath, bloomPath)
		return f, jf, err
	}
	f, err := junk.OpenFilter(log, jf.Params, dbPath, bloomPath, false)
	return f, jf, err
}

// Train new messages, if relevant given their flags.
func (a *Account) Train(log *mlog.Log, msgs []Message) error {
	return a.xtrain(log, msgs, false, true)
}

// Untrain removed messages, if relevant given their flags.
func (a *Account) Untrain(log *mlog.Log, msgs []Message) error {
	return a.xtrain(log, msgs, true, false)
}

// train or untrain messages, if relevant given their flags.
func (a *Account) xtrain(log *mlog.Log, msgs []Message, untrain, train bool) (rerr error) {
	if len(msgs) == 0 {
		return nil
	}

	var jf *junk.Filter

	for _, m := range msgs {
		if !m.Seen && !m.Junk {
			continue
		}
		// Lazy open the junk filter.
		if jf == nil {
			var err error
			jf, _, err = a.OpenJunkFilter(log)
			if err != nil && errors.Is(err, ErrNoJunkFilter) {
				// No junk filter configured. Nothing more to do.
				return nil
			}
			defer func() {
				if jf != nil {
					err := jf.Close()
					if rerr == nil {
						rerr = err
					}
				}
			}()
		}
		ham := !m.Junk
		err := xtrainMessage(log, a, jf, m, untrain, ham, train, ham)
		if err != nil {
			return err
		}
	}
	return nil
}

// Retrain message, if relevant given old flags and the new flags in m.
func (a *Account) Retrain(log *mlog.Log, jf *junk.Filter, old Flags, m Message) error {
	untrain := old.Seen || old.Junk
	train := m.Seen || m.Junk
	untrainHam := !old.Junk
	trainHam := !m.Junk

	if !untrain && !train || (untrain && train && trainHam == untrainHam) {
		return nil
	}

	return xtrainMessage(log, a, jf, m, untrain, untrainHam, train, trainHam)
}

func xtrainMessage(log *mlog.Log, a *Account, jf *junk.Filter, m Message, untrain, untrainHam, train, trainHam bool) error {
	log.Info("updating junk filter", mlog.Field("untrain", untrain), mlog.Field("untrainHam", untrainHam), mlog.Field("train", train), mlog.Field("trainHam", trainHam))

	mr := a.MessageReader(m)
	defer mr.Close()

	p, err := m.LoadPart(mr)
	if err != nil {
		log.Errorx("loading part for message", err)
		return nil
	}

	words, err := jf.ParseMessage(p)
	if err != nil {
		log.Errorx("parsing message for updating junk filter", err, mlog.Field("parse", ""))
		return nil
	}

	if untrain {
		err := jf.Untrain(untrainHam, words)
		if err != nil {
			return err
		}
	}
	if train {
		err := jf.Train(trainHam, words)
		if err != nil {
			return err
		}
	}
	return nil
}
