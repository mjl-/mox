package junk

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/mjl-/mox/mlog"
)

var ctxbg = context.Background()

func tcheck(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", msg, err)
	}
}

func tlistdir(t *testing.T, name string) []string {
	t.Helper()
	l, err := os.ReadDir(name)
	tcheck(t, err, "readdir")
	names := make([]string, len(l))
	for i, e := range l {
		names[i] = e.Name()
	}
	return names
}

func TestFilter(t *testing.T) {
	log := mlog.New("junk", nil)
	params := Params{
		Onegrams:    true,
		Twograms:    true,
		Threegrams:  false,
		MaxPower:    0.1,
		TopWords:    10,
		IgnoreWords: 0.1,
		RareWords:   1,
	}
	dbPath := filepath.FromSlash("../testdata/junk/filter.db")
	bloomPath := filepath.FromSlash("../testdata/junk/filter.bloom")
	os.Remove(dbPath)
	os.Remove(bloomPath)
	f, err := NewFilter(ctxbg, log, params, dbPath, bloomPath)
	tcheck(t, err, "new filter")
	err = f.Close()
	tcheck(t, err, "close filter")

	f, err = OpenFilter(ctxbg, log, params, dbPath, bloomPath, true)
	tcheck(t, err, "open filter")

	// Ensure these dirs exist. Developers should bring their own ham/spam example
	// emails.
	os.MkdirAll("../testdata/train/ham", 0770)
	os.MkdirAll("../testdata/train/spam", 0770)

	hamdir := filepath.FromSlash("../testdata/train/ham")
	spamdir := filepath.FromSlash("../testdata/train/spam")
	hamfiles := tlistdir(t, hamdir)
	if len(hamfiles) > 100 {
		hamfiles = hamfiles[:100]
	}
	spamfiles := tlistdir(t, spamdir)
	if len(spamfiles) > 100 {
		spamfiles = spamfiles[:100]
	}

	err = f.TrainDirs(hamdir, "", spamdir, hamfiles, nil, spamfiles)
	tcheck(t, err, "train dirs")

	if len(hamfiles) == 0 || len(spamfiles) == 0 {
		fmt.Println("not training, no ham and/or spam messages, add them to testdata/train/ham and testdata/train/spam")
		return
	}

	prob, _, _, _, err := f.ClassifyMessagePath(ctxbg, filepath.Join(hamdir, hamfiles[0]))
	tcheck(t, err, "classify ham message")
	if prob > 0.1 {
		t.Fatalf("trained ham file has prob %v, expected <= 0.1", prob)
	}

	prob, _, _, _, err = f.ClassifyMessagePath(ctxbg, filepath.Join(spamdir, spamfiles[0]))
	tcheck(t, err, "classify spam message")
	if prob < 0.9 {
		t.Fatalf("trained spam file has prob %v, expected > 0.9", prob)
	}

	err = f.Close()
	tcheck(t, err, "close filter")

	// Start again with empty filter. We'll train a few messages and check they are
	// classified as ham/spam. Then we untrain to see they are no longer classified.
	os.Remove(dbPath)
	os.Remove(bloomPath)
	f, err = NewFilter(ctxbg, log, params, dbPath, bloomPath)
	tcheck(t, err, "open filter")

	hamf, err := os.Open(filepath.Join(hamdir, hamfiles[0]))
	tcheck(t, err, "open hamfile")
	defer hamf.Close()
	hamstat, err := hamf.Stat()
	tcheck(t, err, "stat hamfile")
	hamsize := hamstat.Size()

	spamf, err := os.Open(filepath.Join(spamdir, spamfiles[0]))
	tcheck(t, err, "open spamfile")
	defer spamf.Close()
	spamstat, err := spamf.Stat()
	tcheck(t, err, "stat spamfile")
	spamsize := spamstat.Size()

	// Train each message twice, to prevent single occurrences from being ignored.
	err = f.TrainMessage(ctxbg, hamf, hamsize, true)
	tcheck(t, err, "train ham message")
	_, err = hamf.Seek(0, 0)
	tcheck(t, err, "seek ham message")
	err = f.TrainMessage(ctxbg, hamf, hamsize, true)
	tcheck(t, err, "train ham message")

	err = f.TrainMessage(ctxbg, spamf, spamsize, false)
	tcheck(t, err, "train spam message")
	_, err = spamf.Seek(0, 0)
	tcheck(t, err, "seek spam message")
	err = f.TrainMessage(ctxbg, spamf, spamsize, true)
	tcheck(t, err, "train spam message")

	if !f.modified {
		t.Fatalf("filter not modified after training")
	}
	if !f.bloom.Modified() {
		t.Fatalf("bloom filter not modified after training")
	}

	err = f.Save()
	tcheck(t, err, "save filter")
	if f.modified || f.bloom.Modified() {
		t.Fatalf("filter or bloom filter still modified after save")
	}

	// Classify and verify.
	_, err = hamf.Seek(0, 0)
	tcheck(t, err, "seek ham message")
	prob, _, _, _, err = f.ClassifyMessageReader(ctxbg, hamf, hamsize)
	tcheck(t, err, "classify ham")
	if prob > 0.1 {
		t.Fatalf("got prob %v, expected <= 0.1", prob)
	}

	_, err = spamf.Seek(0, 0)
	tcheck(t, err, "seek spam message")
	prob, _, _, _, err = f.ClassifyMessageReader(ctxbg, spamf, spamsize)
	tcheck(t, err, "classify spam")
	if prob < 0.9 {
		t.Fatalf("got prob %v, expected >= 0.9", prob)
	}

	// Untrain ham & spam.
	_, err = hamf.Seek(0, 0)
	tcheck(t, err, "seek ham message")
	err = f.UntrainMessage(ctxbg, hamf, hamsize, true)
	tcheck(t, err, "untrain ham message")
	_, err = hamf.Seek(0, 0)
	tcheck(t, err, "seek ham message")
	err = f.UntrainMessage(ctxbg, hamf, spamsize, true)
	tcheck(t, err, "untrain ham message")

	_, err = spamf.Seek(0, 0)
	tcheck(t, err, "seek spam message")
	err = f.UntrainMessage(ctxbg, spamf, spamsize, true)
	tcheck(t, err, "untrain spam message")
	_, err = spamf.Seek(0, 0)
	tcheck(t, err, "seek spam message")
	err = f.UntrainMessage(ctxbg, spamf, spamsize, true)
	tcheck(t, err, "untrain spam message")

	if !f.modified {
		t.Fatalf("filter not modified after untraining")
	}

	// Classify again, should be unknown.
	_, err = hamf.Seek(0, 0)
	tcheck(t, err, "seek ham message")
	prob, _, _, _, err = f.ClassifyMessageReader(ctxbg, hamf, hamsize)
	tcheck(t, err, "classify ham")
	if math.Abs(prob-0.5) > 0.1 {
		t.Fatalf("got prob %v, expected 0.5 +-0.1", prob)
	}

	_, err = spamf.Seek(0, 0)
	tcheck(t, err, "seek spam message")
	prob, _, _, _, err = f.ClassifyMessageReader(ctxbg, spamf, spamsize)
	tcheck(t, err, "classify spam")
	if math.Abs(prob-0.5) > 0.1 {
		t.Fatalf("got prob %v, expected 0.5 +-0.1", prob)
	}

	err = f.Close()
	tcheck(t, err, "close filter")
}
