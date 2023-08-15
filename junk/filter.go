// Package junk implements a bayesian spam filter.
//
// A message can be parsed into words. Words (or pairs or triplets) can be used
// to train the filter or to classify the message as ham or spam.  Training
// records the words in the database as ham/spam. Classifying consists of
// calculating the ham/spam probability by combining the words in the message
// with their ham/spam status.
package junk

// todo: look at inverse chi-square function? see https://www.linuxjournal.com/article/6467
// todo: perhaps: whether anchor text in links in html are different from the url

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
)

var (
	xlog = mlog.New("junk")

	// errBadContentType = errors.New("bad content-type") // sure sign of spam, todo: use this error
	errClosed = errors.New("filter is closed")
)

type word struct {
	Ham  uint32
	Spam uint32
}

type wordscore struct {
	Word string
	Ham  uint32
	Spam uint32
}

// Params holds parameters for the filter. Most are at test-time. The first are
// used during parsing and training.
type Params struct {
	Onegrams    bool    `sconf:"optional" sconf-doc:"Track ham/spam ranking for single words."`
	Twograms    bool    `sconf:"optional" sconf-doc:"Track ham/spam ranking for each two consecutive words."`
	Threegrams  bool    `sconf:"optional" sconf-doc:"Track ham/spam ranking for each three consecutive words."`
	MaxPower    float64 `sconf-doc:"Maximum power a word (combination) can have. If spaminess is 0.99, and max power is 0.1, spaminess of the word will be set to 0.9. Similar for ham words."`
	TopWords    int     `sconf-doc:"Number of most spammy/hammy words to use for calculating probability. E.g. 10."`
	IgnoreWords float64 `sconf:"optional" sconf-doc:"Ignore words that are this much away from 0.5 haminess/spaminess. E.g. 0.1, causing word (combinations) of 0.4 to 0.6 to be ignored."`
	RareWords   int     `sconf:"optional" sconf-doc:"Occurrences in word database until a word is considered rare and its influence in calculating probability reduced. E.g. 1 or 2."`
}

var DBTypes = []any{wordscore{}} // Stored in DB.

type Filter struct {
	Params

	log               *mlog.Log // For logging cid.
	closed            bool
	modified          bool            // Whether any modifications are pending. Cleared by Save.
	hams, spams       uint32          // Message count, stored in db under word "-".
	cache             map[string]word // Words read from database or during training.
	changed           map[string]word // Words modified during training.
	dbPath, bloomPath string
	db                *bstore.DB // Always open on a filter.
	bloom             *Bloom     // Only opened when writing.
	isNew             bool       // Set for new filters until their first sync to disk. For faster writing.
}

func (f *Filter) ensureBloom() error {
	if f.bloom != nil {
		return nil
	}
	var err error
	f.bloom, err = openBloom(f.bloomPath)
	return err
}

// CloseDiscard closes the filter, discarding any changes.
func (f *Filter) CloseDiscard() error {
	if f.closed {
		return errClosed
	}
	err := f.db.Close()
	*f = Filter{log: f.log, closed: true}
	return err
}

// Close first saves the filter if it has modifications, then closes the database
// connection and releases the bloom filter.
func (f *Filter) Close() error {
	if f.closed {
		return errClosed
	}
	var err error
	if f.modified {
		err = f.Save()
	}
	if err != nil {
		f.db.Close()
	} else {
		err = f.db.Close()
	}
	*f = Filter{log: f.log, closed: true}
	return err
}

func OpenFilter(ctx context.Context, log *mlog.Log, params Params, dbPath, bloomPath string, loadBloom bool) (*Filter, error) {
	var bloom *Bloom
	if loadBloom {
		var err error
		bloom, err = openBloom(bloomPath)
		if err != nil {
			return nil, err
		}
	} else if fi, err := os.Stat(bloomPath); err == nil {
		if err := BloomValid(int(fi.Size()), bloomK); err != nil {
			return nil, fmt.Errorf("bloom: %s", err)
		}
	}

	db, err := openDB(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %s", err)
	}

	f := &Filter{
		Params:    params,
		log:       log,
		cache:     map[string]word{},
		changed:   map[string]word{},
		dbPath:    dbPath,
		bloomPath: bloomPath,
		db:        db,
		bloom:     bloom,
	}
	err = f.db.Read(ctx, func(tx *bstore.Tx) error {
		wc := wordscore{Word: "-"}
		err := tx.Get(&wc)
		f.hams = wc.Ham
		f.spams = wc.Spam
		return err
	})
	if err != nil {
		cerr := f.Close()
		log.Check(cerr, "closing filter after error")
		return nil, fmt.Errorf("looking up ham/spam message count: %s", err)
	}
	return f, nil
}

// NewFilter creates a new filter with empty bloom filter and database files. The
// filter is marked as new until the first save, will be done automatically if
// TrainDirs is called. If the bloom and/or database files exist, an error is
// returned.
func NewFilter(ctx context.Context, log *mlog.Log, params Params, dbPath, bloomPath string) (*Filter, error) {
	var err error
	if _, err := os.Stat(bloomPath); err == nil {
		return nil, fmt.Errorf("bloom filter already exists on disk: %s", bloomPath)
	} else if _, err := os.Stat(dbPath); err == nil {
		return nil, fmt.Errorf("database file already exists on disk: %s", dbPath)
	}

	bloomSizeBytes := 4 * 1024 * 1024
	if err := BloomValid(bloomSizeBytes, bloomK); err != nil {
		return nil, fmt.Errorf("bloom: %s", err)
	}
	bf, err := os.Create(bloomPath)
	if err != nil {
		return nil, fmt.Errorf("creating bloom file: %w", err)
	}
	if err := bf.Truncate(4 * 1024 * 1024); err != nil {
		xerr := bf.Close()
		log.Check(xerr, "closing bloom filter file after truncate error")
		xerr = os.Remove(bloomPath)
		log.Check(xerr, "removing bloom filter file after truncate error")
		return nil, fmt.Errorf("making empty bloom filter: %s", err)
	}
	err = bf.Close()
	log.Check(err, "closing bloomfilter file")

	db, err := newDB(ctx, log, dbPath)
	if err != nil {
		xerr := os.Remove(bloomPath)
		log.Check(xerr, "removing bloom filter file after db init error")
		xerr = os.Remove(dbPath)
		log.Check(xerr, "removing database file after db init error")
		return nil, fmt.Errorf("open database: %s", err)
	}

	words := map[string]word{} // f.changed is set to new map after training
	f := &Filter{
		Params:    params,
		log:       log,
		modified:  true, // Ensure ham/spam message count is added for new filter.
		cache:     words,
		changed:   words,
		dbPath:    dbPath,
		bloomPath: bloomPath,
		db:        db,
		isNew:     true,
	}
	return f, nil
}

const bloomK = 10

func openBloom(path string) (*Bloom, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bloom file: %w", err)
	}
	return NewBloom(buf, bloomK)
}

func newDB(ctx context.Context, log *mlog.Log, path string) (db *bstore.DB, rerr error) {
	// Remove any existing files.
	os.Remove(path)

	defer func() {
		if rerr != nil {
			err := os.Remove(path)
			log.Check(err, "removing db file after init error")
		}
	}()

	db, err := bstore.Open(ctx, path, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
	if err != nil {
		return nil, fmt.Errorf("open new database: %w", err)
	}
	return db, nil
}

func openDB(ctx context.Context, path string) (*bstore.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("stat db file: %w", err)
	}
	return bstore.Open(ctx, path, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, DBTypes...)
}

// Save stores modifications, e.g. from training, to the database and bloom
// filter files.
func (f *Filter) Save() error {
	if f.closed {
		return errClosed
	}
	if !f.modified {
		return nil
	}

	if f.bloom != nil && f.bloom.Modified() {
		if err := f.bloom.Write(f.bloomPath); err != nil {
			return fmt.Errorf("writing bloom filter: %w", err)
		}
	}

	// We need to insert sequentially for reasonable performance.
	words := make([]string, len(f.changed))
	i := 0
	for w := range f.changed {
		words[i] = w
		i++
	}
	sort.Slice(words, func(i, j int) bool {
		return words[i] < words[j]
	})

	f.log.Debug("inserting words in junkfilter db", mlog.Field("words", len(f.changed)))
	// start := time.Now()
	if f.isNew {
		if err := f.db.HintAppend(true, wordscore{}); err != nil {
			f.log.Errorx("hint appendonly", err)
		} else {
			defer func() {
				err := f.db.HintAppend(false, wordscore{})
				f.log.Check(err, "restoring append hint")
			}()
		}
	}
	err := f.db.Write(context.Background(), func(tx *bstore.Tx) error {
		update := func(w string, ham, spam uint32) error {
			if f.isNew {
				return tx.Insert(&wordscore{w, ham, spam})
			}

			wc := wordscore{w, 0, 0}
			err := tx.Get(&wc)
			if err == bstore.ErrAbsent {
				return tx.Insert(&wordscore{w, ham, spam})
			} else if err != nil {
				return err
			}
			return tx.Update(&wordscore{w, wc.Ham + ham, wc.Spam + spam})
		}
		if err := update("-", f.hams, f.spams); err != nil {
			return fmt.Errorf("storing total ham/spam message count: %s", err)
		}

		for _, w := range words {
			c := f.changed[w]
			if err := update(w, c.Ham, c.Spam); err != nil {
				return fmt.Errorf("updating ham/spam count: %s", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("updating database: %w", err)
	}

	f.changed = map[string]word{}
	f.modified = false
	f.isNew = false
	// f.log.Info("wrote filter to db", mlog.Field("duration", time.Since(start)))
	return nil
}

func loadWords(ctx context.Context, db *bstore.DB, l []string, dst map[string]word) error {
	sort.Slice(l, func(i, j int) bool {
		return l[i] < l[j]
	})

	err := db.Read(ctx, func(tx *bstore.Tx) error {
		for _, w := range l {
			wc := wordscore{Word: w}
			if err := tx.Get(&wc); err == nil {
				dst[w] = word{wc.Ham, wc.Spam}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("fetching words: %s", err)
	}
	return nil
}

// ClassifyWords returns the spam probability for the given words, and number of recognized ham and spam words.
func (f *Filter) ClassifyWords(ctx context.Context, words map[string]struct{}) (probability float64, nham, nspam int, rerr error) {
	if f.closed {
		return 0, 0, 0, errClosed
	}

	type xword struct {
		Word string
		R    float64
	}

	var hamHigh float64 = 0
	var spamLow float64 = 1
	var topHam []xword
	var topSpam []xword

	// Find words that should be in the database.
	lookupWords := []string{}
	expect := map[string]struct{}{}
	unknowns := map[string]struct{}{}
	totalUnknown := 0
	for w := range words {
		if f.bloom != nil && !f.bloom.Has(w) {
			totalUnknown++
			if len(unknowns) < 50 {
				unknowns[w] = struct{}{}
			}
			continue
		}
		if _, ok := f.cache[w]; ok {
			continue
		}
		lookupWords = append(lookupWords, w)
		expect[w] = struct{}{}
	}
	if len(unknowns) > 0 {
		f.log.Debug("unknown words in bloom filter, showing max 50", mlog.Field("words", unknowns), mlog.Field("totalunknown", totalUnknown), mlog.Field("totalwords", len(words)))
	}

	// Fetch words from database.
	fetched := map[string]word{}
	if len(lookupWords) > 0 {
		if err := loadWords(ctx, f.db, lookupWords, fetched); err != nil {
			return 0, 0, 0, err
		}
		for w, c := range fetched {
			delete(expect, w)
			f.cache[w] = c
		}
		f.log.Debug("unknown words in db", mlog.Field("words", expect), mlog.Field("totalunknown", len(expect)), mlog.Field("totalwords", len(words)))
	}

	for w := range words {
		c, ok := f.cache[w]
		if !ok {
			continue
		}
		var wS, wH float64
		if f.spams > 0 {
			wS = float64(c.Spam) / float64(f.spams)
		}
		if f.hams > 0 {
			wH = float64(c.Ham) / float64(f.hams)
		}
		r := wS / (wS + wH)

		if r < f.MaxPower {
			r = f.MaxPower
		} else if r >= 1-f.MaxPower {
			r = 1 - f.MaxPower
		}

		if c.Ham+c.Spam <= uint32(f.RareWords) {
			// Reduce the power of rare words.
			r += float64(1+uint32(f.RareWords)-(c.Ham+c.Spam)) * (0.5 - r) / 10
		}
		if math.Abs(0.5-r) < f.IgnoreWords {
			continue
		}
		if r < 0.5 {
			if len(topHam) >= f.TopWords && r > hamHigh {
				continue
			}
			topHam = append(topHam, xword{w, r})
			if r > hamHigh {
				hamHigh = r
			}
		} else if r > 0.5 {
			if len(topSpam) >= f.TopWords && r < spamLow {
				continue
			}
			topSpam = append(topSpam, xword{w, r})
			if r < spamLow {
				spamLow = r
			}
		}
	}

	sort.Slice(topHam, func(i, j int) bool {
		a, b := topHam[i], topHam[j]
		if a.R == b.R {
			return len(a.Word) > len(b.Word)
		}
		return a.R < b.R
	})
	sort.Slice(topSpam, func(i, j int) bool {
		a, b := topSpam[i], topSpam[j]
		if a.R == b.R {
			return len(a.Word) > len(b.Word)
		}
		return a.R > b.R
	})

	nham = f.TopWords
	if nham > len(topHam) {
		nham = len(topHam)
	}
	nspam = f.TopWords
	if nspam > len(topSpam) {
		nspam = len(topSpam)
	}
	topHam = topHam[:nham]
	topSpam = topSpam[:nspam]

	var eta float64
	for _, x := range topHam {
		eta += math.Log(1-x.R) - math.Log(x.R)
	}
	for _, x := range topSpam {
		eta += math.Log(1-x.R) - math.Log(x.R)
	}

	f.log.Debug("top words", mlog.Field("hams", topHam), mlog.Field("spams", topSpam))

	prob := 1 / (1 + math.Pow(math.E, eta))
	return prob, len(topHam), len(topSpam), nil
}

// ClassifyMessagePath is a convenience wrapper for calling ClassifyMessage on a file.
func (f *Filter) ClassifyMessagePath(ctx context.Context, path string) (probability float64, words map[string]struct{}, nham, nspam int, rerr error) {
	if f.closed {
		return 0, nil, 0, 0, errClosed
	}

	mf, err := os.Open(path)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	defer func() {
		err := mf.Close()
		f.log.Check(err, "closing file after classify")
	}()
	fi, err := mf.Stat()
	if err != nil {
		return 0, nil, 0, 0, err
	}
	return f.ClassifyMessageReader(ctx, mf, fi.Size())
}

func (f *Filter) ClassifyMessageReader(ctx context.Context, mf io.ReaderAt, size int64) (probability float64, words map[string]struct{}, nham, nspam int, rerr error) {
	m, err := message.EnsurePart(f.log, false, mf, size)
	if err != nil && errors.Is(err, message.ErrBadContentType) {
		// Invalid content-type header is a sure sign of spam.
		//f.log.Infox("parsing content", err)
		return 1, nil, 0, 0, nil
	}
	return f.ClassifyMessage(ctx, m)
}

// ClassifyMessage parses the mail message in r and returns the spam probability
// (between 0 and 1), along with the tokenized words found in the message, and the
// number of recognized ham and spam words.
func (f *Filter) ClassifyMessage(ctx context.Context, m message.Part) (probability float64, words map[string]struct{}, nham, nspam int, rerr error) {
	var err error
	words, err = f.ParseMessage(m)
	if err != nil {
		return 0, nil, 0, 0, err
	}

	probability, nham, nspam, err = f.ClassifyWords(ctx, words)
	return probability, words, nham, nspam, err
}

// Train adds the words of a single message to the filter.
func (f *Filter) Train(ctx context.Context, ham bool, words map[string]struct{}) error {
	if err := f.ensureBloom(); err != nil {
		return err
	}

	var lwords []string

	for w := range words {
		if !f.bloom.Has(w) {
			f.bloom.Add(w)
			continue
		}
		if _, ok := f.cache[w]; !ok {
			lwords = append(lwords, w)
		}
	}

	if err := f.loadCache(ctx, lwords); err != nil {
		return err
	}

	f.modified = true
	if ham {
		f.hams++
	} else {
		f.spams++
	}

	for w := range words {
		c := f.cache[w]
		if ham {
			c.Ham++
		} else {
			c.Spam++
		}
		f.cache[w] = c
		f.changed[w] = c
	}
	return nil
}

func (f *Filter) TrainMessage(ctx context.Context, r io.ReaderAt, size int64, ham bool) error {
	p, _ := message.EnsurePart(f.log, false, r, size)
	words, err := f.ParseMessage(p)
	if err != nil {
		return fmt.Errorf("parsing mail contents: %v", err)
	}
	return f.Train(ctx, ham, words)
}

func (f *Filter) UntrainMessage(ctx context.Context, r io.ReaderAt, size int64, ham bool) error {
	p, _ := message.EnsurePart(f.log, false, r, size)
	words, err := f.ParseMessage(p)
	if err != nil {
		return fmt.Errorf("parsing mail contents: %v", err)
	}
	return f.Untrain(ctx, ham, words)
}

func (f *Filter) loadCache(ctx context.Context, lwords []string) error {
	if len(lwords) == 0 {
		return nil
	}

	return loadWords(ctx, f.db, lwords, f.cache)
}

// Untrain adjusts the filter to undo a previous training of the words.
func (f *Filter) Untrain(ctx context.Context, ham bool, words map[string]struct{}) error {
	if err := f.ensureBloom(); err != nil {
		return err
	}

	// Lookup any words from the db that aren't in the cache and put them in the cache for modification.
	var lwords []string
	for w := range words {
		if _, ok := f.cache[w]; !ok {
			lwords = append(lwords, w)
		}
	}
	if err := f.loadCache(ctx, lwords); err != nil {
		return err
	}

	// Modify the message count.
	f.modified = true
	if ham {
		f.hams--
	} else {
		f.spams--
	}

	// Decrease the word counts.
	for w := range words {
		c, ok := f.cache[w]
		if !ok {
			continue
		}
		if ham {
			c.Ham--
		} else {
			c.Spam--
		}
		f.cache[w] = c
		f.changed[w] = c
	}
	return nil
}

// TrainDir parses mail messages from files and trains the filter.
func (f *Filter) TrainDir(dir string, files []string, ham bool) (n, malformed uint32, rerr error) {
	if f.closed {
		return 0, 0, errClosed
	}
	if err := f.ensureBloom(); err != nil {
		return 0, 0, err
	}

	for _, name := range files {
		p := fmt.Sprintf("%s/%s", dir, name)
		valid, words, err := f.tokenizeMail(p)
		if err != nil {
			// f.log.Infox("tokenizing mail", err, mlog.Field("path", p))
			malformed++
			continue
		}
		if !valid {
			continue
		}
		n++
		for w := range words {
			if !f.bloom.Has(w) {
				f.bloom.Add(w)
				continue
			}
			c := f.cache[w]
			f.modified = true
			if ham {
				c.Ham++
			} else {
				c.Spam++
			}
			f.cache[w] = c
			f.changed[w] = c
		}
	}
	return
}

// TrainDirs trains and saves a filter with mail messages from different types
// of directories.
func (f *Filter) TrainDirs(hamDir, sentDir, spamDir string, hamFiles, sentFiles, spamFiles []string) error {
	if f.closed {
		return errClosed
	}

	var err error

	var start time.Time
	var hamMalformed, sentMalformed, spamMalformed uint32

	start = time.Now()
	f.hams, hamMalformed, err = f.TrainDir(hamDir, hamFiles, true)
	if err != nil {
		return err
	}
	tham := time.Since(start)

	var sent uint32
	start = time.Now()
	if sentDir != "" {
		sent, sentMalformed, err = f.TrainDir(sentDir, sentFiles, true)
		if err != nil {
			return err
		}
	}
	tsent := time.Since(start)

	start = time.Now()
	f.spams, spamMalformed, err = f.TrainDir(spamDir, spamFiles, false)
	if err != nil {
		return err
	}
	tspam := time.Since(start)

	hams := f.hams
	f.hams += sent
	if err := f.Save(); err != nil {
		return fmt.Errorf("saving filter: %s", err)
	}

	dbSize := f.fileSize(f.dbPath)
	bloomSize := f.fileSize(f.bloomPath)

	fields := []mlog.Pair{
		mlog.Field("hams", hams),
		mlog.Field("hamtime", tham),
		mlog.Field("hammalformed", hamMalformed),
		mlog.Field("sent", sent),
		mlog.Field("senttime", tsent),
		mlog.Field("sentmalformed", sentMalformed),
		mlog.Field("spams", f.spams),
		mlog.Field("spamtime", tspam),
		mlog.Field("spammalformed", spamMalformed),
		mlog.Field("dbsize", fmt.Sprintf("%.1fmb", float64(dbSize)/(1024*1024))),
		mlog.Field("bloomsize", fmt.Sprintf("%.1fmb", float64(bloomSize)/(1024*1024))),
		mlog.Field("bloom1ratio", fmt.Sprintf("%.4f", float64(f.bloom.Ones())/float64(len(f.bloom.Bytes())*8))),
	}
	xlog.Print("training done", fields...)

	return nil
}

func (f *Filter) fileSize(p string) int {
	fi, err := os.Stat(p)
	if err != nil {
		f.log.Infox("stat", err, mlog.Field("path", p))
		return 0
	}
	return int(fi.Size())
}

// DB returns the database, for backups.
func (f *Filter) DB() *bstore.DB {
	return f.db
}
