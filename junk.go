package main

/*
note: these testdata paths are not in the repo, you should gather some of your
own ham/spam emails.

./mox junk train testdata/train/ham testdata/train/spam
./mox junk train -sent-dir testdata/sent testdata/train/ham testdata/train/spam
./mox junk check 'testdata/check/ham/mail1'
./mox junk test testdata/check/ham testdata/check/spam
./mox junk analyze testdata/train/ham testdata/train/spam
./mox junk analyze -top-words 10 -train-ratio 0.5 -spam-threshold 0.85 -max-power 0.01 -sent-dir testdata/sent testdata/train/ham testdata/train/spam
./mox junk play -top-words 10 -train-ratio 0.5 -spam-threshold 0.85 -max-power 0.01 -sent-dir testdata/sent testdata/train/ham testdata/train/spam
*/

import (
	"context"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"
	"sort"
	"time"

	"github.com/mjl-/mox/junk"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
)

type junkArgs struct {
	params                        junk.Params
	spamThreshold                 float64
	trainRatio                    float64
	seed                          bool
	sentDir                       string
	databasePath, bloomfilterPath string
	debug                         bool
}

func (a junkArgs) SetLogLevel() {
	mox.Conf.Log[""] = mlog.LevelInfo
	if a.debug {
		mox.Conf.Log[""] = mlog.LevelDebug
	}
	mlog.SetConfig(mox.Conf.Log)
}

func junkFlags(fs *flag.FlagSet) (a junkArgs) {
	fs.BoolVar(&a.params.Onegrams, "one-grams", false, "use 1-grams, i.e. single words, for scoring")
	fs.BoolVar(&a.params.Twograms, "two-grams", true, "use 2-grams, i.e. word pairs, for scoring")
	fs.BoolVar(&a.params.Threegrams, "three-grams", false, "use 3-grams, i.e. word triplets, for scoring")
	fs.Float64Var(&a.params.MaxPower, "max-power", 0.05, "maximum word power, e.g. min 0.05/max 0.95")
	fs.Float64Var(&a.params.IgnoreWords, "ignore-words", 0.1, "ignore words with ham/spaminess within this distance from 0.5")
	fs.IntVar(&a.params.TopWords, "top-words", 10, "number of top spam and number of top ham words from email to use")
	fs.IntVar(&a.params.RareWords, "rare-words", 1, "words are rare if encountered this number during training, and skipped for scoring")
	fs.BoolVar(&a.debug, "debug", false, "print debug logging when calculating spam probability")

	fs.Float64Var(&a.spamThreshold, "spam-threshold", 0.95, "probability where message is seen as spam")
	fs.Float64Var(&a.trainRatio, "train-ratio", 0.5, "part of data to use for training versus analyzing (for analyze only)")
	fs.StringVar(&a.sentDir, "sent-dir", "", "directory with sent mails, for training")
	fs.BoolVar(&a.seed, "seed", false, "seed prng before analysis")
	fs.StringVar(&a.databasePath, "dbpath", "filter.db", "database file for ham/spam words")
	fs.StringVar(&a.bloomfilterPath, "bloompath", "filter.bloom", "bloom filter for ignoring unique strings")

	return
}

func listDir(dir string) (l []string) {
	files, err := os.ReadDir(dir)
	xcheckf(err, "listing directory %q", dir)
	for _, f := range files {
		l = append(l, f.Name())
	}
	return l
}

func must(f *junk.Filter, err error) *junk.Filter {
	xcheckf(err, "filter")
	return f
}

func cmdJunkTrain(c *cmd) {
	c.unlisted = true
	c.params = "hamdir spamdir"
	c.help = "Train a junk filter with messages from hamdir and spamdir."
	a := junkFlags(c.flag)
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	a.SetLogLevel()

	f := must(junk.NewFilter(context.Background(), mlog.New("junktrain"), a.params, a.databasePath, a.bloomfilterPath))
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing junk filter: %v", err)
		}
	}()

	hamFiles := listDir(args[0])
	spamFiles := listDir(args[1])
	var sentFiles []string
	if a.sentDir != "" {
		sentFiles = listDir(a.sentDir)
	}

	err := f.TrainDirs(args[0], a.sentDir, args[1], hamFiles, sentFiles, spamFiles)
	xcheckf(err, "train")
}

func cmdJunkCheck(c *cmd) {
	c.unlisted = true
	c.params = "mailfile"
	c.help = "Check an email message against a junk filter, printing the probability of spam on a scale from 0 to 1."
	a := junkFlags(c.flag)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	a.SetLogLevel()

	f := must(junk.OpenFilter(context.Background(), mlog.New("junkcheck"), a.params, a.databasePath, a.bloomfilterPath, false))
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing junk filter: %v", err)
		}
	}()

	prob, _, _, _, err := f.ClassifyMessagePath(context.Background(), args[0])
	xcheckf(err, "testing mail")

	fmt.Printf("%.6f\n", prob)
}

func cmdJunkTest(c *cmd) {
	c.unlisted = true
	c.params = "hamdir spamdir"
	c.help = "Check a directory with hams and one with spams against the junk filter, and report the success ratio."
	a := junkFlags(c.flag)
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	a.SetLogLevel()

	f := must(junk.OpenFilter(context.Background(), mlog.New("junktest"), a.params, a.databasePath, a.bloomfilterPath, false))
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing junk filter: %v", err)
		}
	}()

	testDir := func(dir string, ham bool) (int, int) {
		ok, bad := 0, 0
		files, err := os.ReadDir(dir)
		xcheckf(err, "readdir %q", dir)
		for _, fi := range files {
			path := dir + "/" + fi.Name()
			prob, _, _, _, err := f.ClassifyMessagePath(context.Background(), path)
			if err != nil {
				log.Printf("classify message %q: %s", path, err)
				continue
			}
			if ham && prob < a.spamThreshold || !ham && prob > a.spamThreshold {
				ok++
			} else {
				bad++
			}
			if ham && prob > a.spamThreshold {
				fmt.Printf("ham %q: %.4f\n", path, prob)
			}
			if !ham && prob < a.spamThreshold {
				fmt.Printf("spam %q: %.4f\n", path, prob)
			}
		}
		return ok, bad
	}

	nhamok, nhambad := testDir(args[0], true)
	nspamok, nspambad := testDir(args[1], false)
	fmt.Printf("total ham, ok %d, bad %d\n", nhamok, nhambad)
	fmt.Printf("total spam, ok %d, bad %d\n", nspamok, nspambad)
	fmt.Printf("specifity (true negatives, hams identified): %.6f\n", float64(nhamok)/(float64(nhamok+nhambad)))
	fmt.Printf("sensitivity (true positives, spams identified): %.6f\n", float64(nspamok)/(float64(nspamok+nspambad)))
	fmt.Printf("accuracy: %.6f\n", float64(nhamok+nspamok)/float64(nhamok+nhambad+nspamok+nspambad))
}

func cmdJunkAnalyze(c *cmd) {
	c.unlisted = true
	c.params = "hamdir spamdir"
	c.help = `Analyze a directory with ham messages and one with spam messages.

A part of the messages is used for training, and remaining for testing. The
messages are shuffled, with optional random seed.`
	a := junkFlags(c.flag)
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	a.SetLogLevel()

	f := must(junk.NewFilter(context.Background(), mlog.New("junkanalyze"), a.params, a.databasePath, a.bloomfilterPath))
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing junk filter: %v", err)
		}
	}()

	hamDir := args[0]
	spamDir := args[1]
	hamFiles := listDir(hamDir)
	spamFiles := listDir(spamDir)

	var rand *mathrand.Rand
	if a.seed {
		rand = mathrand.New(mathrand.NewSource(time.Now().UnixMilli()))
	} else {
		rand = mathrand.New(mathrand.NewSource(0))
	}

	shuffle := func(l []string) {
		count := len(l)
		for i := range l {
			n := rand.Intn(count)
			l[i], l[n] = l[n], l[i]
		}
	}

	shuffle(hamFiles)
	shuffle(spamFiles)

	ntrainham := int(a.trainRatio * float64(len(hamFiles)))
	ntrainspam := int(a.trainRatio * float64(len(spamFiles)))

	trainHam := hamFiles[:ntrainham]
	trainSpam := spamFiles[:ntrainspam]
	testHam := hamFiles[ntrainham:]
	testSpam := spamFiles[ntrainspam:]

	var trainSent []string
	if a.sentDir != "" {
		trainSent = listDir(a.sentDir)
	}

	err := f.TrainDirs(hamDir, a.sentDir, spamDir, trainHam, trainSent, trainSpam)
	xcheckf(err, "train")

	testDir := func(dir string, files []string, ham bool) (ok, bad, malformed int) {
		for _, name := range files {
			path := dir + "/" + name
			prob, _, _, _, err := f.ClassifyMessagePath(context.Background(), path)
			if err != nil {
				// log.Infof("%s: %s", path, err)
				malformed++
				continue
			}
			if ham && prob < a.spamThreshold || !ham && prob > a.spamThreshold {
				ok++
			} else {
				bad++
			}
			if ham && prob > a.spamThreshold {
				fmt.Printf("ham %q: %.4f\n", path, prob)
			}
			if !ham && prob < a.spamThreshold {
				fmt.Printf("spam %q: %.4f\n", path, prob)
			}
		}
		return
	}

	nhamok, nhambad, nmalformedham := testDir(args[0], testHam, true)
	nspamok, nspambad, nmalformedspam := testDir(args[1], testSpam, false)
	fmt.Printf("training done, nham %d, nsent %d, nspam %d\n", ntrainham, len(trainSent), ntrainspam)
	fmt.Printf("total ham, ok %d, bad %d, malformed %d\n", nhamok, nhambad, nmalformedham)
	fmt.Printf("total spam, ok %d, bad %d, malformed %d\n", nspamok, nspambad, nmalformedspam)
	fmt.Printf("specifity (true negatives, hams identified): %.6f\n", float64(nhamok)/(float64(nhamok+nhambad)))
	fmt.Printf("sensitivity (true positives, spams identified): %.6f\n", float64(nspamok)/(float64(nspamok+nspambad)))
	fmt.Printf("accuracy: %.6f\n", float64(nhamok+nspamok)/float64(nhamok+nhambad+nspamok+nspambad))
}

func cmdJunkPlay(c *cmd) {
	c.unlisted = true
	c.params = "hamdir spamdir"
	c.help = "Play messages from ham and spam directory according to their time of arrival and report on junk filter performance."
	a := junkFlags(c.flag)
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	a.SetLogLevel()

	f := must(junk.NewFilter(context.Background(), mlog.New("junkplay"), a.params, a.databasePath, a.bloomfilterPath))
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing junk filter: %v", err)
		}
	}()

	// We'll go through all emails to find their dates.
	type msg struct {
		dir, filename string
		ham, sent     bool
		t             time.Time
	}
	var msgs []msg

	var nbad, nnodate, nham, nspam, nsent int

	jlog := mlog.New("junkplay")

	scanDir := func(dir string, ham, sent bool) {
		for _, name := range listDir(dir) {
			path := dir + "/" + name
			mf, err := os.Open(path)
			xcheckf(err, "open %q", path)
			fi, err := mf.Stat()
			xcheckf(err, "stat %q", path)
			p, err := message.EnsurePart(jlog, false, mf, fi.Size())
			if err != nil {
				nbad++
				if err := mf.Close(); err != nil {
					log.Printf("closing message file: %v", err)
				}
				continue
			}
			if p.Envelope.Date.IsZero() {
				nnodate++
				if err := mf.Close(); err != nil {
					log.Printf("closing message file: %v", err)
				}
				continue
			}
			if err := mf.Close(); err != nil {
				log.Printf("closing message file: %v", err)
			}
			msgs = append(msgs, msg{dir, name, ham, sent, p.Envelope.Date})
			if sent {
				nsent++
			} else if ham {
				nham++
			} else {
				nspam++
			}
		}
	}

	hamDir := args[0]
	spamDir := args[1]
	scanDir(hamDir, true, false)
	scanDir(spamDir, false, false)
	if a.sentDir != "" {
		scanDir(a.sentDir, true, true)
	}

	// Sort the messages, earliest first.
	sort.Slice(msgs, func(i, j int) bool {
		return msgs[i].t.Before(msgs[j].t)
	})

	// Play all messages as if they are coming in. We predict their spaminess, check if
	// we are right. And we train the system with the result.
	var nhamok, nhambad, nspamok, nspambad int

	play := func(msg msg) {
		var words map[string]struct{}
		path := msg.dir + "/" + msg.filename
		if !msg.sent {
			var prob float64
			var err error
			prob, words, _, _, err = f.ClassifyMessagePath(context.Background(), path)
			if err != nil {
				nbad++
				return
			}
			if msg.ham {
				if prob < a.spamThreshold {
					nhamok++
				} else {
					nhambad++
				}
			} else {
				if prob > a.spamThreshold {
					nspamok++
				} else {
					nspambad++
				}
			}
		} else {
			mf, err := os.Open(path)
			xcheckf(err, "open %q", path)
			defer func() {
				if err := mf.Close(); err != nil {
					log.Printf("closing message file: %v", err)
				}
			}()
			fi, err := mf.Stat()
			xcheckf(err, "stat %q", path)
			p, err := message.EnsurePart(jlog, false, mf, fi.Size())
			if err != nil {
				log.Printf("bad sent message %q: %s", path, err)
				return
			}

			words, err = f.ParseMessage(p)
			if err != nil {
				log.Printf("bad sent message %q: %s", path, err)
				return
			}
		}

		if err := f.Train(context.Background(), msg.ham, words); err != nil {
			log.Printf("train: %s", err)
		}
	}

	for _, m := range msgs {
		play(m)
	}

	err := f.Save()
	xcheckf(err, "saving filter")

	fmt.Printf("completed, nham %d, nsent %d, nspam %d, nbad %d, nwithoutdate %d\n", nham, nsent, nspam, nbad, nnodate)
	fmt.Printf("total ham, ok %d, bad %d\n", nhamok, nhambad)
	fmt.Printf("total spam, ok %d, bad %d\n", nspamok, nspambad)
	fmt.Printf("specifity (true negatives, hams identified): %.6f\n", float64(nhamok)/(float64(nhamok+nhambad)))
	fmt.Printf("sensitivity (true positives, spams identified): %.6f\n", float64(nspamok)/(float64(nspamok+nspambad)))
	fmt.Printf("accuracy: %.6f\n", float64(nhamok+nspamok)/float64(nhamok+nhambad+nspamok+nspambad))
}
