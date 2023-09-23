package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

func backupctl(ctx context.Context, ctl *ctl) {
	/* protocol:
	> "backup"
	> destdir
	> "verbose" or ""
	< stream
	< "ok" or error
	*/

	// Convention in this function: variables containing "src" or "dst" are file system
	// paths that can be passed to os.Open and such. Variables with dirs/paths without
	// "src" or "dst" are incomplete paths relative to the source or destination data
	// directories.

	dstDataDir := ctl.xread()
	verbose := ctl.xread() == "verbose"

	// Set when an error is encountered. At the end, we warn if set.
	var incomplete bool

	// We'll be writing output, and logging both to mox and the ctl stream.
	writer := ctl.writer()

	// Format easily readable output for the user.
	formatLog := func(prefix, text string, err error, fields ...mlog.Pair) []byte {
		var b bytes.Buffer
		fmt.Fprint(&b, prefix)
		fmt.Fprint(&b, text)
		if err != nil {
			fmt.Fprint(&b, ": "+err.Error())
		}
		for _, f := range fields {
			fmt.Fprintf(&b, "; %s=%v", f.Key, f.Value)
		}
		fmt.Fprint(&b, "\n")
		return b.Bytes()
	}

	// Log an error to both the mox service as the user running "mox backup".
	xlogx := func(prefix, text string, err error, fields ...mlog.Pair) {
		ctl.log.Errorx(text, err, fields...)

		_, werr := writer.Write(formatLog(prefix, text, err, fields...))
		ctl.xcheck(werr, "write to ctl")
	}

	// Log an error but don't mark backup as failed.
	xwarnx := func(text string, err error, fields ...mlog.Pair) {
		xlogx("warning: ", text, err, fields...)
	}

	// Log an error that causes the backup to be marked as failed. We typically
	// continue processing though.
	xerrx := func(text string, err error, fields ...mlog.Pair) {
		incomplete = true
		xlogx("error: ", text, err, fields...)
	}

	// If verbose is enabled, log to the cli command. Always log as info level.
	xvlog := func(text string, fields ...mlog.Pair) {
		ctl.log.Info(text, fields...)
		if verbose {
			_, werr := writer.Write(formatLog("", text, nil, fields...))
			ctl.xcheck(werr, "write to ctl")
		}
	}

	if _, err := os.Stat(dstDataDir); err == nil {
		xwarnx("destination data directory already exists", nil, mlog.Field("dir", dstDataDir))
	}

	srcDataDir := filepath.Clean(mox.DataDirPath("."))

	// When creating a file in the destination, we first ensure its directory exists.
	// We track which directories we created, to prevent needless syscalls.
	createdDirs := map[string]struct{}{}
	ensureDestDir := func(dstpath string) {
		dstdir := filepath.Dir(dstpath)
		if _, ok := createdDirs[dstdir]; !ok {
			err := os.MkdirAll(dstdir, 0770)
			if err != nil {
				xerrx("creating directory", err)
			}
			createdDirs[dstdir] = struct{}{}
		}
	}

	// Backup a single file by copying (never hardlinking, the file may change).
	backupFile := func(path string) {
		tmFile := time.Now()
		srcpath := filepath.Join(srcDataDir, path)
		dstpath := filepath.Join(dstDataDir, path)

		sf, err := os.Open(srcpath)
		if err != nil {
			xerrx("open source file (not backed up)", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			return
		}
		defer sf.Close()

		ensureDestDir(dstpath)
		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			xerrx("creating destination file (not backed up)", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			return
		}
		defer func() {
			if df != nil {
				df.Close()
			}
		}()
		if _, err := io.Copy(df, sf); err != nil {
			xerrx("copying file (not backed up properly)", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			return
		}
		err = df.Close()
		df = nil
		if err != nil {
			xerrx("closing destination file (not backed up properly)", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			return
		}
		xvlog("backed up file", mlog.Field("path", path), mlog.Field("duration", time.Since(tmFile)))
	}

	// Back up the files in a directory (by copying).
	backupDir := func(dir string) {
		tmDir := time.Now()
		srcdir := filepath.Join(srcDataDir, dir)
		dstdir := filepath.Join(dstDataDir, dir)
		err := filepath.WalkDir(srcdir, func(srcpath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking file (not backed up)", err, mlog.Field("srcpath", srcpath))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			backupFile(srcpath[len(srcDataDir)+1:])
			return nil
		})
		if err != nil {
			xerrx("copying directory (not backed up properly)", err, mlog.Field("srcdir", srcdir), mlog.Field("dstdir", dstdir), mlog.Field("duration", time.Since(tmDir)))
			return
		}
		xvlog("backed up directory", mlog.Field("dir", dir), mlog.Field("duration", time.Since(tmDir)))
	}

	// Backup a database by copying it in a readonly transaction.
	// Always logs on error, so caller doesn't have to, but also returns the error so
	// callers can see result.
	backupDB := func(db *bstore.DB, path string) (rerr error) {
		defer func() {
			if rerr != nil {
				xerrx("backing up database", rerr, mlog.Field("path", path))
			}
		}()

		tmDB := time.Now()

		dstpath := filepath.Join(dstDataDir, path)
		ensureDestDir(dstpath)
		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			return fmt.Errorf("creating destination file: %v", err)
		}
		defer func() {
			if df != nil {
				df.Close()
			}
		}()
		err = db.Read(ctx, func(tx *bstore.Tx) error {
			// Using regular WriteTo seems fine, and fast. It just copies pages.
			//
			// bolt.Compact is slower, it writes all key/value pairs, building up new data
			// structures. My compacted test database was ~60% of original size. Lz4 on the
			// uncompacted database got it to 14%. Lz4 on the compacted database got it to 13%.
			// Backups are likely archived somewhere with compression, so we don't compact.
			//
			// Tests with WriteTo and os.O_DIRECT were slower than without O_DIRECT, but
			// probably because everything fit in the page cache. It may be better to use
			// O_DIRECT when copying many large or inactive databases.
			_, err := tx.WriteTo(df)
			return err
		})
		if err != nil {
			return fmt.Errorf("copying database: %v", err)
		}
		err = df.Close()
		df = nil
		if err != nil {
			return fmt.Errorf("closing destination database after copy: %v", err)
		}
		xvlog("backed up database file", mlog.Field("path", path), mlog.Field("duration", time.Since(tmDB)))
		return nil
	}

	// Try to create a hardlink. Fall back to copying the file (e.g. when on different file system).
	warnedHardlink := false // We warn once about failing to hardlink.
	linkOrCopy := func(srcpath, dstpath string) (bool, error) {
		ensureDestDir(dstpath)

		if err := os.Link(srcpath, dstpath); err == nil {
			return true, nil
		} else if os.IsNotExist(err) {
			// No point in trying with regular copy, we would warn twice.
			return false, err
		} else if !warnedHardlink {
			xwarnx("creating hardlink to message failed, will be doing regular file copies and not warn again", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			warnedHardlink = true
		}

		// Fall back to copying.
		sf, err := os.Open(srcpath)
		if err != nil {
			return false, fmt.Errorf("open source path %s: %v", srcpath, err)
		}
		defer func() {
			err := sf.Close()
			ctl.log.Check(err, "closing copied source file")
		}()

		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			return false, fmt.Errorf("create destination path %s: %v", dstpath, err)
		}
		defer func() {
			if df != nil {
				err := df.Close()
				ctl.log.Check(err, "closing partial destination file")
			}
		}()
		if _, err := io.Copy(df, sf); err != nil {
			return false, fmt.Errorf("coping: %v", err)
		}
		err = df.Close()
		df = nil
		if err != nil {
			return false, fmt.Errorf("closing destination file: %v", err)
		}
		return false, nil
	}

	// Start making the backup.
	tmStart := time.Now()

	ctl.log.Print("making backup", mlog.Field("destdir", dstDataDir))

	err := os.MkdirAll(dstDataDir, 0770)
	if err != nil {
		xerrx("creating destination data directory", err)
	}

	if err := os.WriteFile(filepath.Join(dstDataDir, "moxversion"), []byte(moxvar.Version), 0660); err != nil {
		xerrx("writing moxversion", err)
	}
	backupDB(dmarcdb.DB, "dmarcrpt.db")
	backupDB(mtastsdb.DB, "mtasts.db")
	backupDB(tlsrptdb.DB, "tlsrpt.db")
	backupFile("receivedid.key")

	// Acme directory is optional.
	srcAcmeDir := filepath.Join(srcDataDir, "acme")
	if _, err := os.Stat(srcAcmeDir); err == nil {
		backupDir("acme")
	} else if err != nil && !os.IsNotExist(err) {
		xerrx("copying acme/", err)
	}

	// Copy the queue database and all message files.
	backupQueue := func(path string) {
		tmQueue := time.Now()

		if err := backupDB(queue.DB, path); err != nil {
			xerrx("queue not backed up", err, mlog.Field("path", path), mlog.Field("duration", time.Since(tmQueue)))
			return
		}

		dstdbpath := filepath.Join(dstDataDir, path)
		db, err := bstore.Open(ctx, dstdbpath, &bstore.Options{MustExist: true}, queue.DBTypes...)
		if err != nil {
			xerrx("open copied queue database", err, mlog.Field("dstpath", dstdbpath), mlog.Field("duration", time.Since(tmQueue)))
			return
		}

		defer func() {
			if db != nil {
				err := db.Close()
				ctl.log.Check(err, "closing new queue db")
			}
		}()

		// Link/copy known message files. Warn if files are missing or unexpected
		// (though a message file could have been removed just now due to delivery, or a
		// new message may have been queued).
		tmMsgs := time.Now()
		seen := map[string]struct{}{}
		var nlinked, ncopied int
		err = bstore.QueryDB[queue.Msg](ctx, db).ForEach(func(m queue.Msg) error {
			mp := store.MessagePath(m.ID)
			seen[mp] = struct{}{}
			srcpath := filepath.Join(srcDataDir, "queue", mp)
			dstpath := filepath.Join(dstDataDir, "queue", mp)
			if linked, err := linkOrCopy(srcpath, dstpath); err != nil {
				xerrx("linking/copying queue message", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			} else if linked {
				nlinked++
			} else {
				ncopied++
			}
			return nil
		})
		if err != nil {
			xerrx("processing queue messages (not backed up properly)", err, mlog.Field("duration", time.Since(tmMsgs)))
		} else {
			xvlog("queue message files linked/copied", mlog.Field("linked", nlinked), mlog.Field("copied", ncopied), mlog.Field("duration", time.Since(tmMsgs)))
		}

		// Read through all files in queue directory and warn about anything we haven't handled yet.
		tmWalk := time.Now()
		srcqdir := filepath.Join(srcDataDir, "queue")
		err = filepath.WalkDir(srcqdir, func(srcqpath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking files in queue", err, mlog.Field("srcpath", srcqpath))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			p := srcqpath[len(srcqdir)+1:]
			if _, ok := seen[p]; ok {
				return nil
			}
			if p == "index.db" {
				return nil
			}
			qp := filepath.Join("queue", p)
			xwarnx("backing up unrecognized file in queue directory", nil, mlog.Field("path", qp))
			backupFile(qp)
			return nil
		})
		if err != nil {
			xerrx("walking queue directory (not backed up properly)", err, mlog.Field("dir", "queue"), mlog.Field("duration", time.Since(tmWalk)))
		} else {
			xvlog("walked queue directory", mlog.Field("duration", time.Since(tmWalk)))
		}

		xvlog("queue backed finished", mlog.Field("duration", time.Since(tmQueue)))
	}
	backupQueue("queue/index.db")

	backupAccount := func(acc *store.Account) {
		defer acc.Close()

		tmAccount := time.Now()

		// Copy database file.
		dbpath := filepath.Join("accounts", acc.Name, "index.db")
		err := backupDB(acc.DB, dbpath)
		if err != nil {
			xerrx("copying account database", err, mlog.Field("path", dbpath), mlog.Field("duration", time.Since(tmAccount)))
		}

		// todo: should document/check not taking a rlock on account.

		// Copy junkfilter files, if configured.
		if jf, _, err := acc.OpenJunkFilter(ctx, ctl.log); err != nil {
			if !errors.Is(err, store.ErrNoJunkFilter) {
				xerrx("opening junk filter for account (not backed up)", err)
			}
		} else {
			db := jf.DB()
			jfpath := filepath.Join("accounts", acc.Name, "junkfilter.db")
			backupDB(db, jfpath)
			bloompath := filepath.Join("accounts", acc.Name, "junkfilter.bloom")
			backupFile(bloompath)
			db = nil
			err := jf.Close()
			ctl.log.Check(err, "closing junkfilter")
		}

		dstdbpath := filepath.Join(dstDataDir, dbpath)
		db, err := bstore.Open(ctx, dstdbpath, &bstore.Options{MustExist: true}, store.DBTypes...)
		if err != nil {
			xerrx("open copied account database", err, mlog.Field("dstpath", dstdbpath), mlog.Field("duration", time.Since(tmAccount)))
			return
		}

		defer func() {
			if db != nil {
				err := db.Close()
				ctl.log.Check(err, "close account database")
			}
		}()

		// Link/copy known message files. Warn if files are missing or unexpected (though a
		// message file could have been added just now due to delivery, or a message have
		// been removed).
		tmMsgs := time.Now()
		seen := map[string]struct{}{}
		var nlinked, ncopied int
		err = bstore.QueryDB[store.Message](ctx, db).FilterEqual("Expunged", false).ForEach(func(m store.Message) error {
			mp := store.MessagePath(m.ID)
			seen[mp] = struct{}{}
			amp := filepath.Join("accounts", acc.Name, "msg", mp)
			srcpath := filepath.Join(srcDataDir, amp)
			dstpath := filepath.Join(dstDataDir, amp)
			if linked, err := linkOrCopy(srcpath, dstpath); err != nil {
				xerrx("linking/copying account message", err, mlog.Field("srcpath", srcpath), mlog.Field("dstpath", dstpath))
			} else if linked {
				nlinked++
			} else {
				ncopied++
			}
			return nil
		})
		if err != nil {
			xerrx("processing account messages (not backed up properly)", err, mlog.Field("duration", time.Since(tmMsgs)))
		} else {
			xvlog("account message files linked/copied", mlog.Field("linked", nlinked), mlog.Field("copied", ncopied), mlog.Field("duration", time.Since(tmMsgs)))
		}

		// Read through all files in account directory and warn about anything we haven't handled yet.
		tmWalk := time.Now()
		srcadir := filepath.Join(srcDataDir, "accounts", acc.Name)
		err = filepath.WalkDir(srcadir, func(srcapath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking files in account", err, mlog.Field("srcpath", srcapath))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			p := srcapath[len(srcadir)+1:]
			l := strings.Split(p, string(filepath.Separator))
			if l[0] == "msg" {
				mp := filepath.Join(l[1:]...)
				if _, ok := seen[mp]; ok {
					return nil
				}
			}
			switch p {
			case "index.db", "junkfilter.db", "junkfilter.bloom":
				return nil
			}
			ap := filepath.Join("accounts", acc.Name, p)
			if strings.HasPrefix(p, "msg/") {
				xwarnx("backing up unrecognized file in account message directory (should be moved away)", nil, mlog.Field("path", ap))
			} else {
				xwarnx("backing up unrecognized file in account directory", nil, mlog.Field("path", ap))
			}
			backupFile(ap)
			return nil
		})
		if err != nil {
			xerrx("walking account directory (not backed up properly)", err, mlog.Field("srcdir", srcadir), mlog.Field("duration", time.Since(tmWalk)))
		} else {
			xvlog("walked account directory", mlog.Field("duration", time.Since(tmWalk)))
		}

		xvlog("account backup finished", mlog.Field("dir", filepath.Join("accounts", acc.Name)), mlog.Field("duration", time.Since(tmAccount)))
	}

	// For each configured account, open it, make a copy of the database and
	// hardlink/copy the messages. We track the accounts we handled, and skip the
	// account directories when handling "all other files" below.
	accounts := map[string]struct{}{}
	for _, accName := range mox.Conf.Accounts() {
		acc, err := store.OpenAccount(accName)
		if err != nil {
			xerrx("opening account for copying (will try to copy as regular files later)", err, mlog.Field("account", accName))
			continue
		}
		accounts[accName] = struct{}{}
		backupAccount(acc)
	}

	// Copy all other files, that aren't part of the known files, databases, queue or accounts.
	tmWalk := time.Now()
	err = filepath.WalkDir(srcDataDir, func(srcpath string, d fs.DirEntry, err error) error {
		if err != nil {
			xerrx("walking path", err, mlog.Field("path", srcpath))
			return nil
		}

		if srcpath == srcDataDir {
			return nil
		}
		p := srcpath[len(srcDataDir)+1:]
		if p == "queue" || p == "acme" || p == "tmp" {
			return fs.SkipDir
		}
		l := strings.Split(p, string(filepath.Separator))
		if len(l) >= 2 && l[0] == "accounts" {
			name := l[1]
			if _, ok := accounts[name]; ok {
				return fs.SkipDir
			}
		}

		// Only files are explicitly backed up.
		if d.IsDir() {
			return nil
		}

		switch p {
		case "dmarcrpt.db", "mtasts.db", "tlsrpt.db", "receivedid.key", "ctl":
			// Already handled.
			return nil
		case "lastknownversion": // Optional file, not yet handled.
		default:
			xwarnx("backing up unrecognized file", nil, mlog.Field("path", p))
		}
		backupFile(p)
		return nil
	})
	if err != nil {
		xerrx("walking other files (not backed up properly)", err, mlog.Field("duration", time.Since(tmWalk)))
	} else {
		xvlog("walking other files finished", mlog.Field("duration", time.Since(tmWalk)))
	}

	xvlog("backup finished", mlog.Field("duration", time.Since(tmStart)))

	writer.xclose()

	if incomplete {
		ctl.xwrite("errors were encountered during backup")
	} else {
		ctl.xwriteok()
	}
}
