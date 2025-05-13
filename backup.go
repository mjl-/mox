package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/mtastsdb"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/tlsrptdb"
)

func xbackupctl(ctx context.Context, xctl *ctl) {
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

	dstDir := xctl.xread()
	verbose := xctl.xread() == "verbose"

	// Set when an error is encountered. At the end, we warn if set.
	var incomplete bool

	// We'll be writing output, and logging both to mox and the ctl stream.
	xwriter := xctl.writer()

	// Format easily readable output for the user.
	formatLog := func(prefix, text string, err error, attrs ...slog.Attr) []byte {
		var b bytes.Buffer
		fmt.Fprint(&b, prefix)
		fmt.Fprint(&b, text)
		if err != nil {
			fmt.Fprint(&b, ": "+err.Error())
		}
		for _, a := range attrs {
			fmt.Fprintf(&b, "; %s=%v", a.Key, a.Value)
		}
		fmt.Fprint(&b, "\n")
		return b.Bytes()
	}

	// Log an error to both the mox service as the user running "mox backup".
	pkglogx := func(prefix, text string, err error, attrs ...slog.Attr) {
		xctl.log.Errorx(text, err, attrs...)
		xwriter.Write(formatLog(prefix, text, err, attrs...))
	}

	// Log an error but don't mark backup as failed.
	xwarnx := func(text string, err error, attrs ...slog.Attr) {
		pkglogx("warning: ", text, err, attrs...)
	}

	// Log an error that causes the backup to be marked as failed. We typically
	// continue processing though.
	xerrx := func(text string, err error, attrs ...slog.Attr) {
		incomplete = true
		pkglogx("error: ", text, err, attrs...)
	}

	// If verbose is enabled, log to the cli command. Always log as info level.
	xvlog := func(text string, attrs ...slog.Attr) {
		xctl.log.Info(text, attrs...)
		if verbose {
			xwriter.Write(formatLog("", text, nil, attrs...))
		}
	}

	dstConfigDir := filepath.Join(dstDir, "config")
	dstDataDir := filepath.Join(dstDir, "data")

	// Warn if directories already exist, will likely cause failures when trying to
	// write files that already exist.
	if _, err := os.Stat(dstConfigDir); err == nil {
		xwarnx("destination config directory already exists", nil, slog.String("configdir", dstConfigDir))
	}
	if _, err := os.Stat(dstDataDir); err == nil {
		xwarnx("destination data directory already exists", nil, slog.String("datadir", dstDataDir))
	}

	os.MkdirAll(dstDir, 0770)
	os.MkdirAll(dstConfigDir, 0770)
	os.MkdirAll(dstDataDir, 0770)

	// Copy all files in the config dir.
	srcConfigDir := filepath.Clean(mox.ConfigDirPath("."))
	err := filepath.WalkDir(srcConfigDir, func(srcPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if srcConfigDir == srcPath {
			return nil
		}

		// Trim directory and separator.
		relPath := srcPath[len(srcConfigDir)+1:]

		destPath := filepath.Join(dstConfigDir, relPath)

		if d.IsDir() {
			if info, err := os.Stat(srcPath); err != nil {
				return fmt.Errorf("stat config dir %s: %v", srcPath, err)
			} else if err := os.Mkdir(destPath, info.Mode()&0777); err != nil {
				return fmt.Errorf("mkdir %s: %v", destPath, err)
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			linkDest, err := os.Readlink(srcPath)
			if err != nil {
				return fmt.Errorf("reading symlink %s: %v", srcPath, err)
			}
			if err := os.Symlink(linkDest, destPath); err != nil {
				return fmt.Errorf("creating symlink %s: %v", destPath, err)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			xwarnx("skipping non-regular/dir/symlink file in config dir", nil, slog.String("path", srcPath))
			return nil
		}

		sf, err := os.Open(srcPath)
		if err != nil {
			return fmt.Errorf("open config file %s: %v", srcPath, err)
		}
		info, err := sf.Stat()
		if err != nil {
			return fmt.Errorf("stat config file %s: %v", srcPath, err)
		}
		df, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0777&info.Mode())
		if err != nil {
			return fmt.Errorf("create destination config file %s: %v", destPath, err)
		}
		defer func() {
			if df != nil {
				err := df.Close()
				xctl.log.Check(err, "closing file")
			}
		}()
		defer func() {
			err := sf.Close()
			xctl.log.Check(err, "closing file")
		}()
		if _, err := io.Copy(df, sf); err != nil {
			return fmt.Errorf("copying config file %s to %s: %v", srcPath, destPath, err)
		}
		if err := df.Close(); err != nil {
			return fmt.Errorf("closing destination config file %s: %v", srcPath, err)
		}
		df = nil
		return nil
	})
	if err != nil {
		xerrx("storing config directory", err)
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
			xerrx("open source file (not backed up)", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			return
		}
		defer func() {
			err := sf.Close()
			xctl.log.Check(err, "closing source file")
		}()

		ensureDestDir(dstpath)
		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			xerrx("creating destination file (not backed up)", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			return
		}
		defer func() {
			if df != nil {
				err := df.Close()
				xctl.log.Check(err, "closing destination file")
			}
		}()
		if _, err := io.Copy(df, sf); err != nil {
			xerrx("copying file (not backed up properly)", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			return
		}
		err = df.Close()
		df = nil
		if err != nil {
			xerrx("closing destination file (not backed up properly)", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			return
		}
		xvlog("backed up file", slog.String("path", path), slog.Duration("duration", time.Since(tmFile)))
	}

	// Back up the files in a directory (by copying).
	backupDir := func(dir string) {
		tmDir := time.Now()
		srcdir := filepath.Join(srcDataDir, dir)
		dstdir := filepath.Join(dstDataDir, dir)
		err := filepath.WalkDir(srcdir, func(srcpath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking file (not backed up)", err, slog.String("srcpath", srcpath))
				return nil
			}
			if d.IsDir() {
				return nil
			}
			backupFile(srcpath[len(srcDataDir)+1:])
			return nil
		})
		if err != nil {
			xerrx("copying directory (not backed up properly)", err,
				slog.String("srcdir", srcdir),
				slog.String("dstdir", dstdir),
				slog.Duration("duration", time.Since(tmDir)))
			return
		}
		xvlog("backed up directory", slog.String("dir", dir), slog.Duration("duration", time.Since(tmDir)))
	}

	// Backup a database by copying it in a readonly transaction. Wrapped by backupDB
	// which logs and returns just a bool.
	backupDB0 := func(db *bstore.DB, path string) error {
		dstpath := filepath.Join(dstDataDir, path)
		ensureDestDir(dstpath)
		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			return fmt.Errorf("creating destination file: %v", err)
		}
		defer func() {
			if df != nil {
				err := df.Close()
				xctl.log.Check(err, "closing destination database file")
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
		return nil
	}

	backupDB := func(db *bstore.DB, path string) bool {
		start := time.Now()
		err := backupDB0(db, path)
		if err != nil {
			xerrx("backing up database", err, slog.String("path", path), slog.Duration("duration", time.Since(start)))
			return false
		}
		xvlog("backed up database file", slog.String("path", path), slog.Duration("duration", time.Since(start)))
		return true
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
			var hardlinkHint string
			if runtime.GOOS == "linux" && errors.Is(err, syscall.EXDEV) {
				hardlinkHint = " (hint: if running under systemd, ReadWritePaths in mox.service may cause multiple mountpoints; consider merging paths into a single parent directory to prevent cross-device/mountpoint hardlinks)"
			}
			xwarnx("creating hardlink to message failed, will be doing regular file copies and not warn again"+hardlinkHint, err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			warnedHardlink = true
		}

		// Fall back to copying.
		sf, err := os.Open(srcpath)
		if err != nil {
			return false, fmt.Errorf("open source path %s: %v", srcpath, err)
		}
		defer func() {
			err := sf.Close()
			xctl.log.Check(err, "closing copied source file")
		}()

		df, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
		if err != nil {
			return false, fmt.Errorf("create destination path %s: %v", dstpath, err)
		}
		defer func() {
			if df != nil {
				err := df.Close()
				xctl.log.Check(err, "closing partial destination file")
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

	xctl.log.Print("making backup", slog.String("destdir", dstDataDir))

	if err := os.MkdirAll(dstDataDir, 0770); err != nil {
		xerrx("creating destination data directory", err)
	}

	if err := os.WriteFile(filepath.Join(dstDataDir, "moxversion"), []byte(moxvar.Version), 0660); err != nil {
		xerrx("writing moxversion", err)
	}
	backupDB(store.AuthDB, "auth.db")
	backupDB(dmarcdb.ReportsDB, "dmarcrpt.db")
	backupDB(dmarcdb.EvalDB, "dmarceval.db")
	backupDB(mtastsdb.DB, "mtasts.db")
	backupDB(tlsrptdb.ReportDB, "tlsrpt.db")
	backupDB(tlsrptdb.ResultDB, "tlsrptresult.db")
	backupFile("receivedid.key")

	// Acme directory is optional.
	srcAcmeDir := filepath.Join(srcDataDir, "acme")
	if _, err := os.Stat(srcAcmeDir); err == nil {
		backupDir("acme")
	} else if !os.IsNotExist(err) {
		xerrx("copying acme/", err)
	}

	// Copy the queue database and all message files.
	backupQueue := func(path string) {
		tmQueue := time.Now()

		if !backupDB(queue.DB, path) {
			return
		}

		dstdbpath := filepath.Join(dstDataDir, path)
		opts := bstore.Options{MustExist: true, RegisterLogger: xctl.log.Logger}
		db, err := bstore.Open(ctx, dstdbpath, &opts, queue.DBTypes...)
		if err != nil {
			xerrx("open copied queue database", err, slog.String("dstpath", dstdbpath), slog.Duration("duration", time.Since(tmQueue)))
			return
		}

		defer func() {
			if db != nil {
				err := db.Close()
				xctl.log.Check(err, "closing new queue db")
			}
		}()

		// Link/copy known message files. If a message has been removed while we read the
		// database, our backup is not consistent and the backup will be marked failed.
		tmMsgs := time.Now()
		seen := map[string]struct{}{}
		var nlinked, ncopied int
		var maxID int64
		err = bstore.QueryDB[queue.Msg](ctx, db).ForEach(func(m queue.Msg) error {
			if m.ID > maxID {
				maxID = m.ID
			}
			mp := store.MessagePath(m.ID)
			seen[mp] = struct{}{}
			srcpath := filepath.Join(srcDataDir, "queue", mp)
			dstpath := filepath.Join(dstDataDir, "queue", mp)
			if linked, err := linkOrCopy(srcpath, dstpath); err != nil {
				xerrx("linking/copying queue message", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			} else if linked {
				nlinked++
			} else {
				ncopied++
			}
			return nil
		})
		if err != nil {
			xerrx("processing queue messages (not backed up properly)", err, slog.Duration("duration", time.Since(tmMsgs)))
		} else {
			xvlog("queue message files linked/copied",
				slog.Int("linked", nlinked),
				slog.Int("copied", ncopied),
				slog.Duration("duration", time.Since(tmMsgs)))
		}

		// Read through all files in queue directory and warn about anything we haven't
		// handled yet. Message files that are newer than we expect from our consistent
		// database snapshot are ignored.
		tmWalk := time.Now()
		srcqdir := filepath.Join(srcDataDir, "queue")
		err = filepath.WalkDir(srcqdir, func(srcqpath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking files in queue", err, slog.String("srcpath", srcqpath))
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
			// Skip any messages that were added since we started on our consistent snapshot.
			// We don't want to cause spurious backup warnings.
			if id, err := strconv.ParseInt(filepath.Base(p), 10, 64); err == nil && maxID > 0 && id > maxID && p == store.MessagePath(id) {
				return nil
			}

			qp := filepath.Join("queue", p)
			xwarnx("backing up unrecognized file in queue directory", nil, slog.String("path", qp))
			backupFile(qp)
			return nil
		})
		if err != nil {
			xerrx("walking queue directory (not backed up properly)", err, slog.String("dir", "queue"), slog.Duration("duration", time.Since(tmWalk)))
		} else {
			xvlog("walked queue directory", slog.Duration("duration", time.Since(tmWalk)))
		}

		xvlog("queue backed finished", slog.Duration("duration", time.Since(tmQueue)))
	}
	backupQueue(filepath.FromSlash("queue/index.db"))

	backupAccount := func(acc *store.Account) {
		defer func() {
			err := acc.Close()
			xctl.log.Check(err, "closing account")
		}()

		tmAccount := time.Now()

		// Copy database file.
		dbpath := filepath.Join("accounts", acc.Name, "index.db")
		backupDB(acc.DB, dbpath)

		// todo: should document/check not taking a rlock on account.

		// Copy junkfilter files, if configured.
		if jf, _, err := acc.OpenJunkFilter(ctx, xctl.log); err != nil {
			if !errors.Is(err, store.ErrNoJunkFilter) {
				xerrx("opening junk filter for account (not backed up)", err)
			}
		} else {
			db := jf.DB()
			jfpath := filepath.Join("accounts", acc.Name, "junkfilter.db")
			backupDB(db, jfpath)
			bloompath := filepath.Join("accounts", acc.Name, "junkfilter.bloom")
			backupFile(bloompath)
			err := jf.Close()
			xctl.log.Check(err, "closing junkfilter")
		}

		dstdbpath := filepath.Join(dstDataDir, dbpath)
		opts := bstore.Options{MustExist: true, RegisterLogger: xctl.log.Logger}
		db, err := bstore.Open(ctx, dstdbpath, &opts, store.DBTypes...)
		if err != nil {
			xerrx("open copied account database", err, slog.String("dstpath", dstdbpath), slog.Duration("duration", time.Since(tmAccount)))
			return
		}

		defer func() {
			if db != nil {
				err := db.Close()
				xctl.log.Check(err, "close account database")
			}
		}()

		// Link/copy known message files.
		tmMsgs := time.Now()
		seen := map[string]struct{}{}
		var maxID int64
		var nlinked, ncopied int
		err = bstore.QueryDB[store.Message](ctx, db).FilterEqual("Expunged", false).ForEach(func(m store.Message) error {
			if m.ID > maxID {
				maxID = m.ID
			}
			mp := store.MessagePath(m.ID)
			seen[mp] = struct{}{}
			amp := filepath.Join("accounts", acc.Name, "msg", mp)
			srcpath := filepath.Join(srcDataDir, amp)
			dstpath := filepath.Join(dstDataDir, amp)
			if linked, err := linkOrCopy(srcpath, dstpath); err != nil {
				xerrx("linking/copying account message", err, slog.String("srcpath", srcpath), slog.String("dstpath", dstpath))
			} else if linked {
				nlinked++
			} else {
				ncopied++
			}
			return nil
		})
		if err != nil {
			xerrx("processing account messages (not backed up properly)", err, slog.Duration("duration", time.Since(tmMsgs)))
		} else {
			xvlog("account message files linked/copied",
				slog.Int("linked", nlinked),
				slog.Int("copied", ncopied),
				slog.Duration("duration", time.Since(tmMsgs)))
		}

		eraseIDs := map[int64]struct{}{}
		err = bstore.QueryDB[store.MessageErase](ctx, db).ForEach(func(me store.MessageErase) error {
			eraseIDs[me.ID] = struct{}{}
			return nil
		})
		if err != nil {
			xerrx("listing erased messages", err)
		}

		// Read through all files in queue directory and warn about anything we haven't
		// handled yet. Message files that are newer than we expect from our consistent
		// database snapshot are ignored.
		tmWalk := time.Now()
		srcadir := filepath.Join(srcDataDir, "accounts", acc.Name)
		err = filepath.WalkDir(srcadir, func(srcapath string, d fs.DirEntry, err error) error {
			if err != nil {
				xerrx("walking files in account", err, slog.String("srcpath", srcapath))
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

				// Skip any messages that were added since we started on our consistent snapshot,
				// or messages that will be erased. We don't want to cause spurious backup
				// warnings.
				id, err := strconv.ParseInt(l[len(l)-1], 10, 64)
				if err == nil && id > maxID && mp == store.MessagePath(id) {
					return nil
				} else if _, ok := eraseIDs[id]; err == nil && ok {
					return nil
				}
			}
			switch p {
			case "index.db", "junkfilter.db", "junkfilter.bloom":
				return nil
			}
			ap := filepath.Join("accounts", acc.Name, p)
			if strings.HasPrefix(p, "msg"+string(filepath.Separator)) {
				xwarnx("backing up unrecognized file in account message directory (should be moved away)", nil, slog.String("path", ap))
			} else {
				xwarnx("backing up unrecognized file in account directory", nil, slog.String("path", ap))
			}
			backupFile(ap)
			return nil
		})
		if err != nil {
			xerrx("walking account directory (not backed up properly)", err, slog.String("srcdir", srcadir), slog.Duration("duration", time.Since(tmWalk)))
		} else {
			xvlog("walked account directory", slog.Duration("duration", time.Since(tmWalk)))
		}

		xvlog("account backup finished", slog.String("dir", filepath.Join("accounts", acc.Name)), slog.Duration("duration", time.Since(tmAccount)))
	}

	// For each configured account, open it, make a copy of the database and
	// hardlink/copy the messages. We track the accounts we handled, and skip the
	// account directories when handling "all other files" below.
	accounts := map[string]struct{}{}
	for _, accName := range mox.Conf.Accounts() {
		acc, err := store.OpenAccount(xctl.log, accName, false)
		if err != nil {
			xerrx("opening account for copying (will try to copy as regular files later)", err, slog.String("account", accName))
			continue
		}
		accounts[accName] = struct{}{}
		backupAccount(acc)
	}

	// Copy all other files, that aren't part of the known files, databases, queue or accounts.
	tmWalk := time.Now()
	err = filepath.WalkDir(srcDataDir, func(srcpath string, d fs.DirEntry, err error) error {
		if err != nil {
			xerrx("walking path", err, slog.String("path", srcpath))
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
		case "auth.db", "dmarcrpt.db", "dmarceval.db", "mtasts.db", "tlsrpt.db", "tlsrptresult.db", "receivedid.key", "ctl":
			// Already handled.
			return nil
		case "lastknownversion": // Optional file, not yet handled.
		default:
			xwarnx("backing up unrecognized file", nil, slog.String("path", p))
		}
		backupFile(p)
		return nil
	})
	if err != nil {
		xerrx("walking other files (not backed up properly)", err, slog.Duration("duration", time.Since(tmWalk)))
	} else {
		xvlog("walking other files finished", slog.Duration("duration", time.Since(tmWalk)))
	}

	xvlog("backup finished", slog.Duration("duration", time.Since(tmStart)))

	xwriter.xclose()

	if incomplete {
		xctl.xwrite("errors were encountered during backup")
	} else {
		xctl.xwriteok()
	}
}
