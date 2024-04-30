package webops

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/store"
)

// Export is used by webmail and webaccount to export messages of one or
// multiple mailboxes, in maildir or mbox format, in a tar/tgz/zip archive or
// direct mbox.
func Export(log mlog.Log, accName string, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "405 - method not allowed - use post", http.StatusMethodNotAllowed)
		return
	}

	mailbox := r.FormValue("mailbox") // Empty means all.
	format := r.FormValue("format")
	archive := r.FormValue("archive")
	recursive := r.FormValue("recursive") != ""
	switch format {
	case "maildir", "mbox":
	default:
		http.Error(w, "400 - bad request - unknown format", http.StatusBadRequest)
		return
	}
	switch archive {
	case "none", "tar", "tgz", "zip":
	default:
		http.Error(w, "400 - bad request - unknown archive", http.StatusBadRequest)
		return
	}
	if archive == "none" && (format != "mbox" || recursive) {
		http.Error(w, "400 - bad request - archive none can only be used with non-recursive mbox", http.StatusBadRequest)
		return
	}

	acc, err := store.OpenAccount(log, accName)
	if err != nil {
		log.Errorx("open account for export", err)
		http.Error(w, "500 - internal server error", http.StatusInternalServerError)
		return
	}
	defer func() {
		err := acc.Close()
		log.Check(err, "closing account")
	}()

	name := strings.ReplaceAll(mailbox, "/", "-")
	if name == "" {
		name = "all"
	}
	filename := fmt.Sprintf("mailexport-%s-%s", name, time.Now().Format("20060102-150405"))
	filename += "." + format
	var archiver store.Archiver
	if archive == "none" {
		w.Header().Set("Content-Type", "application/mbox")
		archiver = &store.MboxArchiver{Writer: w}
	} else if archive == "tar" {
		// Don't tempt browsers to "helpfully" decompress.
		w.Header().Set("Content-Type", "application/x-tar")
		archiver = store.TarArchiver{Writer: tar.NewWriter(w)}
		filename += ".tar"
	} else if archive == "tgz" {
		// Don't tempt browsers to "helpfully" decompress.
		w.Header().Set("Content-Type", "application/octet-stream")

		gzw := gzip.NewWriter(w)
		defer func() {
			_ = gzw.Close()
		}()
		archiver = store.TarArchiver{Writer: tar.NewWriter(gzw)}
		filename += ".tgz"
	} else {
		w.Header().Set("Content-Type", "application/zip")
		archiver = store.ZipArchiver{Writer: zip.NewWriter(w)}
		filename += ".zip"
	}
	defer func() {
		err := archiver.Close()
		log.Check(err, "exporting mail close")
	}()
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	if err := store.ExportMessages(r.Context(), log, acc.DB, acc.Dir, archiver, format == "maildir", mailbox, recursive); err != nil {
		log.Errorx("exporting mail", err)
	}
}
