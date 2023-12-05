package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/store"
)

func cmdExportMaildir(c *cmd) {
	c.params = "dst-dir account-path [mailbox]"
	c.help = `Export one or all mailboxes from an account in maildir format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections. To export from a running instance, use
the accounts web page.
`
	args := c.Parse()
	xcmdExport(false, args, c)
}

func cmdExportMbox(c *cmd) {
	c.params = "dst-dir account-path [mailbox]"
	c.help = `Export messages from one or all mailboxes in an account in mbox format.

Using mbox is not recommended. Maildir is a better format.

Export bypasses a running mox instance. It opens the account mailbox/message
database file directly. This may block if a running mox instance also has the
database open, e.g. for IMAP connections. To export from a running instance, use
the accounts web page.

For mbox export, "mboxrd" is used where message lines starting with the magic
"From " string are escaped by prepending a >. All ">*From " are escaped,
otherwise reconstructing the original could lose a ">".
`
	args := c.Parse()
	xcmdExport(true, args, c)
}

func xcmdExport(mbox bool, args []string, c *cmd) {
	if len(args) != 2 && len(args) != 3 {
		c.Usage()
	}

	dst := args[0]
	accountDir := args[1]
	var mailbox string
	if len(args) == 3 {
		mailbox = args[2]
	}

	dbpath := filepath.Join(accountDir, "index.db")
	db, err := bstore.Open(context.Background(), dbpath, &bstore.Options{Timeout: 5 * time.Second, Perm: 0660}, store.DBTypes...)
	xcheckf(err, "open database %q", dbpath)
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("closing db after export: %v", err)
		}
	}()

	a := store.DirArchiver{Dir: dst}
	err = store.ExportMessages(context.Background(), c.log, db, accountDir, a, !mbox, mailbox)
	xcheckf(err, "exporting messages")
	err = a.Close()
	xcheckf(err, "closing archiver")
}
