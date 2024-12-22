package imapserver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// Fuzz the server. For each fuzz string, we set up servers in various connection states, and write the string as command.
func FuzzServer(f *testing.F) {
	seed := []string{
		fmt.Sprintf("authenticate plain %s", base64.StdEncoding.EncodeToString([]byte("\u0000mjl@mox.example\u0000testtest"))),
		"*",
		"capability",
		"noop",
		"logout",
		"select inbox",
		"examine inbox",
		"unselect",
		"close",
		"expunge",
		"subscribe inbox",
		"unsubscribe inbox",
		`lsub "" "*"`,
		`list "" ""`,
		`namespace`,
		"enable utf8=accept",
		"create inbox",
		"create tmpbox",
		"rename tmpbox ntmpbox",
		"delete ntmpbox",
		"status inbox (uidnext messages uidvalidity deleted size unseen recent)",
		"append inbox (\\seen) {2+}\r\nhi",
		"fetch 1 all",
		"fetch 1 body",
		"fetch 1 (bodystructure)",
		`store 1 flags (\seen \answered)`,
		`store 1 +flags ($junk)`,
		`store 1 -flags ($junk)`,
		"noop",
		"copy 1Trash",
		"copy 1 Trash",
		"move 1 Trash",
		"search 1 all",
	}
	for _, cmd := range seed {
		const tag = "x "
		f.Add(tag + cmd)
	}

	log := mlog.New("imapserver", nil)
	mox.Context = ctxbg
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/imapserverfuzz/mox.conf")
	mox.MustLoadConfig(true, false)
	dataDir := mox.ConfigDirPath(mox.Conf.Static.DataDir)
	os.RemoveAll(dataDir)
	acc, err := store.OpenAccount(log, "mjl")
	if err != nil {
		f.Fatalf("open account: %v", err)
	}
	defer func() {
		acc.Close()
		acc.CheckClosed()
	}()
	err = acc.SetPassword(log, password0)
	if err != nil {
		f.Fatalf("set password: %v", err)
	}
	defer store.Switchboard()()

	comm := store.RegisterComm(acc)
	defer comm.Unregister()

	var cid int64 = 1

	var fl *os.File
	if false {
		fl, err = os.OpenFile("fuzz.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			f.Fatalf("fuzz log")
		}
		defer fl.Close()
	}
	flog := func(err error, msg string) {
		if fl != nil && err != nil {
			fmt.Fprintf(fl, "%s: %v\n", msg, err)
		}
	}

	f.Fuzz(func(t *testing.T, s string) {
		run := func(cmds []string) {
			limitersInit() // Reset rate limiters.
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()

			go func() {
				defer func() {
					x := recover()
					// Protocol can become botched, when fuzzer sends literals.
					if x == nil {
						return
					}
					err, ok := x.(error)
					if !ok || (!errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, io.EOF)) {
						panic(x)
					}
				}()

				defer clientConn.Close()

				err := clientConn.SetDeadline(time.Now().Add(time.Second))
				flog(err, "set client deadline")
				client, _ := imapclient.New(clientConn, true)

				for _, cmd := range cmds {
					client.Commandf("", "%s", cmd)
					client.Response()
				}
				client.Commandf("", "%s", s)
				client.Response()
			}()

			err = serverConn.SetDeadline(time.Now().Add(time.Second))
			flog(err, "set server deadline")
			serve("test", cid, nil, serverConn, false, true, false)
			cid++
		}

		// Each command brings the connection state one step further. We try the fuzzing
		// input for each state.
		run([]string{})
		run([]string{`login mjl@mox.example "` + password0 + `"`})
		run([]string{`login mjl@mox.example "` + password0 + `"`, "select inbox"})
		xappend := fmt.Sprintf("append inbox () {%d+}\r\n%s", len(exampleMsg), exampleMsg)
		run([]string{`login mjl@mox.example "` + password0 + `"`, "select inbox", xappend})
	})
}
