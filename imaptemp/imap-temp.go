/*
Written 2024 by Harald Rudell <harald.rudell@gmail.com> (https://haraldrudell.github.io/haraldrudell/)
*/

package imaptemp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/exp/slog"

	_ "embed"

	"github.com/mjl-/mox/imapserver"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// NewImapMem returns an object that runs an temporary-storage imap server
//   - configurable: logging, timeouts, file-system location
//   - logger is optional logger. If missing or nil, logging is to standard error, text with all log-levels
//   - — [golang.org/x/exp/slog.New] creates a logger that may control:
//   - — what [io.Writer] to send logging to, eg. standard output or file
//   - — log format, eg. text or json
//   - — log level eg. [github.com/mjl-/mox/mlog.LevelError]
//   - because package [github.com/mjl-/mox/store] is not thread-safe:
//   - — only one instance at any one time per process
//   - — If regular mox code is used, that and CreateSocket can only be invoked by a single thread due to lack of thread-safety
//   - file-system storage depends on process’ working directory
//   - — multiple processes must be in different working directories
//
// Example:
//
//	var options = slog.HandlerOptions{
//	  Level: minLevel,
//	  }
//	levelFilteredLogger = slog.New(slog.NewTextHandler(os.Stdout, &options))
func NewImapTemp(logger ...*slog.Logger) (imapTemp *ImapTemp) {
	var _ slog.TextHandler

	var createNewStructuredLogger *slog.Logger
	if len(logger) > 0 {
		createNewStructuredLogger = logger[0]
		if createNewStructuredLogger != nil {
			mlog.LogModel.Store(createNewStructuredLogger)
		}
	}
	return &ImapTemp{
		pkglog: mlog.New(logPackageLabel, createNewStructuredLogger),
	}
}

// UseTimeouts ensures that mox’ socket timeouts are active and cause disconnections
//   - as default, mox timeouts aree disabled allowing to debug and single step for
//     extended periods of time
func (i *ImapTemp) UseTimeouts() { i.useTimeouts.Store(true) }

// CreateSocket returns a socket where an IMAP4Rev2 server is listening
//   - imapConn.Close is thread-safe idempotent
//   - if CreateSocket returns successfully, Close must be invoked to release resources
//   - if dir is provided, it is a file-system directory where mox wil keep its data
//   - CreateSocket can only be invoked once per ImapTemp instance
//   - only one ImapTemp can be active at a time per process
//   - for thread-safety, regular mox code should not be used in a process where CreateSocket is used
//   - thread-safe
//   - mox start/stop takes around 500 ms
//   - —
//   - the returned socket imapConn is an emulated network socket bypassing networking instead connecting
//     directly to the server via an unbuffered Go channel:
//   - — no TLS
//   - — no TCP port
//   - — [io.ReadWriteCloser] over unbuffered channels
//   - a server thread is launched
func (i *ImapTemp) CreateSocket(dir ...string) (imapConn net.Conn, err error) {
	if len(dir) > 0 {
		if i.dir, err = filepath.Abs(dir[0]); err != nil {
			return
		}
	}

	// ensure that CreateSocket is only invoked once for this ImapTemp instance
	if !i.isCreateServer.CompareAndSwap(false, true) {
		err = errors.New("CreateSocket invoked more than once")
		return
	}

	// to enforce one mox at a time per process,
	// the gating value is a private top-level variable
	//	- the consumer must assure that:
	//	- — regular mox is not used in a non-thread-safe way at any time in a process using ImapTemp
	if !isRunning.CompareAndSwap(nil, i) {
		err = errors.New("ImapTemp is already running")
		return
	}
	defer i.createEnd(&err)
	// this ImapTemp now owns mox until isRunning is set to nil

	// create a unique file-system directory for storage
	if i.dir == "" {
		const useDefaultTempDir = ""
		if i.dir, err = os.MkdirTemp(useDefaultTempDir, dirTemplate); err != nil {
			return
		}
		i.doRemove.Store(true)
	}

	// make mox able to run
	internals.LimitersInit()
	// store.InitialUIDValidity is not thread-safe
	//	- reading and writing isRunning makes access thread-safe for ImapTemp instances
	i.initialUIDValidity = store.InitialUIDValidity
	store.InitialUIDValidity = validityOne
	// here we must copy mox test code into the real world
	//	- server_test.go:337 startArgs
	// server new connection rate-limits
	// mox handles cancel of this context
	mox.Context = context.Background()
	// write “mox.conf”
	mox.ConfigStaticPath = filepath.Join(i.dir, moxConf)
	if err = os.WriteFile(mox.ConfigStaticPath, moxConfData, urwx); err != nil {
		return
	}
	// write “domains.conf”
	mox.ConfigDynamicPath = filepath.Join(i.dir, domainsConf)
	if err = os.WriteFile(mox.ConfigDynamicPath, domainsConfData, urwx); err != nil {
		return
	}
	// do not load certificates from configuration
	const doNotLoadTLSKeyCerts = false
	// do not load certificate renewal data from configuration
	const doNotCheckACMEHosts = false
	// errs is a list of non-nil errors
	if errs := mox.LoadConfig(context.Background(), i.pkglog, doNotLoadTLSKeyCerts, doNotCheckACMEHosts); len(errs) > 0 {
		err = errs[0]
		return
	}
	// create account: opening it will create
	var acc *store.Account
	if acc, err = store.OpenAccount(i.pkglog, accountName); err != nil {
		return
		// the account will have a password
	} else if err = acc.SetPassword(i.pkglog, passwd); err != nil {
		return
	}

	// launch server thread

	// some notification bus
	var switchStopFunc = store.Switchboard()
	// the socket used by the server
	//	- imapConn is the connection where IMAP4rev2 protocol is available
	var connUsedByServer net.Conn
	connUsedByServer, imapConn = net.Pipe()
	// disable all deadlines on connUsedByServer
	if !i.useTimeouts.Load() {
		connUsedByServer = NewNoDeadline(connUsedByServer)
	}
	// make imapConn.Close idempotent
	//	- an imap client may close on:
	//	- — server closing or
	//	- — protocol error or
	//	- — after sending imap LOGOUT
	//	- making Close idempotent allows for the connection to with certainty be closed exactly once
	imapConn = newCloseOncer(imapConn)
	i.imapConn = imapConn
	// make server-thread awaitable
	var serverExit = make(chan struct{})
	i.serverExit = serverExit
	go i.imapServerThread(connUsedByServer, switchStopFunc, serverExit)

	return
}

// After successful CreateSocket, EndCh is available
//   - EndCh returns a channel that closes once resources are released
//   - thread-safe
func (i *ImapTemp) EndCh() (endCh <-chan struct{}) {
	i.isCreateServer.Load()
	endCh = i.serverExit
	return
}

// Creds returns login credentials for the imap server’s only account
//   - thread-safe
func (i *ImapTemp) Creds() (emailAcccountName, password string) { return accountEmail, passwd }

// Dir returns absolute path to temporary file-system storage
//   - no consumer should need this
//   - thread-safe
func (i *ImapTemp) Dir() (dir string) {
	i.isCreateServer.Load()
	dir = i.dir
	return
}

// Close releases resources from a successful CreateSocket invocation
//   - thread-safe
func (i *ImapTemp) Close() (err error) {
	if isRunning.Load() != i {
		return // this is not an active imapTemp
	}
	err = i.unCreate()

	return
}

// imapServerThread runs a server until ?
func (i *ImapTemp) imapServerThread(connUsedByServer net.Conn, switchStopFunc func(), serverExit chan<- struct{}) {
	defer close(serverExit)
	defer i.recoverPanic(recover())
	defer switchStopFunc()

	// do not use TLS requiring certificates and such
	const isTLS = false
	// do not use TLS requiring certificates and such
	const allowLoginWithoutTLS = true
	var noTLSConfig *tls.Config
	// cid is numbering of connection used for logging
	var cid = connectionNumberer.Add(1)
	internals.Serve(listenerName, cid, noTLSConfig, connUsedByServer, isTLS, allowLoginWithoutTLS)
}

// recoverPanic stores any server-thread runtime error at ImapTemp.serverPanic
func (i *ImapTemp) recoverPanic(panicValue any) {
	var err error
	var ok bool
	if panicValue == nil {
		return
	} else if err, ok = panicValue.(error); !ok {
		err = fmt.Errorf("server-thread PANIC: non-error value: %T %+[1]v", panicValue)
	} else {
		err = fmt.Errorf("server-thread PANIC: %w", err)
	}
	i.serverPanic = err
}

// createEnd invokes unCreate if CreateSocket failed
func (i *ImapTemp) createEnd(errp *error) {
	if *errp == nil {
		i.isCreateServer.Store(true) // make any writes thread-safe
		return                       // CreateSocket success return
	}
	// an error is already present, so ignore error here
	_ = i.unCreate()
}

// unCreate undos any actions by CreateSocket
//   - only inoked on:
//   - — CreateSocket failing
//   - — Close after CreateSocket success
func (i *ImapTemp) unCreate() (err error) {
	i.isCreateServer.Load()    // make any previous writes thread-safe
	defer isRunning.Store(nil) // release mox for other instances

	store.InitialUIDValidity = i.initialUIDValidity
	if closer := i.imapConn; closer != nil {
		err = closer.Close()
	}
	if serverExit := i.serverExit; serverExit != nil {
		<-serverExit
		if e := i.serverPanic; e != nil {
			if err == nil {
				err = e
			} else {
				i.pkglog.Error(e.Error())
			}
		}
	}
	// remove temporary files, ignore error if an error is already present
	if i.doRemove.Load() {
		if e := os.RemoveAll(i.dir); e != nil && err == nil {
			err = e
		}
	}

	return
}

//go:embed mox.conf
var moxConfData []byte

//go:embed domains.conf
var domainsConfData []byte

// validityOne returns UIDValidity 1 during ImapTemp being active
func validityOne() (UIDValidity uint32) { return 1 }

const (
	// naming template for temporary file-system directory
	dirTemplate = "mox"
	// configuration file is hard-coded in the test code
	moxConf = "mox.conf"
	// some filename mox needs
	domainsConf = "domains.conf"
	// log label is hard-coded in test code
	logPackageLabel = "imapserver"
	// accountName is imap server account login name
	//	- returned by Creds method
	accountName = "mjl"
	// impa LOGIN must be by email
	accountEmail = accountName + "@mox.example"
	// imap server account password
	//	- returned by Creds method
	passwd = "testtest"
	// listenerName is a label the server outputs when the connection is ready
	listenerName = "test"
	// filemode for created files
	urwx os.FileMode = 0700
)

// retrieve private identifiers from imapserver package
var internals = imapserver.Internals()

// connectionNumberer number connections 1… for logging
var connectionNumberer atomic.Int64

// isRunning ensures that only one ImapMem runs at any one time per process
//   - because mox uses non-thread-safe top-level variables, it is a process-scope top-level variable
//   - provides thread-safety for [store.InitialUIDValidity] and possibly the rest of mox
var isRunning atomic.Pointer[ImapTemp]

// ImapTemp runs an IMAP4Rev2 server with temporary storage for testing purposes
type ImapTemp struct {
	// pkglog is a standard error logger labeled “imapserver”
	pkglog mlog.Log
	// gates CreateSocket invocations
	//	- provides field thread-safety
	isCreateServer atomic.Bool
	// true if timeouts should not be disabled
	useTimeouts atomic.Bool
	// true if file system is not temporary and should not be removed
	doRemove atomic.Bool

	// absolute path to temporary file-system storage
	//	- thread-safe through isCreateServer read and write
	dir string
	// held temporary value
	//	- thread-safe through isCreateServer read and write
	initialUIDValidity func() uint32
	// imap connection to close on unCreate
	//	- may be nil
	//	- thread-safe through isCreateServer read and write
	imapConn io.Closer
	// serverExit closes on server thread exit
	//	- after successful Create value is available.
	//	- this channel will close on imap server thread-exit
	//	- may be nil
	//	- thread-safe through isCreateServer read and write
	serverExit <-chan struct{}
	// possible server panic
	//	- available after non-nil serverExit closes
	//	- thread-safe through isCreateServer read and write
	serverPanic error
}
