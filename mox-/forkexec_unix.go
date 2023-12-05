//go:build unix

package mox

import (
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/exp/slog"
)

// Fork and exec as unprivileged user.
//
// We don't use just setuid because it is hard to guarantee that no other
// privileged go worker processes have been started before we get here. E.g. init
// functions in packages can start goroutines.
func ForkExecUnprivileged() {
	prog, err := os.Executable()
	if err != nil {
		pkglog.Fatalx("finding executable for exec", err)
	}

	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	var addrs []string
	for addr, f := range passedListeners {
		files = append(files, f)
		addrs = append(addrs, addr)
	}
	var paths []string
	for path, fl := range passedFiles {
		for _, f := range fl {
			files = append(files, f)
			paths = append(paths, path)
		}
	}
	env := os.Environ()
	env = append(env, "MOX_SOCKETS="+strings.Join(addrs, ","), "MOX_FILES="+strings.Join(paths, ","))

	p, err := os.StartProcess(prog, os.Args, &os.ProcAttr{
		Env:   env,
		Files: files,
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: Conf.Static.UID,
				Gid: Conf.Static.GID,
			},
		},
	})
	if err != nil {
		pkglog.Fatalx("fork and exec", err)
	}
	CleanupPassedFiles()

	// If we get a interrupt/terminate signal, pass it on to the child. For interrupt,
	// the child probably already got it.
	// todo: see if we tie up child and root process so a kill -9 of the root process
	// kills the child process too.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigc
		p.Signal(sig)
	}()

	st, err := p.Wait()
	if err != nil {
		pkglog.Fatalx("wait", err)
	}
	code := st.ExitCode()
	pkglog.Print("stopping after child exit", slog.Int("exitcode", code))
	os.Exit(code)
}
