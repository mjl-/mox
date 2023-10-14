package mox

// Fork and exec as unprivileged user.
//
// Not implemented yet on windows. Would need to understand its security model
// first.
func ForkExecUnprivileged() {
	xlog.Fatal("fork and exec to unprivileged user not yet implemented on windows")
}
