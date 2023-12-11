This directory lists incompatible changes between released versions for packages
intended for reuse by third party projects, as listed in packages.txt. These
files are generated using golang.org/x/exp/cmd/apidiff (see
https://pkg.go.dev/golang.org/x/exp/apidiff) and ../apidiff.sh.

There is no guarantee that there will be no breaking changes. With Go's
dependency versioning approach (minimal version selection), Go code will never
unexpectedly stop compiling. Incompatibilities will show when explicitly
updating a dependency. Making the required changes is typically fairly
straightforward.
