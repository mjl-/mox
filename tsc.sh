#!/usr/bin/env bash
set -euo pipefail

# - todo: get tsc to directly print unix line numbers without --pretty (which seems unaware of termcap).
# - todo: get tsc to not turn multiline statements into one huge line. makes the dom-building statements unreadable in the js output.
# - todo: get bundler to not emit semicolons except for the handful cases where it is needed.

out=$1
shift

./node_modules/.bin/tsc --noEmitOnError true --pretty false --newLine lf --strict --allowUnreachableCode false --allowUnusedLabels false --noFallthroughCasesInSwitch true --noImplicitReturns true --noUnusedLocals true --noImplicitThis true --noUnusedParameters true --target es2022 --module es2022 --outDir .js "$@" | sed -E 's/^([^\(]+)\(([0-9]+),([0-9]+)\):/\1:\2:\3: /'
./node_modules/.bin/esbuild --log-level=warning --bundle --keep-names --outfile=.js/$out.spaces.js .js/$(echo "$1" | sed 's/\.ts$/.js/')
CGO_ENABLED=0 go run unexpand.go -t 2 <.js/$out.spaces.js >$out
rm .js/$out.spaces.js
