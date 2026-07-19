#!/usr/bin/env bash
set -euo pipefail

# - todo: get tsc to not emit semicolons except for the handful cases where it is needed.
# - todo: get tsc to directly print unix line numbers without --pretty (which seems unaware of termcap).
# - todo: get tsc to not turn multiline statements into one huge line. makes the dom-building statements unreadable in the js output.

out=$1
shift
outbasename=$(dirname $out)/$(basename $out .js)
cat "$@" >$outbasename-spaces.ts
./node_modules/.bin/tsc --noEmitOnError true --pretty false --newLine lf --strict --allowUnreachableCode false --allowUnusedLabels false --noFallthroughCasesInSwitch true --noImplicitReturns true --noUnusedLocals true --noImplicitThis true --noUnusedParameters true --target es2022 --module es2022 $outbasename-spaces.ts | sed -E 's/^([^\(]+)\(([0-9]+),([0-9]+)\):/\1:\2:\3: /'
CGO_ENABLED=0 go run unexpand.go -t 4 <$outbasename-spaces.js >$outbasename.js
rm $outbasename-spaces.ts $outbasename-spaces.js
