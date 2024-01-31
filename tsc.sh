#!/usr/bin/env bash
set -euo pipefail

# - todo: get tsc to not emit semicolons except for the handful cases where it is needed.
# - todo: get tsc to directly print unix line numbers without --pretty (which seems unaware of termcap).
# - todo: get tsc to not turn multiline statements into one huge line. makes the dom-building statements unreadable in the js output.

out=$1
shift
./node_modules/.bin/tsc --noEmitOnError true --pretty false --newLine lf --strict --allowUnreachableCode false --allowUnusedLabels false --noFallthroughCasesInSwitch true --noImplicitReturns true --noUnusedLocals true --noImplicitThis true --noUnusedParameters true --target es2022 --module none --outFile $out.spaces "$@" | sed -E 's/^([^\(]+)\(([0-9]+),([0-9]+)\):/\1:\2:\3: /'
unexpand -t4 <$out.spaces >$out
rm $out.spaces
