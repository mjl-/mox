#!/bin/sh
set -e

prevversion=$(go list -mod=readonly -m -f '{{ .Version }}' github.com/mjl-/mox@latest)
nextversion=$(cat next.txt)
if ! test -d tmp/mox-$prevversion; then
	mkdir -p tmp/mox-$prevversion
	git archive --format=tar $prevversion | tar -C tmp/mox-$prevversion -xf -
fi
(rm -r tmp/apidiff || exit 0)
mkdir -p tmp/apidiff/$prevversion tmp/apidiff/next
(rm apidiff/$nextversion.txt || exit 0)
(
echo "Below are the incompatible changes between $prevversion and $nextversion, per package."
echo
) >>apidiff/$nextversion.txt
for p in $(cat apidiff/packages.txt); do
	(cd tmp/mox-$prevversion && apidiff -w ../apidiff/$prevversion/$p.api ./$p)
	apidiff -w tmp/apidiff/next/$p.api ./$p
	(
	echo '#' $p
	apidiff -incompatible tmp/apidiff/$prevversion/$p.api tmp/apidiff/next/$p.api
	echo
	) >>apidiff/$nextversion.txt
done
