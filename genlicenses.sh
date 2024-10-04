#!/bin/sh
rm -r licenses
set -e
for p in $(cd vendor && find . -iname '*license*' -or -iname '*licence*' -or -iname '*notice*' -or -iname '*patent*'); do
	(set +e; mkdir -p $(dirname licenses/$p))
	cp vendor/$p licenses/$p
done
