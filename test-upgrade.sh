#!/bin/sh

# todo: should we also test with mox.conf and domains.conf files? should "mox backup" and "mox gentestdata" add them, and "mox verifydata" use them?

set -e
# set -x

(rm -r testdata/upgrade 2>/dev/null || exit 0)
mkdir testdata/upgrade
cd testdata/upgrade

# Check that we can upgrade what we currently generate.
../../mox gentestdata data
../../mox verifydata data
rm -r data

# For each historic release (i.e. all tagged versions) except the first few that
# didn't have the gentestdata command, we generate a data directory for testing
# and simulate upgrade to currently checked out version.
# The awk command reverses the tags, so we try the previous release first since
# it is the most likely to fail.
tagsrev=$(git tag --sort creatordate | grep -v '^v0\.0\.[123]$' | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }')
if test "$tagsrev" = ""; then exit 0; fi
for tag in $tagsrev; do
	echo "Testing upgrade from $tag to current."
	mkdir $tag
	(CGO_ENABLED=0 GOBIN=$PWD/$tag go install github.com/mjl-/mox@$tag)
	# Generate with historic release.
	./$tag/mox gentestdata $tag/data
	# Verify with current code.
	../../mox verifydata $tag/data
	rm -r $tag/data
done

# Also go step-wise through each released version. Having upgraded step by step
# can have added more schema upgrades to the database files.
tags=$(git tag --sort creatordate | grep -v '^v0\.0\.[123]$' | cat)
first=yes
for tag in $tags; do
	if test "$first" = yes; then
		echo "Starting with test data for $tag."
		./$tag/mox gentestdata stepdata
		first=
	else
		echo "Upgrade data to $tag."
		./$tag/mox verifydata stepdata
	fi
done
echo "Testing final upgrade to current."
../../mox verifydata stepdata
rm -r stepdata
rm */mox
cd ../..
rmdir testdata/upgrade/* testdata/upgrade
