#!/bin/sh

# note: If testdata/upgradetest.mbox.gz exists it will be imported it as part of
# testing the upgrades. If this is a large mailbox, it will highlight performance
# or resource consumption issues during upgrades.

# todo: should we also test with mox.conf and domains.conf files? should "mox backup" and "mox gentestdata" add them, and "mox verifydata" use them?

set -e
# set -x

# We'll set a max memory limit during upgrades. We modify the softlimit when
# importing the potentially large mbox file.
# Currently at 768MB, needed for upgrading with 500k messages from v0.0.5 to
# v0.0.6 (two new indexes on store.Message).
ulimit -S -d 768000

(rm -r testdata/upgrade 2>/dev/null || exit 0)
mkdir testdata/upgrade
cd testdata/upgrade

# Check that we can upgrade what we currently generate.
../../mox gentestdata data
../../mox verifydata data
rm -r data
echo

# For each historic release (i.e. all tagged versions) except the first few that
# didn't have the gentestdata command, we generate a data directory for testing
# and simulate upgrading to the currently checked out version.
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
	echo
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
		echo
		first=
	else
		# v0.0.5 got the ximport command
		if test $tag = v0.0.5 -a -f ../upgradetest.mbox.gz; then
			ulimit -S -d unlimited
			echo 'Importing bulk data for upgrading.'
			gunzip < ../upgradetest.mbox.gz | time ./$tag/mox ximport mbox ./stepdata/accounts/test0 upgradetest /dev/stdin
			echo
			ulimit -S -d 768000
		fi

		echo "Upgrade data to $tag."
		time ./$tag/mox verifydata stepdata
		echo
	fi
done
echo "Testing final upgrade to current."
time ../../mox verifydata stepdata
rm -r stepdata
rm */mox
cd ../..
rmdir testdata/upgrade/* testdata/upgrade
