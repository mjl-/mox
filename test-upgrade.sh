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
../../mox openaccounts data test0 test1 test2
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
	# Verify with current code. v0.0.[45] had a message with wrong Size. We don't
	# want to abort the upgrade check because of it.
	if test $tag = v0.0.4 -o $tag = v0.0.5; then
		../../mox verifydata -skip-size-check $tag/data
	else
		../../mox verifydata $tag/data
	fi
	echo
	rm -r $tag/data
done

# Do upgrade from v0.0.5 with big import straight to current. Will create
# multiple new indices so may be heavier during upgrade.
echo "Testing upgrade from v0.0.5 + big import straight to current."
tag=v0.0.5
./$tag/mox gentestdata stepdata
ulimit -S -d unlimited
echo 'Importing bulk data for upgrading.'
gunzip < ../upgradetest.mbox.gz | time ./$tag/mox ximport mbox ./stepdata/accounts/test0 upgradetest /dev/stdin
echo
ulimit -S -d 768000
time ../../mox -cpuprof ../../upgrade0-verifydata.cpu.pprof -memprof ../../upgrade0-verifydata.mem.pprof verifydata -skip-size-check stepdata
time ../../mox -loglevel info -cpuprof ../../upgrade0-openaccounts.cpu.pprof -memprof ../../upgrade0-openaccounts.mem.pprof openaccounts stepdata test0 test1 test2
rm -r stepdata


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
		if test $tag = v0.0.4 -o $tag = v0.0.5; then
			time ./$tag/mox verifydata stepdata
		else
			time ./$tag/mox verifydata -skip-size-check stepdata
			time ./$tag/mox openaccounts stepdata test0 test1 test2
		fi
		echo
	fi
done
echo "Testing final upgrade to current."
time ../../mox -cpuprof ../../upgrade1-verifydata.cpu.pprof -memprof ../../upgrade1-verifydata.mem.pprof verifydata -skip-size-check stepdata
time ../../mox -loglevel info -cpuprof ../../upgrade1-openaccounts.cpu.pprof -memprof ../../upgrade1-openaccounts.mem.pprof openaccounts stepdata test0 test1 test2
rm -r stepdata
rm */mox
cd ../..
rmdir testdata/upgrade/* testdata/upgrade
