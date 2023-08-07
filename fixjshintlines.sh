#!/bin/sh
# change output to regular filename:linenumber format for easier opening.
arg=$(echo $1 | sed 's,/,\\/,')
exec sed "s/^\([^:]*\): line \([0-9][0-9]*\), \(.*\)\$/${arg}\1:\2: \3/"
