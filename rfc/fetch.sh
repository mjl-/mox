#!/bin/sh
for number in $(sed -n 's/^\([0-9][0-9]*\)[ \t].*$/\1/p' index.txt); do
	if ! test -f "$number"; then
		curl https://www.rfc-editor.org/rfc/rfc$number.txt >$number || rm $number
	fi
done

for name in $(sed -n 's/^\([0-9][0-9]*-eid[0-9][0-9]*\)[ \t].*$/\1/p' index.txt); do
	if ! test -f "$name"; then
		rfc=$(echo $name | cut -f1 -d-)
		eid=$(echo $name | cut -f2 -d-)
		curl https://www.rfc-editor.org/errata/$eid | go run errata.go >$name || rm $name
	fi
done
