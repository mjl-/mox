#!/bin/sh
(
cat <<EOF
/*
Command bstore provides commands for inspecting a bstore database.

Subcommands:

EOF
go run cmd/bstore/bstore.go 2>&1 | sed 's/^/	/' | grep -v 'exit status'
echo '*/'
echo 'package main'
) >cmd/bstore/doc.go
