default: fetch link

fetch:
	./fetch.sh

link:
	go run -tags link link.go -- ../*.go ../*/*.go

genxr:
	go run xr.go -- xr/dev $$(git rev-parse --short HEAD) $$(git log -1 --date=format:"%Y-%m-%d" --format="%ad") $$(git tag | tail -n1) ../*.go ../*/*.go

check:
	# output should be empty
	-grep '	' index.txt  | grep -E -v '^[^	]+	[^	]+	[^	]+	[^	]+$$'
