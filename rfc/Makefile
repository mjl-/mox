default: fetch link

fetch:
	./fetch.sh

link:
	go run -tags link link.go -- ../*.go ../*/*.go

xr:
	go run xr.go -- xr-dev $$(git rev-parse --short HEAD) $$(git tag | tail -n1) ../*.go ../*/*.go
