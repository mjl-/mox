build:
	go build ./...
	go vet ./...
	GOARCH=386 go vet ./...
	staticcheck -checks 'all,-ST1012' ./...
	./gendoc.sh

fmt:
	go fmt ./...
	gofmt -w -s *.go cmd/bstore/*.go

test:
	go test -race -shuffle=on -coverprofile cover.out
	go tool cover -html=cover.out -o cover.html

benchmark:
	go test -bench .

fuzz:
	go test -fuzz .
