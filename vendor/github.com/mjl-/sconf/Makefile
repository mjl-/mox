build:
	go build ./...
	go vet ./...
	GOARCH=386 go vet ./...
	staticcheck ./...

fmt:
	gofmt -w -s *.go cmd/*/*.go

test:
	go test -shuffle=on -coverprofile cover.out
	go tool cover -html=cover.out -o cover.html
