SHELL=/bin/bash -o pipefail

build:
	go build ./...
	go vet ./...

test:
	golint
	go test -cover ./...

coverage:
	go test -coverprofile=coverage.out -test.outputdir . --
	go tool cover -html=coverage.out

fmt:
	go fmt ./...

clean:
	go clean

# for testing generated typescript
setup:
	-mkdir -p node_modules/.bin
	npm install typescript@3.0.1 typescript-formatter@7.2.2
