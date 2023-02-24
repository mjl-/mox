default: build

build:
	# build early to catch syntax errors
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet -tags integration ./...
	./gendoc.sh
	(cd http && CGO_ENABLED=0 go run ../vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none Admin) >http/adminapi.json
	(cd http && CGO_ENABLED=0 go run ../vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none Account) >http/accountapi.json
	# build again, files above are embedded
	CGO_ENABLED=0 go build

test:
	CGO_ENABLED=0 go test -shuffle=on -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

test-race:
	CGO_ENABLED=1 go test -race -shuffle=on -covermode atomic -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

check:
	staticcheck ./...
	staticcheck -tags integration

# having "err" shadowed is common, best to not have others
check-shadow:
	go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

fuzz:
	go test -fuzz FuzzParseSignature -fuzztime 5m ./dkim
	go test -fuzz FuzzParseRecord -fuzztime 5m ./dkim
	go test -fuzz . -fuzztime 5m ./dmarc
	go test -fuzz . -fuzztime 5m ./dmarcrpt
	go test -fuzz . -parallel 1 -fuzztime 5m ./imapserver
	go test -fuzz . -parallel 1 -fuzztime 5m ./junk
	go test -fuzz FuzzParseRecord -fuzztime 5m ./mtasts
	go test -fuzz FuzzParsePolicy -fuzztime 5m ./mtasts
	go test -fuzz . -parallel 1 -fuzztime 5m ./smtpserver
	go test -fuzz . -fuzztime 5m ./spf
	go test -fuzz FuzzParseRecord -fuzztime 5m ./tlsrpt
	go test -fuzz FuzzParseMessage -fuzztime 5m ./tlsrpt

integration-build:
	docker-compose -f docker-compose-integration.yml build --no-cache moxmail

integration-start:
	-MOX_UID=$$(id -u) MOX_GID=$$(id -g) docker-compose -f docker-compose-integration.yml run moxmail /bin/bash
	MOX_UID= MOX_GID= docker-compose -f docker-compose-integration.yml down

# run from within "make integration-start"
integration-test:
	CGO_ENABLED=0 go test -tags integration

imaptest-build:
	-MOX_UID=$$(id -u) MOX_GID=$$(id -g) docker-compose -f docker-compose-imaptest.yml build --no-cache mox

imaptest-run:
	-rm -r testdata/imaptest/data
	mkdir testdata/imaptest/data
	MOX_UID=$$(id -u) MOX_GID=$$(id -g) docker-compose -f docker-compose-imaptest.yml run --entrypoint /usr/local/bin/imaptest imaptest host=mox port=1143 user=mjl@mox.example pass=testtest mbox=imaptest.mbox
	MOX_UID= MOX_GID= docker-compose -f docker-compose-imaptest.yml down

fmt:
	go fmt ./...
	gofmt -w -s *.go */*.go

jswatch:
	inotifywait -m -e close_write http/admin.html http/account.html | xargs -n2 sh -c 'echo changed; ./checkhtmljs http/admin.html http/account.html'

jsinstall:
	-mkdir -p node_modules/.bin
	npm install jshint@2.13.2

docker:
	docker build -t mox:latest .
