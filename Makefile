default: build

build: build0 frontend build1

build0:
	# build early to catch syntax errors
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet ./...
	./gendoc.sh
	./genapidoc.sh
	./gents.sh webadmin/api.json webadmin/api.ts
	./gents.sh webaccount/api.json webaccount/api.ts
	./gents.sh webmail/api.json webmail/api.ts

build1:
	# build again, api json files above are embedded and new frontend code generated
	CGO_ENABLED=0 go build

install: build0 frontend
	CGO_ENABLED=0 go install

race: build0
	go build -race

test:
	CGO_ENABLED=0 go test -fullpath -shuffle=on -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

test-race:
	CGO_ENABLED=1 go test -fullpath -race -shuffle=on -covermode atomic -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

test-more:
	TZ= CGO_ENABLED=0 go test -fullpath -shuffle=on -count 2 ./...

# note: if testdata/upgradetest.mbox.gz exists, its messages will be imported
# during tests. helpful for performance/resource consumption tests.
test-upgrade: build
	nice ./test-upgrade.sh

# needed for "check" target
install-staticcheck:
	CGO_ENABLED=0 go install honnef.co/go/tools/cmd/staticcheck@latest

install-ineffassign:
	CGO_ENABLED=0 go install github.com/gordonklaus/ineffassign@v0.1.0

check:
	CGO_ENABLED=0 go vet -tags integration
	CGO_ENABLED=0 go vet -tags website website/website.go
	CGO_ENABLED=0 go vet -tags link rfc/link.go
	CGO_ENABLED=0 go vet -tags errata rfc/errata.go
	CGO_ENABLED=0 go vet -tags xr rfc/xr.go
	GOARCH=386 CGO_ENABLED=0 go vet ./...
	CGO_ENABLED=0 ineffassign ./...
	CGO_ENABLED=0 staticcheck ./...
	CGO_ENABLED=0 staticcheck -tags integration
	CGO_ENABLED=0 staticcheck -tags website website/website.go
	CGO_ENABLED=0 staticcheck -tags link rfc/link.go
	CGO_ENABLED=0 staticcheck -tags errata rfc/errata.go
	CGO_ENABLED=0 staticcheck -tags xr rfc/xr.go

# needed for check-shadow
install-shadow:
	CGO_ENABLED=0 go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest

# having "err" shadowed is common, best to not have others
check-shadow:
	CGO_ENABLED=0 go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'
	CGO_ENABLED=0 go vet -tags integration -vettool=$$(which shadow) 2>&1 | grep -v '"err"'
	CGO_ENABLED=0 go vet -tags website -vettool=$$(which shadow) website/website.go 2>&1 | grep -v '"err"'
	CGO_ENABLED=0 go vet -tags link -vettool=$$(which shadow) rfc/link.go 2>&1 | grep -v '"err"'
	CGO_ENABLED=0 go vet -tags errata -vettool=$$(which shadow) rfc/errata.go 2>&1 | grep -v '"err"'
	CGO_ENABLED=0 go vet -tags xr -vettool=$$(which shadow) rfc/xr.go 2>&1 | grep -v '"err"'

fuzz:
	go test -fullpath -fuzz FuzzParseSignature -fuzztime 5m ./dkim
	go test -fullpath -fuzz FuzzParseRecord -fuzztime 5m ./dkim
	go test -fullpath -fuzz . -fuzztime 5m ./dmarc
	go test -fullpath -fuzz . -fuzztime 5m ./dmarcrpt
	go test -fullpath -fuzz . -parallel 1 -fuzztime 5m ./imapserver
	go test -fullpath -fuzz . -fuzztime 5m ./imapclient
	go test -fullpath -fuzz . -parallel 1 -fuzztime 5m ./junk
	go test -fullpath -fuzz FuzzParseRecord -fuzztime 5m ./mtasts
	go test -fullpath -fuzz FuzzParsePolicy -fuzztime 5m ./mtasts
	go test -fullpath -fuzz . -fuzztime 5m ./smtp
	go test -fullpath -fuzz . -parallel 1 -fuzztime 5m ./smtpserver
	go test -fullpath -fuzz . -fuzztime 5m ./spf
	go test -fullpath -fuzz FuzzParseRecord -fuzztime 5m ./tlsrpt
	go test -fullpath -fuzz FuzzParseMessage -fuzztime 5m ./tlsrpt

govendor:
	go mod tidy
	go mod vendor
	./genlicenses.sh

test-integration:
	-docker compose -f docker-compose-integration.yml kill
	-docker compose -f docker-compose-integration.yml down
	docker image build --pull --no-cache -f Dockerfile -t mox_integration_moxmail .
	docker image build --pull --no-cache -f testdata/integration/Dockerfile.test -t mox_integration_test testdata/integration
	-rm -rf testdata/integration/moxacmepebble/data
	-rm -rf testdata/integration/moxmail2/data
	-rm -f testdata/integration/tmp-pebble-ca.pem
	MOX_UID=$$(id -u) docker compose -f docker-compose-integration.yml run test
	docker compose -f docker-compose-integration.yml kill


imaptest-build:
	-docker compose -f docker-compose-imaptest.yml build --no-cache --pull mox

imaptest-run:
	-rm -r testdata/imaptest/data
	mkdir testdata/imaptest/data
	docker compose -f docker-compose-imaptest.yml run --entrypoint /usr/local/bin/imaptest imaptest host=mox port=1143 user=mjl@mox.example pass=testtest mbox=imaptest.mbox
	docker compose -f docker-compose-imaptest.yml down


fmt:
	go fmt ./...
	gofmt -w -s *.go */*.go

tswatch:
	bash -c 'while true; do inotifywait -q -e close_write *.ts webadmin/*.ts webaccount/*.ts webmail/*.ts; make frontend; done'

node_modules/.bin/tsc:
	-mkdir -p node_modules/.bin
	npm ci --ignore-scripts

install-js: node_modules/.bin/tsc

install-js0:
	-mkdir -p node_modules/.bin
	npm install --ignore-scripts --save-dev --save-exact typescript@5.1.6

webmail/webmail.js: lib.ts webmail/api.ts webmail/lib.ts webmail/webmail.ts
	./tsc.sh $@ lib.ts webmail/api.ts webmail/lib.ts webmail/webmail.ts

webmail/msg.js: lib.ts webmail/api.ts webmail/lib.ts webmail/msg.ts
	./tsc.sh $@ lib.ts webmail/api.ts webmail/lib.ts webmail/msg.ts

webmail/text.js: lib.ts webmail/api.ts webmail/lib.ts webmail/text.ts
	./tsc.sh $@ lib.ts webmail/api.ts webmail/lib.ts webmail/text.ts

webadmin/admin.js: lib.ts webadmin/api.ts webadmin/admin.ts
	./tsc.sh $@ lib.ts webadmin/api.ts webadmin/admin.ts

webaccount/account.js: lib.ts webaccount/api.ts webaccount/account.ts
	./tsc.sh $@ lib.ts webaccount/api.ts webaccount/account.ts

frontend: node_modules/.bin/tsc webadmin/admin.js webaccount/account.js webmail/webmail.js webmail/msg.js webmail/text.js

install-apidiff:
	CGO_ENABLED=0 go install golang.org/x/exp/cmd/apidiff@v0.0.0-20231206192017-f3f8817b8deb

genapidiff:
	./apidiff.sh

docker:
	docker build -t mox:dev .

docker-release:
	./docker-release.sh

genwebsite:
	./genwebsite.sh

buildall:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=netbsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=dragonfly GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=illumos GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=solaris GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=aix GOARCH=ppc64 go build
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build
	# no plan9 for now
