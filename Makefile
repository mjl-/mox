default: build

build:
	# build early to catch syntax errors
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet -tags integration
	CGO_ENABLED=0 go vet -tags quickstart quickstart_test.go
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

test-upgrade:
	./test-upgrade.sh

check:
	staticcheck ./...
	staticcheck -tags integration
	staticcheck -tags quickstart
	GOARCH=386 CGO_ENABLED=0 go vet -tags integration ./...

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

test-integration:
	docker-compose -f docker-compose-integration.yml build --no-cache --pull moxmail
	-rm -r testdata/integration/data
	docker-compose -f docker-compose-integration.yml run moxmail sh -c 'CGO_ENABLED=0 go test -tags integration'
	docker-compose -f docker-compose-integration.yml down

# like test-integration, but in separate steps
integration-build:
	docker-compose -f docker-compose-integration.yml build --no-cache --pull moxmail

integration-start:
	-rm -r testdata/integration/data
	-docker-compose -f docker-compose-integration.yml run moxmail /bin/bash
	docker-compose -f docker-compose-integration.yml down

# run from within "make integration-start"
integration-test:
	CGO_ENABLED=0 go test -tags integration


test-quickstart:
	docker image build --pull -f Dockerfile -t mox_quickstart_moxmail .
	docker image build --pull -f testdata/quickstart/Dockerfile.test -t mox_quickstart_test testdata/quickstart
	-rm -rf testdata/quickstart/moxacmepebble/data
	-rm -rf testdata/quickstart/moxmail2/data
	-rm -f testdata/quickstart/tmp-pebble-ca.pem
	MOX_UID=$$(id -u) docker-compose -f docker-compose-quickstart.yml run test
	docker-compose -f docker-compose-quickstart.yml down --timeout 1


imaptest-build:
	-docker-compose -f docker-compose-imaptest.yml build --no-cache --pull mox

imaptest-run:
	-rm -r testdata/imaptest/data
	mkdir testdata/imaptest/data
	docker-compose -f docker-compose-imaptest.yml run --entrypoint /usr/local/bin/imaptest imaptest host=mox port=1143 user=mjl@mox.example pass=testtest mbox=imaptest.mbox
	docker-compose -f docker-compose-imaptest.yml down


fmt:
	go fmt ./...
	gofmt -w -s *.go */*.go

jswatch:
	inotifywait -m -e close_write http/admin.html http/account.html | xargs -n2 sh -c 'echo changed; ./checkhtmljs http/admin.html http/account.html'

jsinstall:
	-mkdir -p node_modules/.bin
	npm install jshint@2.13.2

docker:
	docker build -t mox:dev .

docker-release:
	./docker-release.sh
