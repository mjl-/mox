default: build

build:
	# build early to catch syntax errors
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet ./...
	CGO_ENABLED=0 go vet -tags integration
	./gendoc.sh
	(cd webadmin && CGO_ENABLED=0 go run ../vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none Admin) >webadmin/adminapi.json
	(cd webaccount && CGO_ENABLED=0 go run ../vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none Account) >webaccount/accountapi.json
	(cd webmail && CGO_ENABLED=0 go run ../vendor/github.com/mjl-/sherpadoc/cmd/sherpadoc/*.go -adjust-function-names none Webmail) >webmail/api.json
	go run vendor/github.com/mjl-/sherpats/cmd/sherpats/main.go -bytes-to-string -slices-nullable -maps-nullable -nullable-optional -namespace api api <webmail/api.json >webmail/api.ts
	# build again, api json files above are embedded
	CGO_ENABLED=0 go build

test:
	CGO_ENABLED=0 go test -shuffle=on -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

test-race:
	CGO_ENABLED=1 go test -race -shuffle=on -covermode atomic -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

# note: if testdata/upgradetest.mbox.gz exists, its messages will be imported
# during tests. helpful for performance/resource consumption tests.
test-upgrade:
	nice ./test-upgrade.sh

check:
	staticcheck ./...
	staticcheck -tags integration
	GOARCH=386 CGO_ENABLED=0 go vet ./...

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
	docker image build --pull --no-cache -f Dockerfile -t mox_integration_moxmail .
	docker image build --pull --no-cache -f testdata/integration/Dockerfile.test -t mox_integration_test testdata/integration
	-rm -rf testdata/integration/moxacmepebble/data
	-rm -rf testdata/integration/moxmail2/data
	-rm -f testdata/integration/tmp-pebble-ca.pem
	MOX_UID=$$(id -u) docker-compose -f docker-compose-integration.yml run test
	docker-compose -f docker-compose-integration.yml down --timeout 1


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
	bash -c 'while true; do inotifywait -q -e close_write webadmin/*.html webaccount/*.html webmail/*.ts; make frontend; done'

jsinstall:
	-mkdir -p node_modules/.bin
	npm ci

jsinstall0:
	-mkdir -p node_modules/.bin
	npm install --save-dev --save-exact jshint@2.13.6 typescript@5.1.6

webmail/webmail.js: webmail/api.ts webmail/lib.ts webmail/webmail.ts
	./tsc.sh $@ $^

webmail/msg.js: webmail/api.ts webmail/lib.ts webmail/msg.ts
	./tsc.sh $@ $^

webmail/text.js: webmail/api.ts webmail/lib.ts webmail/text.ts
	./tsc.sh $@ $^

webadmin/admin.htmlx:
	./node_modules/.bin/jshint --extract always webadmin/admin.html | ./fixjshintlines.sh

webaccount/account.htmlx:
	./node_modules/.bin/jshint --extract always webaccount/account.html | ./fixjshintlines.sh

frontend: webadmin/admin.htmlx webaccount/account.htmlx webmail/webmail.js webmail/msg.js webmail/text.js

docker:
	docker build -t mox:dev .

docker-release:
	./docker-release.sh
