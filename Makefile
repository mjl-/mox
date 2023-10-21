GO ?= $(shell which go || echo go)
DOCKER ?= $(shell which docker || echo docker)
DOCKER_COMPOSE ?= $(shell docker compose &> /dev/null && echo "$(which docker)" compose || echo docker-compose)

gosrc = $(shell find * -type f -name '*.go')
gomod = go.mod go.sum
GOFLAGS = -trimpath

mox: $(gosrc) $(gomod) config/doc.go webmail/api.ts webadmin webaccount webmail
	CGO_ENABLED=0 go build $(GOFLAGS) -o $@

webmail/api.ts: webmail/api.json $(gomod)
	$(GO) run github.com/mjl-/sherpats/cmd/sherpats -bytes-to-string -slices-nullable -maps-nullable -nullable-optional -namespace api api <$< >$@

.mox.tmp: main.go
	CGO_ENABLED=0 go build $(GOFLAGS) -o $@

config/doc.go: ./gendoc.sh
	$(MAKE) .mox.tmp
	./gendoc.sh
	rm .mox.tmp

webadmin/adminapi.json: $(wildcard webadmin/*.go) $(gomod)
	cd webadmin && CGO_ENABLED=0 $(GO) run github.com/mjl-/sherpadoc/cmd/sherpadoc -adjust-function-names none Admin >$(notdir $@)

webaccount/accountapi.json: $(wildcard webaccount/*.go) $(gomod)
	cd webaccount && CGO_ENABLED=0 $(GO) run github.com/mjl-/sherpadoc/cmd/sherpadoc -adjust-function-names none Account >$(notdir $@)

webmail/api.json: $(wildcard webmail/*.go) $(gomod)
	cd webmail && CGO_ENABLED=0 $(GO) run github.com/mjl-/sherpadoc/cmd/sherpadoc -adjust-function-names none Webmail >$(notdir $@)

.PHONY: lint
lint:
	CGO_ENABLED=0 $(GO) vet ./...
	CGO_ENABLED=0 $(GO) vet -tags integration
	staticcheck ./...
	staticcheck -tags integration
	GOARCH=386 CGO_ENABLED=0 $(GO) vet ./...

.PHONY: test
test:
	CGO_ENABLED=0 $(GO) test -shuffle=on -coverprofile cover.out ./...
	$(GO) tool cover -html=cover.out -o cover.html

.PHONY: test-race
test-race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on -covermode atomic -coverprofile cover.out ./...
	$(GO) tool cover -html=cover.out -o cover.html

# note: if testdata/upgradetest.mbox.gz exists, its messages will be imported
# during tests. helpful for performance/resource consumption tests.
.PHONY: test-upgrade
test-upgrade:
	nice ./test-upgrade.sh

# having "err" shadowed is common, best to not have others
.PHONY: check-shadow
check-shadow:
	$(GO) vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

.PHONY: fuzz
fuzz:
	$(GO) test -fuzz FuzzParseSignature -fuzztime 5m ./dkim
	$(GO) test -fuzz FuzzParseRecord -fuzztime 5m ./dkim
	$(GO) test -fuzz . -fuzztime 5m ./dmarc
	$(GO) test -fuzz . -fuzztime 5m ./dmarcrpt
	$(GO) test -fuzz . -parallel 1 -fuzztime 5m ./imapserver
	$(GO) test -fuzz . -parallel 1 -fuzztime 5m ./junk
	$(GO) test -fuzz FuzzParseRecord -fuzztime 5m ./mtasts
	$(GO) test -fuzz FuzzParsePolicy -fuzztime 5m ./mtasts
	$(GO) test -fuzz . -parallel 1 -fuzztime 5m ./smtpserver
	$(GO) test -fuzz . -fuzztime 5m ./spf
	$(GO) test -fuzz FuzzParseRecord -fuzztime 5m ./tlsrpt
	$(GO) test -fuzz FuzzParseMessage -fuzztime 5m ./tlsrpt

.PHONY: test-integration
test-integration:
	$(DOCKER) image build --pull --no-cache -f Dockerfile -t mox_integration_moxmail .
	$(DOCKER) image build --pull --no-cache -f testdata/integration/Dockerfile.test -t mox_integration_test testdata/integration
	-rm -rf testdata/integration/moxacmepebble/data
	-rm -rf testdata/integration/moxmail2/data
	-rm -f testdata/integration/tmp-pebble-ca.pem
	MOX_UID=$$(id -u) $(DOCKER_COMPOSE) -f docker-compose-integration.yml run test
	$(DOCKER_COMPOSE) -f docker-compose-integration.yml down --timeout 1

.PHONY: imaptest-build
imaptest-build:
	-$(DOCKER_COMPOSE) -f docker-compose-imaptest.yml build --no-cache --pull mox

.PHONY: imaptest-run
imaptest-run:
	-rm -r testdata/imaptest/data
	mkdir testdata/imaptest/data
	$(DOCKER_COMPOSE) -f docker-compose-imaptest.yml run --entrypoint /usr/local/bin/imaptest imaptest host=mox port=1143 user=mjl@mox.example pass=testtest mbox=imaptest.mbox
	$(DOCKER_COMPOSE) -f docker-compose-imaptest.yml down


fmt:
	$(GO) fmt ./...
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

.PHONY: frontend
frontend: webadmin/admin.htmlx webaccount/account.htmlx webmail/webmail.js webmail/msg.js webmail/text.js

.PHONY: docker
docker:
	$(DOCKER) build -t mox:dev .

.PHONY: docker-release
docker-release:
	./docker-release.sh

.PHONY: buildall
buildall:
	GOOS=linux GOARCH=arm $(GO) $(GOFLAGS) build
	GOOS=linux GOARCH=arm64 $(GO) $(GOFLAGS) build
	GOOS=linux GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=linux GOARCH=386 $(GO) $(GOFLAGS) build
	GOOS=openbsd GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=freebsd GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=netbsd GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=darwin GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=dragonfly GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=illumos GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=solaris GOARCH=amd64 $(GO) $(GOFLAGS) build
	GOOS=aix GOARCH=ppc64 $(GO) $(GOFLAGS) build
	GOOS=windows GOARCH=amd64 $(GO) $(GOFLAGS) build
	# no plan9 for now
