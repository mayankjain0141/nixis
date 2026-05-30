.PHONY: build generate test-keys dev lint test install uninstall release-local

## build: compile all Go binaries
build:
	go build ./...

## generate: export policies.json for the dashboard static fallback (no daemon needed)
generate:
	go run ./cmd/aegis/ policy export --dir ./policies --out ./dashboard/public/policies.json

## test-keys: generate Ed25519 test key pair for go test ./... (keys are gitignored, run once)
test-keys:
	@mkdir -p testdata
	openssl genpkey -algorithm ed25519 -out testdata/bundle_signing_key.pem
	openssl pkey -in testdata/bundle_signing_key.pem -pubout -out testdata/bundle_signing_pub.pem
	@echo "Test keys written to testdata/"

## lint: run golangci-lint on all Go packages
lint:
	golangci-lint run ./...

## test: run all Go tests (requires testdata/ keys — run make test-keys first)
test:
	go test ./... -race -count=1

## dev: start daemon + dashboard dev server (requires daemon binary built first)
dev:
	@echo "Starting daemon on :9090..."
	@go build -o /tmp/aegis-daemon ./cmd/aegis-daemon/ && \
	  /tmp/aegis-daemon -policy-dir ./policies &
	@echo "Starting dashboard dev server..."
	@cd dashboard && npm run dev

## install: build from source and run interactive setup
install: build
	@go build -o ~/.aegis/aegis ./cmd/aegis
	@go build -o ~/.aegis/aegis-hook -ldflags="-s -w" ./cmd/aegis-hook
	@~/.aegis/aegis setup

## uninstall: remove aegis installation
uninstall:
	@~/.aegis/aegis setup --uninstall --yes || true
	@echo "Aegis uninstalled"

## release-local: build release artifacts locally (for testing)
release-local:
	goreleaser release --snapshot --clean
