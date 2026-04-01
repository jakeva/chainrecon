VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X github.com/chainrecon/chainrecon/internal/cli.Version=$(VERSION) \
           -X github.com/chainrecon/chainrecon/internal/cli.Commit=$(COMMIT) \
           -X github.com/chainrecon/chainrecon/internal/cli.Date=$(DATE)

.DEFAULT_GOAL := build

.PHONY: build test lint vet install clean integration-test

build:
	go build -ldflags "$(LDFLAGS)" -o bin/chainrecon ./cmd/chainrecon

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

install:
	go install ./cmd/chainrecon

clean:
	rm -rf bin/

integration-test:
	go test -tags=integration -race -v ./...
