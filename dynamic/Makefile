GOCMD=go
GOBUILD=$(GOCMD) build -trimpath -ldflags="-s -w"
GOTEST=$(GOCMD) test

BASE_BINARY_NAME=pipesec
DYNAMIC_BINARY_NAME=$(BASE_BINARY_NAME)-dynamic

BINARY_DIR=bin

.PHONY: install i test build lint fmt format clean help

install:
	$(GOCMD) mod download
	$(GOCMD) mod tidy

i: install

test:
	$(GOTEST) ./...

build-dynamic:
	$(GOBUILD) -o ./$(BINARY_DIR)/$(DYNAMIC_BINARY_NAME) ./cmd/dynamic
	chmod +x ./$(BINARY_DIR)/$(DYNAMIC_BINARY_NAME)

build: build-dynamic

lint:
	golangci-lint run -c .golangci.yaml ./...

fmt:
	golangci-lint fmt -c .golangci.yaml ./...

format: fmt

clean:
	rm -rf bin/*

help:
	@echo "Help:"
	@echo "  install   - Install all deps using go mod download"
	@echo "        i"
	@echo "  test      - Run tests"
	@echo "  build     - Build all binaries"
	@echo "  run       - Run the application"
	@echo "  lint      - Run golangci-lint linter"
	@echo "  format    - Run golangci-lint formatter"
	@echo "     fmt"
	@echo "  clean     - Clean build artifacts"


.DEFAULT_GOAL := help

%:
	@:
