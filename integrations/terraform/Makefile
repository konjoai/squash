# Squash Terraform Provider — Makefile
#
# Konjo: every target does one thing and does it cleanly. No bash sprawl,
# no recursive submakes. If you need a step the Makefile doesn't have,
# add a target — don't pipe it in.

NAME       := squash
HOSTNAME   := registry.terraform.io
NAMESPACE  := konjoai
BINARY     := terraform-provider-$(NAME)
VERSION    := $(shell git describe --tags --always 2>/dev/null || echo dev)
OS_ARCH    := $(shell go env GOOS)_$(shell go env GOARCH)
PLUGIN_DIR := $(HOME)/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(NAME)/$(VERSION)/$(OS_ARCH)

.PHONY: help build install test test-core fmt vet lint clean docs tidy

help:
	@echo "Targets:"
	@echo "  build     - build provider binary at ./$(BINARY)"
	@echo "  install   - install to $(PLUGIN_DIR)"
	@echo "  test      - run all Go tests"
	@echo "  test-core - run stdlib-only squashcli tests (offline)"
	@echo "  fmt       - gofmt -s -w on all sources"
	@echo "  vet       - go vet ./..."
	@echo "  tidy      - go mod tidy"
	@echo "  clean     - remove built artefacts"

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

install: build
	mkdir -p $(PLUGIN_DIR)
	cp $(BINARY) $(PLUGIN_DIR)/$(BINARY)

test:
	go test -race -count=1 ./...

test-core:
	go test -race -count=1 ./internal/squashcli/...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
