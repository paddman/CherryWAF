SHELL := /bin/bash
GO ?= go
VERSION ?= 0.2.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

.PHONY: all fmt test vet webcheck build clean run docker smoke release-linux-amd64 appliance-init appliance

all: fmt test build

fmt:
	@test -z "$$(gofmt -l .)" || { echo "Run gofmt on:"; gofmt -l .; exit 1; }

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

webcheck:
	node --check internal/control/web/app.js
	node --check internal/control/web/threatmap-data.js
	node --check internal/control/web/threatmap-core.js
	node --check internal/control/web/threatmap-view.js
	node --check internal/control/web/threatmap-live.js

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/cherrywaf ./cmd/cherrywaf
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o dist/cherrywafctl ./cmd/cherrywafctl
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/cherrywaf-control ./cmd/cherrywaf-control
	CGO_ENABLED=0 GOOS=linux GOARCH=$$($(GO) env GOARCH) $(GO) build -trimpath -ldflags="-s -w" -o dist/cherrywaf-netd ./cmd/cherrywaf-netd

run:
	CHERRYWAF_ADMIN_TOKEN=development-only $(GO) run ./cmd/cherrywaf serve --config ./configs/cherrywaf.example.json

docker:
	docker compose up --build

smoke:
	./scripts/smoke-test.sh

release-linux-amd64:
	mkdir -p dist/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/linux-amd64/cherrywaf ./cmd/cherrywaf
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o dist/linux-amd64/cherrywafctl ./cmd/cherrywafctl
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/linux-amd64/cherrywaf-control ./cmd/cherrywaf-control
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o dist/linux-amd64/cherrywaf-netd ./cmd/cherrywaf-netd
	tar -C dist/linux-amd64 -czf dist/cherrywaf_$(VERSION)_linux_amd64.tar.gz cherrywaf cherrywafctl cherrywaf-control cherrywaf-netd

appliance-init:
	packer init appliance/packer/ubuntu-26.04.pkr.hcl

appliance: release-linux-amd64 appliance-init
	packer build -var-file=appliance/packer/variables.pkrvars.hcl appliance/packer/ubuntu-26.04.pkr.hcl

clean:
	rm -rf dist appliance/output-* var