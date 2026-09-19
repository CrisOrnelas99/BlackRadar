SHELL := /bin/sh

.PHONY: help format format-check test test-backend test-ui lint check build security docker-up docker-down install-hooks

help:
	@printf '%s\n' \
		'make format        Format Go and Angular source files' \
		'make format-check  Check formatting without changing files' \
		'make test          Run backend and frontend tests' \
		'make lint          Run Go vet and frontend formatting checks' \
		'make check         Run formatting, lint, tests, and diff checks' \
		'make build         Build the backend and frontend' \
		'make security      Run dependency and vulnerability checks' \
		'make docker-up     Start the Docker Compose stack' \
		'make docker-down   Stop the Docker Compose stack' \
		'make install-hooks Install Lefthook Git hooks'

format:
	cd BlackRadar && gofmt -w $$(find . -type f -name '*.go')
	cd BlackRadar/ui && npx --no-install prettier --write 'src/**/*.{ts,html,css,scss}'

format-check:
	@test -z "$$(cd BlackRadar && gofmt -l $$(find . -type f -name '*.go'))" || (echo 'Go files need formatting.' && exit 1)
	cd BlackRadar/ui && npx --no-install prettier --check 'src/**/*.{ts,html,css,scss}'

test: test-backend test-ui

test-backend:
	cd BlackRadar && go test ./...

test-ui:
	cd BlackRadar/ui && npx --no-install ng test --watch=false

lint:
	cd BlackRadar && go vet ./...
	cd BlackRadar/ui && npm run lint

check: format-check lint test
	git diff --check

build:
	cd BlackRadar && go build .
	cd BlackRadar/ui && npm run build

security:
	cd BlackRadar && \
	tool_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tool_dir"' EXIT; \
	GOBIN="$$tool_dir" go install golang.org/x/vuln/cmd/govulncheck@v1.1.4; \
	"$$tool_dir/govulncheck" ./...
	cd BlackRadar/ui && npm audit --audit-level=high

docker-up:
	docker compose up --build

docker-down:
	docker compose down

install-hooks:
	lefthook install
