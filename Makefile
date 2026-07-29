GO ?= go
PYTHON ?= python3
GOLANGCI_LINT_VERSION ?= v2.1.6
GOVULNCHECK_VERSION ?= v1.1.4
GITLEAKS_VERSION ?= v8.30.1

.PHONY: all boundary fmt-check generated-check gitleaks lint race test vet vuln-check

all: fmt-check lint test race vet generated-check vuln-check boundary gitleaks

fmt-check:
	@unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -exec gofmt -l {} +)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'The following Go files are not formatted:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

generated-check:
	$(GO) generate ./...
	@status="$$(git status --porcelain=v1 --untracked-files=all)"; \
	if [ -n "$$status" ]; then \
		printf 'go generate left repository changes:\n%s\n' "$$status"; \
		exit 1; \
	fi

vuln-check:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

boundary:
	$(PYTHON) scripts/check_public_boundary.py --go "$(GO)"
	$(GO) list -deps ./... >/dev/null

gitleaks:
	$(GO) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir --redact --no-banner .
	$(GO) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) git --redact --no-banner .
