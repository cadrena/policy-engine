GO ?= go
PYTHON ?= python3
GOLANGCI_LINT_VERSION ?= v2.1.6
GOVULNCHECK_VERSION ?= v1.1.4
GITLEAKS_VERSION ?= v8.30.1

.PHONY: all boundary boundary-test fmt-check generated-check gitleaks lint race test vet vuln-check

all: fmt-check lint test race vet generated-check vuln-check boundary boundary-test gitleaks

fmt-check:
	@set -eu; \
	goroot="$$($(GO) env GOROOT)"; \
	unformatted="$$(find . -type f -name '*.go' -not -path './.git/*' -exec "$$goroot/bin/gofmt" -l {} +)"; \
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
	GOWORK=off $(PYTHON) scripts/check_public_boundary.py --go "$(GO)"
	GOWORK=off $(GO) list -deps ./... >/dev/null

boundary-test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest -v scripts.test_check_public_boundary

gitleaks:
	$(GO) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir --redact --no-banner .
	$(GO) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) git --redact --no-banner .
