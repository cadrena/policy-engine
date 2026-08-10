GO ?= go
PYTHON ?= python3
GOLANGCI_LINT_VERSION ?= v2.1.6
GOVULNCHECK_VERSION ?= v1.1.4
GITLEAKS_VERSION ?= v8.30.1

.PHONY: all batch-2a-final batch-2a-focused boundary boundary-test fmt-check generated-check gitleaks lint race sqlitenofollow-manifest test vet vuln-check

all: fmt-check lint test race vet generated-check sqlitenofollow-manifest vuln-check boundary boundary-test gitleaks

# These release gates deliberately spell out every command so a local Make run
# uses the same toolchain and coverage as the recorded Batch 2A evidence.
batch-2a-focused: export GOTOOLCHAIN = go1.25.12
batch-2a-focused:
	$(GO) test . ./internal/app ./conformance/authorization -run 'Test.*(ApprovalBinding|AuthorizationDigest|ApprovalContinuation)' -count=10
	$(GO) test ./store/sqlite ./store/conformance ./cmd/cadrena-policy-store -count=10
	$(GO) test ./store/sqlite ./cmd/cadrena-policy-store -run 'Test(Integrity|Recovery|Crash|Subprocess|RunIntegrity)' -count=10

batch-2a-final: export GOTOOLCHAIN = go1.25.12
batch-2a-final:
	$(GO) version
	$(MAKE) batch-2a-focused
	$(GO) test ./... -count=3
	$(GO) test -race ./... -count=1
	$(MAKE) vet
	$(GO) mod verify
	$(MAKE) fmt-check lint generated-check sqlitenofollow-manifest
	$(MAKE) boundary boundary-test
	$(MAKE) vuln-check
	$(MAKE) gitleaks
	git diff --check
	git status --short --branch

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
	# The preserved modernc driver mirror intentionally uses uintptr-backed FFI
	# patterns which its own source triggers under vet's unsafeptr analyzer.
	# Keep all regular vet analyzers for every project package, and all except
	# unsafeptr for this one reviewed upstream mirror.
	@$(GO) list ./... | grep -v '/internal/sqlitenofollow$$' | xargs $(GO) vet
	$(GO) vet -unsafeptr=false ./internal/sqlitenofollow

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

generated-check:
	$(GO) generate ./...
	@status="$$(git status --porcelain=v1 --untracked-files=all)"; \
	if [ -n "$$status" ]; then \
		printf 'go generate left repository changes:\n%s\n' "$$status"; \
		exit 1; \
	fi

sqlitenofollow-manifest:
	sh scripts/check-sqlitenofollow-manifest.sh

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
