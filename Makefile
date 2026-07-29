GO ?= go
GOLANGCI_LINT_VERSION ?= v2.1.6
GOVULNCHECK_VERSION ?= v1.1.4

.PHONY: all boundary fmt-check generated-check lint race test vet vuln-check

all: fmt-check lint test race vet generated-check vuln-check boundary

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
	git diff --exit-code

vuln-check:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

boundary:
	@set -eu; \
	private_module='github.com/conductera/'"control-plane"; \
	if grep -RInF --exclude-dir=.git "$$private_module" .; then \
		echo 'public boundary violation: private module reference'; \
		exit 1; \
	fi; \
	private_host_pattern='([[:alnum:]-]+\.)*(artifactory|nexus|registry\.(internal|corp|local)|([[:alnum:]-]+\.)+(internal|corp|local))([/:]|$$)'; \
	if grep -RInE --exclude-dir=.git "$$private_host_pattern" .; then \
		echo 'public boundary violation: private registry host'; \
		exit 1; \
	fi; \
	credential_pattern='(https?://[^/@[:space:]]+:[^/@[:space:]]+@|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16})'; \
	if grep -RInE --exclude-dir=.git "$$credential_pattern" .; then \
		echo 'public boundary violation: credential material'; \
		exit 1; \
	fi; \
	if awk '\
		BEGIN { in_replace = 0; bad = 0 } \
		/^[[:space:]]*replace[[:space:]]*\(/ { in_replace = 1; next } \
		in_replace && /^[[:space:]]*\)/ { in_replace = 0; next } \
		/^[[:space:]]*replace[[:space:]]+/ || in_replace { \
			for (i = 1; i <= NF; i++) { \
				if ($$i == "=>" && ( $$(i + 1) ~ /^\.\.?\// || $$(i + 1) ~ /^\// || $$(i + 1) ~ /^~\// || $$(i + 1) ~ /^file:/ )) { \
					bad = 1 \
				} \
			} \
		} \
		END { exit bad ? 0 : 1 }' go.mod; then \
		echo 'public boundary violation: local replace directive'; \
		exit 1; \
	fi; \
	$(GO) list -deps ./... >/dev/null
