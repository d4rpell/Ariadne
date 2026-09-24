# Ariadne local gates. CI runs `make check` (.github/workflows/ci.yml).
# Every target is offline: no module downloads, no network access.

GO ?= go
GOLDEN_PATTERN ?= Golden|Canonical|Hash
CONTRACT_PATTERN ?= ImportBoundary
CONTRACT_PACKAGE ?= ./internal/security/

.PHONY: all check fmt fmt-check vet build test test-race test-golden test-contract clean

all: check

check: fmt-check vet build test test-golden test-race test-contract

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt reports unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "gofmt: clean"

vet:
	$(GO) vet ./...

build:
	$(GO) build ./...

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -count=1 -race ./...

# Named gate over the canonical wire and hash vectors of ADR-0006. `test` runs the
# same tests; this target keeps the contract vectors invocable without the full suite.
# `go test -run` exits 0 when nothing matches, so every named gate checks that the
# pattern selects a test first: a renamed or deleted test cannot leave CI green.
test-golden:
	@names="$$($(GO) test -list '$(GOLDEN_PATTERN)' ./...)" || { echo "error: go test -list failed for '$(GOLDEN_PATTERN)'"; exit 1; }; \
	if ! printf '%s\n' "$$names" | grep -q '^Test'; then echo "error: no golden test matches '$(GOLDEN_PATTERN)'"; exit 1; fi
	$(GO) test -count=1 -run '$(GOLDEN_PATTERN)' ./...

# Import boundary of the evaluator and the report layer (threat T12).
test-contract:
	@names="$$($(GO) test -list '$(CONTRACT_PATTERN)' $(CONTRACT_PACKAGE))" || { echo "error: go test -list failed for '$(CONTRACT_PATTERN)' in $(CONTRACT_PACKAGE)"; exit 1; }; \
	if ! printf '%s\n' "$$names" | grep -q '^Test'; then echo "error: no contract test matches '$(CONTRACT_PATTERN)' in $(CONTRACT_PACKAGE)"; exit 1; fi
	$(GO) test -count=1 -run '$(CONTRACT_PATTERN)' $(CONTRACT_PACKAGE)

clean:
	$(GO) clean ./...
	rm -rf bin dist
