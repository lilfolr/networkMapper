.DEFAULT_GOAL := help

# Allow arguments after "make run" (e.g. make run trace example.com or make run ARGS="...")
ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  $(eval $(RUN_ARGS):;@:)
endif

.PHONY: help build run release test fmt fmt-check clippy check clean

help: ## Show this usage and available targets
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build debug binaries
	cargo build

run: ## Run mapr CLI (e.g. make run ARGS="trace example.com")
	cargo run -- $(if $(RUN_ARGS),$(RUN_ARGS),$(ARGS))

release: ## Build release binaries
	cargo build --release

test: ## Run unit tests
	cargo test

fmt: ## Format Rust source files
	cargo fmt

fmt-check: ## Verify source formatting without modifying files
	cargo fmt --check

clippy: ## Run Clippy checks with warnings treated as errors
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt-check clippy test ## Run full verification suite (fmt-check, clippy, test)

clean: ## Remove build artifacts
	cargo clean
