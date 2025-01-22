.PHONY: help test

.DEFAULT_GOAL := help

# Variables
SHELL := /usr/bin/env bash
REPO_ROOT := $(shell git rev-parse --show-toplevel)
TEST_SCRIPT := $(REPO_ROOT)/scripts/run.sh

help:
	@echo "Makefile targets:"
	@echo "  test       Run all tests using the run_tests.sh script"
	@echo "  help       Show this help message"

test:
	@if [ ! -f "$(TEST_SCRIPT)" ]; then \
		echo "Error: run_tests.sh not found in repository root."; \
		exit 1; \
	fi
	@cd "$(REPO_ROOT)/crates/bls_utils" && cargo test
	@cd "$(REPO_ROOT)" && $(TEST_SCRIPT) $(ARGS)
	