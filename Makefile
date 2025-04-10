.PHONY: help test

.DEFAULT_GOAL := help

# Variables
SHELL := /usr/bin/env bash
REPO_ROOT := $(shell git rev-parse --show-toplevel)
TEST_SCRIPT := $(REPO_ROOT)/script/run.sh

help:
	@echo "Makefile targets:"
	@echo "  test       Run all tests using the run_tests.sh script"
	@echo "  help       Show this help message"

install-git-hooks:
	@ls -R ./.git/hooks > before.txt
	@cp -r ./script/hooks/ ./.git/
	@chmod +x ./.git/hooks/pre-commit
	@ls -R ./.git/hooks > after.txt
	@diff before.txt after.txt || true
	@rm before.txt after.txt
	@echo "Hooks installed successfully."

test:
	@if [ ! -f "$(TEST_SCRIPT)" ]; then \
		echo "Error: run_tests.sh not found in repository root."; \
		exit 1; \
	fi
	@cd "$(REPO_ROOT)/crates/dvt" && cargo test
	@cd "$(REPO_ROOT)" && $(TEST_SCRIPT) $(ARGS)
	