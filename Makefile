# Copyright 2026 Michael Shields. Licensed under the Apache License, Version 2.0.

.PHONY: lint test build fmt ci docker-ci

lint: actions-lock-verify-local
	just lint

test:
	just test

build:
	just build

fmt:
	just fmt

ci: lint
	just check test-verbose

docker-ci:
	just docker-ci

.PHONY: actions-lock-install actions-lock actions-lock-verify-local actions-lock-verify

actions-lock-install:
	gh extension install github/gh-actions-lock --pin v0.4.1 --force

actions-lock:
	gh actions-lock --no-interactive

actions-lock-verify-local:
	gh actions-lock --verify-local

actions-lock-verify:
	gh actions-lock --verify
