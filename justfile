set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

typos:
  typos

check: tidy typos fmt lint vet test fuzz

fuzz:
	#!/usr/bin/env bash
	if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
	  echo "Skipping fuzz tests in GitHub Actions"
	  exit 0
	fi
	fuzz_time="${FUZZ_TIME:-1m}"
	pids=()
	for package in ./helpers ./spoofer ./vtun; do
	  go test "$package" -run '^$' -fuzz '^FuzzUntrustedInput$' -fuzztime "$fuzz_time" &
	  pids+=("$!")
	done
	status=0
	for pid in "${pids[@]}"; do
	  if ! wait "$pid"; then
	    status=1
	  fi
	done
	exit "$status"

test:
	go test ./... --race -count=1

vet:
	go vet ./...

tidy:
	go mod tidy

lint:
  golangci-lint run ./...

fmt:
  golangci-lint fmt ./...
