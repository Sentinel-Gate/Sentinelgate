.PHONY: lint test test-race build check

lint:
	golangci-lint run ./...

test:
	go test -count=1 -timeout 300s ./...

test-race:
	go test -race -count=1 -timeout 300s ./...

build:
	go build ./...

check: lint test-race build
	@echo "All checks passed"
