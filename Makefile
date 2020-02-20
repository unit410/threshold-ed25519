GOLINT:=$(shell go list -f {{.Target}} golang.org/x/lint/golint)

all: test

lint: tools
	@$(GOLINT) -set_exit_status ./...

test:
	@go test -short ./...

race:
	@go test -race -short ./...

msan:
	@go test -msan -short ./...

tools:
	@go install golang.org/x/lint/golint

.PHONY: all lint test race msan tools