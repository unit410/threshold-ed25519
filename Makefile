all: test

tools:
	go install github.com/kisielk/errcheck@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.46.2

lint: tools
	go fmt ./...
	golangci-lint run -c ./.golangci.yml

test:
	@go test -short ./...

race:
	@go test -race -short ./...

msan:
	@go test -msan -short ./...

.PHONY: all lint test race msan tools