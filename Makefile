BINARY  := openticollect
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X openticollect/internal/version.Version=$(VERSION)

.PHONY: build run test lint clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/server

run: build
	./$(BINARY)

test:
	go test ./...

lint:
	go vet ./...
	gofmt -l .

clean:
	rm -f $(BINARY)
