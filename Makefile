BINARY := pubapi
GO     := go

.PHONY: run build test vet fmt tidy docker clean

run:
	$(GO) run .

build:
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o bin/$(BINARY) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

tidy:
	$(GO) mod tidy

docker:
	docker build -t pubapi-offsec:latest .

clean:
	rm -rf bin/ $(BINARY)
