BINARY := pubapi
GO     := go

.PHONY: run build test vet fmt tidy docker up down logs clean

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

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	rm -rf bin/ $(BINARY)
