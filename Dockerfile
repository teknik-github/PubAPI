# --- build stage ---
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go build (modernc SQLite) — no CGO, so it runs on distroless/static.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/pubapi .
# Pre-create the data dir so the named volume inherits nonroot ownership.
RUN mkdir -p /data

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pubapi /pubapi
COPY --from=build --chown=65532:65532 /data /data
# SQLite database (users, API keys, request logs) lives on the /data volume.
ENV DB_PATH=/data/pubapi.db \
    HOST=0.0.0.0 \
    PORT=8080 \
    GIN_MODE=release
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/pubapi"]
