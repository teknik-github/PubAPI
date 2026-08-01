# --- build stage ---
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/pubapi .

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pubapi /pubapi
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/pubapi"]
