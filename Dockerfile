# --- build stage ---
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build \
    -ldflags "-X openticollect/internal/version.Version=${VERSION}" \
    -o /openticollect ./cmd/server

# --- final stage ---
# Minimal Alpine base: ~8 MB, provides CA roots and a writable rootfs that
# modernc.org/sqlite needs. (A scratch image hangs SQLite on open.)
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /openticollect /openticollect
EXPOSE 8080
ENTRYPOINT ["/openticollect"]
