# Sentinel Gate OSS - Multi-stage Dockerfile
#
# This builds the open-source version of Sentinel Gate with:
# - Single binary: /sentinel-gate
# - Single port: 8080 (no admin port)
# - No database dependencies (PostgreSQL, Redis)
# - Distroless runtime for minimal attack surface
#
# Build: docker build -t sentinel-gate:latest .
# Run:   docker run -p 8080:8080 -v ./config.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro sentinel-gate:latest

# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Build configuration for static binary (no GOARCH: let Docker Buildx handle architecture)
ENV CGO_ENABLED=0 GOOS=linux

# Version info (override at build time with --build-arg)
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
COPY sdks/go/go.mod sdks/go/
RUN go mod download

# Copy source and build
COPY . .
RUN go build -trimpath \
    -ldflags="-s -w \
      -X github.com/Sentinel-Gate/Sentinelgate/cmd/sentinel-gate/cmd.Version=${VERSION} \
      -X github.com/Sentinel-Gate/Sentinelgate/cmd/sentinel-gate/cmd.Commit=${COMMIT} \
      -X github.com/Sentinel-Gate/Sentinelgate/cmd/sentinel-gate/cmd.BuildDate=${BUILD_DATE}" \
    -o /sentinel-gate ./cmd/sentinel-gate

# Stage 2: Prepare data directory with correct ownership
FROM busybox:1.36-uclibc AS perms
RUN mkdir -p /data && chown 65532:65532 /data

# Stage 3: Runtime
FROM gcr.io/distroless/static-debian12 AS runtime

# Copy wget from busybox for healthcheck (distroless has no shell tools)
COPY --from=busybox:1.36-uclibc /bin/wget /usr/bin/wget

# OCI labels for GitHub Container Registry
LABEL org.opencontainers.image.source="https://github.com/Sentinel-Gate/Sentinelgate"
LABEL org.opencontainers.image.description="MCP proxy with policy enforcement for AI agents"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

# Copy binary and CA certificates for HTTPS
COPY --from=builder /sentinel-gate /sentinel-gate
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# State persistence volume with correct ownership for non-root user (UID 65534)
COPY --from=perms /data /data
VOLUME ["/data"]
ENV SENTINEL_GATE_STATE_PATH=/data/state.json
# Bind to all interfaces inside container (default is localhost-only for security).
ENV SENTINEL_GATE_SERVER_HTTP_ADDR=":8080"

# Run as non-root user
USER nonroot:nonroot

# Expose HTTP port (no admin port in OSS)
EXPOSE 8080

# Health check using /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/bin/wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]

ENTRYPOINT ["/sentinel-gate"]
CMD ["start"]
