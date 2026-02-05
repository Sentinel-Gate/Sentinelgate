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

# Build configuration for static binary
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /sentinel-gate ./cmd/sentinel-gate

# Stage 2: Runtime
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

# Run as non-root user
USER nonroot:nonroot

# Expose HTTP port (no admin port in OSS)
EXPOSE 8080

# Health check using /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/bin/wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]

ENTRYPOINT ["/sentinel-gate"]
CMD ["start"]
