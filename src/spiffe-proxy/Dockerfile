# =============================================================================
# AIM Prototype Platform - SPIFFE Proxy Docker Image
# =============================================================================
# Multi-stage build:
#   1. Generate protobuf Go code
#   2. Build Go proxy binary
#   3. Runtime image with SPIRE + proxy
#
# Runs in two modes via CONTAINER_MODE env:
#   - "server":      SPIRE Server only
#   - "agent-proxy": SPIRE Agent + Go proxy (egress or ingress)
# =============================================================================

# --- Stage 1: Protobuf generation ---
FROM golang:1.24-bookworm AS protogen

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

WORKDIR /src
COPY proto/ proto/
COPY go.mod .

# Generate Go code from proto
RUN mkdir -p internal/tunnel/tunnelpb && \
    protoc --go_out=. --go_opt=paths=source_relative \
           --go-grpc_out=. --go-grpc_opt=paths=source_relative \
           --go_opt=Mproto/tunnel.proto=github.com/project-aim/spiffe-proxy/internal/tunnel/tunnelpb \
           --go-grpc_opt=Mproto/tunnel.proto=github.com/project-aim/spiffe-proxy/internal/tunnel/tunnelpb \
           -I. proto/tunnel.proto

# Move generated files to the correct package directory
RUN mv proto/tunnel.pb.go internal/tunnel/tunnelpb/ 2>/dev/null || true && \
    mv proto/tunnel_grpc.pb.go internal/tunnel/tunnelpb/ 2>/dev/null || true && \
    ls -la internal/tunnel/tunnelpb/

# --- Stage 2: Build Go binary ---
FROM golang:1.24-bookworm AS builder

WORKDIR /src

# Copy module files and download deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source and generated protobuf code
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=protogen /src/internal/tunnel/tunnelpb/ internal/tunnel/tunnelpb/

# Build (go.sum is committed complete; no go mod tidy needed)
RUN CGO_ENABLED=0 GOOS=linux go build -o /spiffe-proxy ./cmd/main.go

# --- Stage 3: Runtime image ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    bash \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Install SPIRE binaries
ARG SPIRE_VERSION=1.9.6
RUN curl -sL "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz" \
    | tar xz -C /opt && \
    mv /opt/spire-${SPIRE_VERSION} /opt/spire

# Create directories
RUN mkdir -p /opt/spire/conf /opt/spire/data/server /opt/spire/data/agent /opt/spire/sockets

# Copy SPIRE configs
COPY spire-config/server.conf /opt/spire/conf/server.conf
COPY spire-config/agent.conf /opt/spire/conf/agent.conf

# Copy proxy binary
COPY --from=builder /spiffe-proxy /app/spiffe-proxy

# Copy RBAC policy config
COPY config/ /app/config/

# Copy IMDS mock (PoC workaround for ACI/Container Apps lacking metadata/instance)
COPY imds-mock.py /app/imds-mock.py

# Copy entrypoint
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Default environment
ENV CONTAINER_MODE=agent-proxy
ENV PROXY_MODE=egress
ENV SPIRE_SOCKET_PATH=/opt/spire/sockets/workload.sock

ENTRYPOINT ["/app/entrypoint.sh"]
