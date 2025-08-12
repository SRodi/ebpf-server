# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies including clang for eBPF compilation
RUN apk add --no-cache \
    build-base \
    clang \
    llvm \
    linux-headers \
    libbpf-dev \
    pkgconfig

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the application (eBPF objects should already be compiled on host)
RUN mkdir -p bin
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/ebpf-server ./cmd/server

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary and eBPF objects from builder stage
COPY --from=builder /app/bin/ebpf-server .
COPY --from=builder /app/bpf/*.o ./bpf/

# Create non-root user (though we'll run as root for eBPF)
RUN useradd -m -s /bin/bash ebpf

# Expose port
EXPOSE 8080

# Run as root (required for eBPF)
USER root

ENTRYPOINT ["./ebpf-server"]
