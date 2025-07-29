# mcp-ebpf - MCP Server with eBPF Network Monitoring

# Variables
BINARY_NAME := mcp-ebpf
BPF_SOURCES := $(wildcard bpf/*.c)
BPF_OBJECTS := $(BPF_SOURCES:.c=.o)
GO_SOURCES := $(shell find . -name '*.go' -not -path './vendor/*')

# Detect architecture and OS
ARCH := $(shell uname -m)
OS := $(shell uname -s)

# eBPF compilation settings
ifeq ($(ARCH),x86_64)
    TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
    TARGET_ARCH := arm64
else ifeq ($(ARCH),arm64)
    TARGET_ARCH := arm64
else
    TARGET_ARCH := $(ARCH)
endif

# Include paths for different systems
ifeq ($(OS),Darwin)
    # macOS - eBPF development is limited, mainly for cross-compilation
    BPF_INCLUDES := -I./bpf/include
else
    # Linux
    BPF_INCLUDES := -I/usr/include/$(ARCH)-linux-gnu -I./bpf/include
endif

# Default target
.PHONY: all
all: generate build

# Generate eBPF Go bindings
.PHONY: generate
generate: $(BPF_OBJECTS)
	@echo "Generating eBPF Go bindings..."
	go generate ./...

# Generate vmlinux.h from running kernel (Linux only)
.PHONY: vmlinux
vmlinux:
	@if [ "$(OS)" = "Linux" ]; then \
		echo "Generating vmlinux.h from running kernel..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h.generated; \
		echo "Generated bpf/include/vmlinux.h.generated"; \
		echo "You can replace bpf/include/vmlinux.h with this file for better kernel compatibility"; \
	else \
		echo "vmlinux.h generation is only supported on Linux systems"; \
		echo "Using provided minimal vmlinux.h for development"; \
	fi

# Compile eBPF programs
%.o: %.c
	@echo "Compiling eBPF program: $<"
	@if [ "$(OS)" = "Darwin" ]; then \
		echo "Warning: eBPF compilation on macOS is for development only and may not work at runtime"; \
		echo "Consider using a Linux VM or container for actual eBPF development"; \
	fi
	clang -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
		$(BPF_INCLUDES) \
		-Wall \
		-g -c $< -o $@

# Build the Go binary
.PHONY: build
build: $(BPF_OBJECTS)
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(BINARY_NAME) ./cmd/server

# Development build with debug symbols and debug logging
.PHONY: build-dev
build-dev: $(BPF_OBJECTS)
	@echo "Building $(BINARY_NAME) with debug symbols and debug logging..."
	go build -race -tags debug -o bin/$(BINARY_NAME)-dev ./cmd/server

# Run the server (requires root for eBPF)
.PHONY: run
run: build
	@echo "Running $(BINARY_NAME) (requires root privileges)..."
	sudo ./bin/$(BINARY_NAME)

# Run in development mode
.PHONY: run-dev
run-dev: build-dev
	@echo "Running $(BINARY_NAME) in development mode..."
	sudo ./bin/$(BINARY_NAME)-dev

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing Go dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Run linting
.PHONY: lint
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	@echo "Formatting C code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(BPF_SOURCES); \
	else \
		echo "clang-format not installed, skipping C formatting"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f $(BPF_OBJECTS)
	rm -f bpf/*.skel.go
	rm -f bpf/include/vmlinux.h.generated
	go clean

# Install the binary system-wide
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp bin/$(BINARY_NAME) /usr/local/bin/

# Uninstall the binary
.PHONY: uninstall
uninstall:
	@echo "Removing $(BINARY_NAME) from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# Development tools setup
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Development setup complete!"

# Check system requirements
.PHONY: check-deps
check-deps:
	@echo "Checking system dependencies..."
	@command -v clang >/dev/null 2>&1 || (echo "clang is required but not installed" && exit 1)
	@command -v go >/dev/null 2>&1 || (echo "Go is required but not installed" && exit 1)
	@if [ "$(OS)" = "Linux" ]; then \
		echo "Linux system detected - full eBPF support available"; \
		if command -v bpftool >/dev/null 2>&1; then \
			echo "bpftool found - can generate proper vmlinux.h"; \
		else \
			echo "bpftool not found - using minimal vmlinux.h (install bpftool for better compatibility)"; \
		fi; \
	else \
		echo "Non-Linux system detected ($(OS)) - eBPF programs will compile but won't run"; \
		echo "Consider using Docker or a Linux VM for actual eBPF development"; \
	fi
	@echo "All basic dependencies are available!"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all         - Generate eBPF bindings and build the binary"
	@echo "  generate    - Generate eBPF Go bindings"
	@echo "  vmlinux     - Generate vmlinux.h from running kernel (Linux only)"
	@echo "  build       - Build the release binary"
	@echo "  build-dev   - Build development binary with debug symbols"
	@echo "  run         - Run the server (requires root)"
	@echo "  run-dev     - Run development server"
	@echo "  deps        - Install Go dependencies"
	@echo "  test        - Run tests"
	@echo "  test-race   - Run tests with race detection"
	@echo "  lint        - Run linters"
	@echo "  fmt         - Format code"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary system-wide"
	@echo "  uninstall   - Remove binary from system"
	@echo "  dev-setup   - Setup development tools"
	@echo "  check-deps  - Check system dependencies"
	@echo "  help        - Show this help message"

# Create necessary directories
bin:
	mkdir -p bin
