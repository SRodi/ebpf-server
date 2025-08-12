# ebpf-server - HTTP API Server with eBPF Network Monitoring
#
# Project Structure:
#   - docker/: Docker build files (Dockerfile, Dockerfile.aggregator)
#   - scripts/: Deployment and testing scripts
#   - kubernetes/: Kubernetes manifests
#   - bpf/: eBPF source code and compiled objects
#

# Variables
BINARY_NAME := ebpf-server
AGGREGATOR_NAME := ebpf-aggregator
BPF_SOURCES := $(wildcard bpf/*.c)
BPF_OBJECTS := $(BPF_SOURCES:.c=.o)
GO_SOURCES := $(shell find . -name '*.go' -not -path './vendor/*')

# Container settings
REGISTRY ?= localhost:5000
TAG ?= latest
AGENT_IMAGE := $(REGISTRY)/$(BINARY_NAME):$(TAG)
AGGREGATOR_IMAGE := $(REGISTRY)/$(AGGREGATOR_NAME):$(TAG)

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

# Build all eBPF programs
.PHONY: bpf
bpf: $(BPF_OBJECTS)
	@echo "All eBPF programs compiled successfully"

# Build the Go binary (server)
.PHONY: build-server
build-server: generate
	@echo "Building $(BINARY_NAME)..."
	go build -o bin/$(BINARY_NAME) ./cmd/server

# Build the aggregator binary
.PHONY: build-aggregator
build-aggregator: generate
	@echo "Building $(AGGREGATOR_NAME)..."
	go build -o bin/$(AGGREGATOR_NAME) ./cmd/aggregator

# Build the aggregator binary without eBPF dependencies (for Docker)
.PHONY: build-aggregator-only
build-aggregator-only:
	@echo "Building $(AGGREGATOR_NAME) (no eBPF dependencies)..."
	go build -o bin/$(AGGREGATOR_NAME) ./cmd/aggregator

# Build both binaries
.PHONY: build
build: build-server build-aggregator

# Build development version with debug symbols and verbose debug logging
.PHONY: build-dev
build-dev: generate
	@echo "Building $(BINARY_NAME) with debug symbols and debug logging..."
	CGO_ENABLED=1 CC=clang go build -race -tags debug -o bin/$(BINARY_NAME)-dev ./cmd/server

# Run the server (requires root for eBPF) - HTTP transport
.PHONY: run
run: build
	@echo "Running $(BINARY_NAME) (requires root privileges)..."
	@echo "HTTP server will start on port 8080"
	sudo ./bin/$(BINARY_NAME) -addr :8080

# Run in development mode
.PHONY: run-dev
run-dev: build-dev
	@echo "Running $(BINARY_NAME) in development mode..."
	sudo ./bin/$(BINARY_NAME)-dev -addr :8080

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
	rm -rf bpf/*.o

# Clean only eBPF objects (for fresh compilation)
.PHONY: clean-bpf
clean-bpf:
	@echo "Cleaning eBPF object files..."
	rm -rf bpf/*.o

# Fresh build - clean eBPF objects and rebuild everything
.PHONY: fresh-build
fresh-build: clean-bpf bpf docker-build
	@echo "Fresh build completed with new eBPF objects"

# Fresh build for kind testing - builds everything from scratch
.PHONY: fresh-kind-build
fresh-kind-build:
	@echo "🔄 Starting fresh build for kind testing..."
# 	@echo "1️⃣  Compiling fresh eBPF objects on host..."
# 	$(MAKE) bpf
	@echo "2️⃣  Building fresh Docker images..."
	$(MAKE) docker-build
	@echo "3️⃣  Loading images to kind..."
	$(MAKE) kind-load-images
	@echo "✅ Fresh kind build completed!"

# Generate API documentation using Swagger
.PHONY: docs
docs:
	@command -v $(shell go env GOPATH)/bin/swag >/dev/null 2>&1 || { echo "Installing swag..."; go install github.com/swaggo/swag/cmd/swag@latest; }
	$(shell go env GOPATH)/bin/swag init -g internal/api/handlers.go -o docs/swagger --parseDependency --parseInternal
	@echo "API documentation generated at docs/swagger/"
	@echo "Interactive docs: http://localhost:8080/docs/ (when server is running)"
	@echo "External docs: https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger.json"

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
	@echo "  all         - Generate eBPF bindings and build binaries"
	@echo "  generate    - Generate eBPF Go bindings"
	@echo "  bpf         - Compile eBPF programs"
	@echo "  vmlinux     - Generate vmlinux.h from running kernel (Linux only)"
	@echo "  build       - Build both server and aggregator binaries"
	@echo "  build-server - Build the server binary"
	@echo "  build-aggregator - Build the aggregator binary"
	@echo "  build-dev   - Build development binary with debug symbols"
	@echo "  run         - Run the server (requires root)"
	@echo "  run-dev     - Run development server"
	@echo "  test        - Run all tests"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  check       - Run linting and static analysis"
	@echo "  deps        - Install dependencies"
	@echo "  check-deps  - Check if dependencies are installed"
	@echo "  clean       - Clean build artifacts"
	@echo "  clean-bpf   - Clean only eBPF object files"
	@echo "  fresh-build - Clean eBPF objects and rebuild everything"
	@echo "  fresh-kind-build - Fresh build for kind testing"
	@echo ""
	@echo "Container targets:"
	@echo "  docker-build - Build Docker images (using docker/Dockerfile*)"
	@echo "  docker-push  - Push Docker images to registry"
	@echo "  docker-build-agent - Build agent Docker image"
	@echo "  docker-build-aggregator - Build aggregator Docker image"
	@echo ""
	@echo "Kubernetes targets:"
	@echo "  k8s-deploy   - Deploy to Kubernetes"
	@echo "  k8s-undeploy - Remove from Kubernetes"
	@echo "  k8s-logs     - Show logs from pods"
	@echo "  k8s-status   - Show pod status"
	@echo ""
	@echo "Kind (local testing) targets (using scripts/):"
	@echo "  kind-check-deps  - Check prerequisites for kind testing"
	@echo "  kind-cluster-create - Create kind cluster with local registry"
	@echo "  kind-cluster-delete - Delete kind cluster and registry"
	@echo "  kind-deploy  - Build and deploy to kind cluster"
	@echo "  kind-test    - Deploy and run basic tests in kind"
	@echo "  kind-full-test - Create cluster, deploy, and test"
	@echo "  kind-integration-test - Run comprehensive integration tests"
	@echo "  kind-cleanup - Clean up kind deployment"

# Container build targets
.PHONY: docker-build
docker-build: docker-build-agent docker-build-aggregator

.PHONY: docker-build-agent
docker-build-agent:
	@echo "Building agent Docker image..."
	docker build -t $(AGENT_IMAGE) -f docker/Dockerfile .

.PHONY: docker-build-aggregator
docker-build-aggregator:
	@echo "Building aggregator Docker image..."
	docker build -t $(AGGREGATOR_IMAGE) -f docker/Dockerfile.aggregator .

.PHONY: docker-push
docker-push:
	@echo "Pushing Docker images..."
	docker push $(AGENT_IMAGE)
	docker push $(AGGREGATOR_IMAGE)

# Kubernetes targets
.PHONY: k8s-deploy
k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f kubernetes/namespace.yaml
	kubectl apply -f kubernetes/rbac.yaml
	kubectl apply -f kubernetes/configmap.yaml
	kubectl apply -f kubernetes/services.yaml
	kubectl apply -f kubernetes/aggregator-deployment.yaml
	kubectl apply -f kubernetes/daemonset.yaml
	@echo "Waiting for deployments to be ready..."
	kubectl wait --for=condition=available --timeout=300s deployment/ebpf-aggregator -n ebpf-system
	kubectl rollout status daemonset/ebpf-monitor -n ebpf-system --timeout=300s

.PHONY: k8s-undeploy
k8s-undeploy:
	@echo "Removing from Kubernetes..."
	-kubectl delete -f kubernetes/daemonset.yaml
	-kubectl delete -f kubernetes/aggregator-deployment.yaml
	-kubectl delete -f kubernetes/services.yaml
	-kubectl delete -f kubernetes/configmap.yaml
	-kubectl delete -f kubernetes/rbac.yaml
	-kubectl delete -f kubernetes/namespace.yaml

.PHONY: k8s-logs
k8s-logs:
	@echo "Showing aggregator logs..."
	kubectl logs -l app=ebpf-aggregator -n ebpf-system --tail=100 -f

.PHONY: k8s-logs-agents
k8s-logs-agents:
	@echo "Showing agent logs..."
	kubectl logs -l app=ebpf-monitor -n ebpf-system --tail=50

.PHONY: k8s-status
k8s-status:
	@echo "Checking deployment status..."
	kubectl get pods -n ebpf-system
	kubectl get services -n ebpf-system
	kubectl get daemonset -n ebpf-system
	kubectl get deployment -n ebpf-system

# Combined build and deploy target
.PHONY: k8s-build-deploy
k8s-build-deploy: docker-build docker-push k8s-deploy

# Kind (Kubernetes in Docker) targets for local testing
KIND_CLUSTER_NAME ?= ebpf-test
KIND_REGISTRY_NAME ?= kind-registry
KIND_REGISTRY_PORT ?= 5001
KIND_NODE_IMAGE ?= kindest/node:v1.28.0

.PHONY: kind-check-deps
kind-check-deps:
	@echo "🔍 Checking Kind testing prerequisites..."
	@which kind > /dev/null || (echo "❌ Kind not found. Install from: https://kind.sigs.k8s.io/docs/user/quick-start/" && exit 1)
	@which docker > /dev/null || (echo "❌ Docker not found. Install Docker Desktop or Docker Engine" && exit 1)
	@which kubectl > /dev/null || (echo "❌ kubectl not found. Install from: https://kubernetes.io/docs/tasks/tools/" && exit 1)
	@which jq > /dev/null || (echo "⚠️  jq not found. Install for better test output: https://stedolan.github.io/jq/")
	@which curl > /dev/null || (echo "❌ curl not found. Install curl" && exit 1)
	@docker info > /dev/null 2>&1 || (echo "❌ Docker is not running. Start Docker Desktop or Docker daemon" && exit 1)
	@echo "✅ All prerequisites available!"

.PHONY: kind-cluster-create
kind-cluster-create: kind-check-deps
	@./scripts/create-kind-cluster.sh

.PHONY: kind-cluster-delete
kind-cluster-delete:
	@echo "🗑️ Deleting kind cluster and registry..."
	-kind delete cluster --name $(KIND_CLUSTER_NAME)
	-docker rm -f $(KIND_REGISTRY_NAME)
	@echo "✅ Kind cluster and registry deleted"

.PHONY: kind-load-images
kind-load-images: docker-build
	@./scripts/load-kind-images.sh

.PHONY: kind-deploy
kind-deploy: kind-load-images
	@./scripts/deploy-to-kind.sh

.PHONY: kind-test
kind-test: fresh-kind-build kind-deploy
	@./scripts/test-kind-deployment.sh

.PHONY: kind-full-test
kind-full-test: kind-cluster-create kind-test
	@echo "🎉 Full kind cluster test completed!"

.PHONY: kind-integration-test
kind-integration-test: kind-deploy
	@echo "🧪 Running comprehensive integration tests..."
	./scripts/test-kind.sh --automated

.PHONY: kind-cleanup
kind-cleanup:
	@echo "🧹 Cleaning up kind deployment..."
	-kubectl delete -f kubernetes/daemonset.yaml
	-kubectl delete -f kubernetes/aggregator-deployment.yaml
	-kubectl delete -f kubernetes/services.yaml
	-kubectl delete -f kubernetes/configmap.yaml
	-kubectl delete -f kubernetes/rbac.yaml
	-kubectl delete -f kubernetes/namespace.yaml
	@echo "✅ Kind deployment cleaned up"

# Create necessary directories
bin:
	mkdir -p bin
