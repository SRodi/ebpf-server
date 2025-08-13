# eBPF Network Monitor

[![CI](https://github.com/srodi/ebpf-server/actions/workflows/ci.yml/badge.svg)](https://github.com/srodi/ebpf-server/actions/workflows/ci.yml)
[![API Documentation](https://img.shields.io/badge/API-Documentation-blue?style=for-the-badge&logo=swagger)](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)
[![OpenAPI Spec](https://img.shields.io/badge/OpenAPI-3.0-green?style=for-the-badge&logo=openapiinitiative)](docs/swagger.json)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)

A modular eBPF monitoring system with HTTP API server for real-time network and system event monitoring. **Supports both VM and Kubernetes deployments** with automatic metadata enrichment.

## 🚀 Deployment Options

### Kubernetes Deployment (Recommended)

Deploy across your entire Kubernetes cluster with automatic node metadata enrichment:

```bash
# Quick deployment with built-in script
./scripts/deploy.sh all --registry your-registry.com

# Or step by step
make docker-build
make docker-push REGISTRY=your-registry.com
make k8s-deploy
```

**📖 [Complete Kubernetes Guide](kubernetes/README.md)** - Detailed setup and configuration

### Local Testing with Kind

Test the full Kubernetes deployment locally:

```bash
# Full automated test
make kind-full-test

# Or step by step:
make kind-cluster-create    # Create local cluster
make kind-deploy           # Deploy to kind cluster  
make kind-integration-test # Run comprehensive tests
```

To get detailed API documentation for the aggregator, available only in Kubernetes mode [see API Aggregator Documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger-aggregator/swagger.json)

### VM Deployment (Traditional)

For single-server deployments:

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y golang-go clang libbpf-dev linux-headers-$(uname -r)

# Build and run
make build
sudo ./bin/ebpf-server

# Test the API
curl http://localhost:8080/health
curl "http://localhost:8080/api/events?type=connection&limit=10"
```

**📚 [Interactive API Documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)** - Test APIs in your browser

## ✨ Key Features

### 🔄 Dual Deployment Support
- **Kubernetes Mode**: DaemonSet + Aggregator architecture for cluster-wide monitoring
- **VM Mode**: Traditional single-server deployment
- **Automatic Detection**: Seamlessly detects environment and adapts behavior

### 🏷️ Kubernetes Metadata Enrichment  
Events in Kubernetes include rich metadata:
```json
{
  "id": "abc123",
  "type": "connection",
  "k8s_node_name": "worker-node-1",
  "k8s_pod_name": "ebpf-monitor-xyz",
  "k8s_namespace": "ebpf-system",
  ...
}
```

### 🏗️ Scalable Architecture

**Kubernetes Mode**: Distributed monitoring with centralized aggregation
```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │    Node 1   │  │    Node 2   │  │        Node N   │  │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │   ┌─────────┐   │  │
│  │ │ eBPF    │ │  │ │ eBPF    │ │  │   │ eBPF    │   │  │
│  │ │ Agent   │ │  │ │ Agent   │ │  │   │ Agent   │   │  │
│  │ │+K8s Meta│ │  │ │+K8s Meta│ │  │   │+K8s Meta│   │  │
│  │ └────┬────┘ │  │ └────┬────┘ │  │   └────┬────┘   │  │
│  └──────┼──────┘  └──────┼──────┘  └────────┼────────┘  │
│         │                │                  │           │
│         └────────────────┼──────────────────┘           │
│                          │                              │
│                    ┌─────▼─────┐                        │
│                    │   eBPF    │                        │
│                    │ Aggregator│◄─── Unified API        │
│                    │           │                        │
│                    └───────────┘                        │
└─────────────────────────────────────────────────────────┘
```

**VM Mode**: Modular, interface-based monitoring system
```
┌─────────────────────────────────────────────────────┐
│                     eBPF Programs                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Connection  │  │ Packet Drop │  │   Custom    │  │
│  │ Monitor     │  │ Monitor     │  │   Monitors  │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────┬───┘  │
└─────────┼─────────────────┼──────────────────┼-─────┘
          │                 │                  │
          └─────────────────┼──────────────────┘
                            ▼
               ┌─────────────────────────┐
               │    Event Processing     │
               │   (Manager + Storage)   │
               └─────────────┬───────────┘
                             ▼
               ┌─────────────────────────┐
               │       HTTP API          │
               │    (/api/events)        │
               └─────────────────────────┘
```

### 📊 Unified Monitoring
- **Cross-Node Correlation**: View events across entire Kubernetes cluster
- **Node-Specific Filtering**: Query events by specific nodes or pods
- **Aggregated Statistics**: Cluster-wide event statistics and metrics
- **Backward Compatible**: Existing VM deployments continue unchanged

## 📡 API Features

- **Unified Event API**: Single `/api/events` endpoint for all monitoring data
- **Flexible Filtering**: Filter by event type, PID, command, and time windows  
- **Kubernetes Filtering**: Filter by node name, pod name, or namespace
- **Program Status**: View program status and metrics via `/api/programs`
- **Auto-Generated Documentation**: OpenAPI 3.0 spec from code annotations
- **Interactive Testing**: Built-in Swagger UI for API exploration

### Core Endpoints

- **`GET /health`** - System health and status
- **`GET /api/events`** - Query events with filtering support
- **`GET /api/programs`** - List all programs and their status

### Query Examples

```bash
# Get all connection events from the last hour
curl "http://localhost:8080/api/events?type=connection&since=2023-01-01T00:00:00Z"

# Get events for a specific process
curl "http://localhost:8080/api/events?pid=1234&limit=50"

# Kubernetes: Get events from specific node
curl "http://localhost:8080/api/events?k8s_node_name=worker-1"
```

### Query Parameters

- `type`: Event type filter (e.g., "connection", "packet_drop")
- `pid`: Process ID filter
- `command`: Command name filter
- `k8s_node_name`, `k8s_pod_name`, `k8s_namespace`: Kubernetes filters
- `since`, `until`: RFC3339 timestamp filters
- `limit`: Maximum results (default: 100)

## 🛠️ Development

```bash
# Development build with debug logging
make build-dev && sudo ./bin/ebpf-server-dev

# Generate API docs
make docs

# Run tests
make test

# Build eBPF programs
make build-bpf
```

**📚 [Complete Development Guide](docs/program-development.md)** - Detailed guide for creating new eBPF monitoring programs

## 📁 Project Structure

```
├── cmd/                 # Application entry points
│   ├── server/         # eBPF monitoring server
│   └── aggregator/     # Kubernetes aggregator
├── internal/
│   ├── core/          # Core interfaces and types
│   ├── events/        # Event system (BaseEvent, streams)
│   ├── programs/      # eBPF program implementations
│   ├── storage/       # Event storage and querying
│   ├── api/          # HTTP API handlers
│   ├── kubernetes/   # Kubernetes metadata integration
│   └── system/       # System initialization
├── bpf/              # eBPF C programs and headers
├── kubernetes/       # Kubernetes manifests
├── scripts/          # Deployment and testing scripts
└── docs/            # Documentation and API specs
```

## 🔧 Requirements

- **Linux kernel 4.18+** with eBPF support
- **Root privileges** for eBPF program loading  
- **Dependencies**: Go 1.23+, Clang, libbpf-dev, kernel headers
- **Kubernetes**: 1.20+ (for K8s deployment)

**📖 Setup Guide**: [docs/setup.md](docs/setup.md)

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
