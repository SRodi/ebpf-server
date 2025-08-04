# eBPF Network Monitor

[![CI Pipeline](https://github.com/srodi/mcp-ebpf/actions/workflows/ci.yml/badge.svg)](https://github.com/srodi/mcp-ebpf/actions/workflows/ci.yml)
[![API Documentation](https://img.shields.io/badge/API-Documentation-blue?style=for-the-badge&logo=swagger)](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)
[![OpenAPI Spec](https://img.shields.io/badge/OpenAPI-3.0-green?style=for-the-badge&logo=openapiinitiative)](docs/swagger.json)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)

A modular HTTP API server for real-time network monitoring using eBPF. Features a plugin architecture for easy extension with new monitoring capabilities.

## Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y golang-go clang libbpf-dev linux-headers-$(uname -r)

# Build and run
make build
sudo ./bin/ebpf-server

# Test the API
curl http://localhost:8080/health
curl -X POST http://localhost:8080/api/connections/summary -d '{"duration":60}'
```

**📚 [Interactive API Documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger.json)** - Test APIs directly in your browser

## Architecture

**Plugin-based monitoring system** where each eBPF program runs independently:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ HTTP Client │───▶│ REST API     │───▶│ eBPF Manager│
└─────────────┘    │ (Auto-docs)  │    │ (Lifecycle) │
                   └──────────────┘    └─────────────┘
                                              │
                          ┌───────────────────┼──────────────────┐
                          │                   │                  │
                   ┌──────▼──────┐    ┌───────▼───────┐   ┌─────▼─────┐
                   │ Connection  │    │ Packet Drop   │   │  Your     │
                   │ Monitor     │    │ Monitor       │   │  Plugin   │
                   └─────────────┘    └───────────────┘   └───────────┘
```

**Core Components:**
- **Manager**: Centralized lifecycle management for all eBPF programs
- **Storage**: Unified event collection and querying across programs  
- **API**: Auto-documented REST endpoints with OpenAPI support
- **Plugins**: Independent eBPF programs that can be added without affecting others

## Extending the API

### 1. Create a New Monitoring Program

```bash
mkdir -p internal/bpf/programs/your_monitor
```

### 2. Define Event Type

```go
// internal/bpf/programs/your_monitor/event.go
package your_monitor

import "github.com/srodi/ebpf-server/internal/bpf"

type Event struct {
    bpf.BaseEvent
    CustomField string `json:"custom_field"`
}

func (e *Event) GetEventType() string {
    return "your_monitor"
}
```

### 3. Implement Program

```go
// internal/bpf/programs/your_monitor/program.go
package your_monitor

import (
    "context"
    "github.com/srodi/ebpf-server/internal/bpf"
)

type Program struct {
    name        string
    description string
    objectPath  string
    storage     bpf.EventStorage
    // ... other fields
}

func NewProgram(storage bpf.EventStorage) *Program {
    return &Program{
        name:        "your_monitor",
        description: "Monitors your custom events",
        objectPath:  "bpf/your_monitor.o",
        storage:     storage,
    }
}

// Implement bpf.BPFProgram interface methods:
func (p *Program) GetName() string { return p.name }
func (p *Program) GetDescription() string { return p.description }
func (p *Program) Load() error { /* Load eBPF bytecode */ }
func (p *Program) Attach() error { /* Attach to kernel hooks */ }
func (p *Program) Start(ctx context.Context) error { /* Start processing */ }
func (p *Program) Stop() error { /* Cleanup */ }
// ... implement remaining interface methods
```

### 4. Register Program

```go
// Add to internal/bpf/loader.go in registerDefaultPrograms()
yourMonitor := your_monitor.NewProgram(storage)
if err := globalManager.RegisterProgram(yourMonitor); err != nil {
    return fmt.Errorf("failed to register your_monitor: %w", err)
}
```

### 5. Add API Endpoints (Optional)

API endpoints are auto-generated from the unified `/api/events` interface, but you can add custom endpoints:

```go
// internal/api/handlers.go
// @Summary Get your monitor statistics
// @Description Returns metrics for your custom monitoring program
// @Tags your_monitor
// @Produce json
// @Param duration query int true "Time window in seconds"
// @Success 200 {object} map[string]interface{}
// @Router /api/your_monitor/summary [post]
func HandleYourMonitorSummary(w http.ResponseWriter, r *http.Request) {
    // Implementation using the unified storage interface
}
```

### 6. Create eBPF C Program

```c
// bpf/your_monitor.c
#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct your_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
    char custom_field[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/your_tracepoint")
int trace_your_event(struct trace_event_raw_your_tracepoint *ctx) {
    // eBPF program logic
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## API Features

- **Auto-Generated Documentation**: OpenAPI 3.0 spec from code annotations
- **Interactive Testing**: Built-in Swagger UI at `/docs` endpoint
- **Unified Querying**: Single `/api/events` endpoint for all monitoring data
- **Flexible Filtering**: Filter by PID, command, event type, and time windows
- **Code-Driven**: Documentation stays in sync automatically

## Development

```bash
# Development build with debug logging
make build-dev && sudo ./bin/ebpf-server-dev

# Generate API docs
make docs

# Run tests
make test
```

## Requirements

- **Linux kernel 4.18+** with eBPF support
- **Root privileges** for eBPF program loading
- **Dependencies**: Go 1.23+, Clang, libbpf-dev, kernel headers

For detailed setup: [docs/setup.md](docs/setup.md) | Development guide: [docs/program-development.md](docs/program-development.md)

## License

MIT License - see [LICENSE](LICENSE) file.
