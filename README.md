# eBPF Network Monitor

[![CI Pipeline](https://github.com/srodi/ebpf-server/actions/workflows/ci.yml/badge.svg)](https://github.com/srodi/ebpf-server/actions/workflows/ci.yml)
[![API Documentation](https://img.shields.io/badge/API-Documentation-blue?style=for-the-badge&logo=swagger)](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)
[![OpenAPI Spec](https://img.shields.io/badge/OpenAPI-3.0-green?style=for-the-badge&logo=openapiinitiative)](docs/swagger.json)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)

A modular eBPF monitoring system with HTTP API server for real-time network and system event monitoring. Features a clean, interface-based architecture for easy extension with new monitoring programs.

## Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y golang-go clang libbpf-dev linux-headers-$(uname -r)

# Build and run
make build
sudo ./bin/ebpf-server

# Test the API
curl http://localhost:8080/health
curl "http://localhost:8080/api/events?type=connection&limit=10"
curl "http://localhost:8080/api/programs"
```

**📚 [View Interactive API Documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)** - Test APIs directly in your browser

## Architecture

**Modular, interface-based monitoring system** with clean separation of concerns:

```
┌───────────────────────────────────────────────────────────┐
│                        System Layer                       │
│  ┌─────────────────────────────────────────────────────┐  │
│  │                  Manager                            │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │ Connection  │  │ Packet Drop │  │   Your New  │  │  │
│  │  │ Program     │  │ Program     │  │   Program   │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
                            │
                   ┌────────┴────────┐
                   │                 │
          ┌────────▼────────┐  ┌─────▼─────┐
          │ Event Storage   │  │ HTTP API  │
          │ (Unified)       │  │ Handlers  │
          └─────────────────┘  └───────────┘
```

**Core Components:**
- **Core Interfaces**: Define contracts for Events, Programs, Managers, and Storage
- **Event System**: Unified event creation, streaming, and storage with `BaseEvent`
- **Program Manager**: Coordinates program lifecycle and provides unified event streams
- **Storage Layer**: Persistent event storage with query capabilities  
- **API Layer**: HTTP endpoints for querying events and program status
- **System Layer**: Top-level coordination and initialization

## Event Flow Architecture

The system processes events through a real-time streaming pipeline that ensures low latency and high throughput:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   eBPF Program  │    │   Ring Buffer   │    │  Event Parser   │    │  Event Stream   │
│                 │    │                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ sys_connect │ │───▶│ │   events    │ │───▶│ │ Connection  │ │───▶│ │   Channel   │ │
│ │ tracepoint  │ │    │ │   (16MB)    │ │    │ │  Parser     │ │    │ │ (buffered)  │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
│ │ kfree_skb   │ │───▶│ │drop_events  │ │───▶│ │ PacketDrop  │ │───▶│                 │
│ │ tracepoint  │ │    │ │  (256KB)    │ │    │ │   Parser    │ │    │                 │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │                       │
   Kernel Space               Ring Buffer              Go Application          Event Stream
   (eBPF Programs)           (Temporary)               (Event Parsing)         (Buffered)
                                 │                                                │
                                 ▼                                                ▼
                        ┌─────────────────────┐                     ┌─────────────────────┐
                        │   Always Empty      │                     │ ┌─────────────────┐ │
                        │                     │                     │ │ Memory Storage  │ │
                        │ Events consumed     │                     │ │                 │ │
                        │ immediately by      │                     │ │ • Query Events  │ │
                        │ userspace readers   │                     │ │ • Time Filters  │ │
                        └─────────────────────┘                     │ │ • PID Grouping  │ │
                                                                    │ └─────────────────┘ │
                                                                    │          │          │
                                                                    │          ▼          │
                                                                    │ ┌─────────────────┐ │
                                                                    │ │   HTTP API      │ │
                                                                    │ │                 │ │
                                                                    │ │ /api/list-      │ │
                                                                    │ │ connections     │ │
                                                                    │ │                 │ │
                                                                    │ │ /api/list-      │ │
                                                                    │ │ packet-drops    │ │
                                                                    │ └─────────────────┘ │
                                                                    └─────────────────────┘


```

### Ring buffers

Ring buffers in eBPF are designed for real-time streaming:

1. **eBPF programs** write events to ring buffers using `bpf_ringbuf_reserve()` and `bpf_ringbuf_submit()`
2. **Userspace readers** immediately consume events using `ringbuf.NewReader()`
3. **Events are parsed** and sent to Go event streams
4. **Ring buffers become empty** as events are consumed in real-time
5. **Events are stored** in memory for API queries

Events flow through the pipeline without accumulating in kernel space.

## Extending the System

📚 **[Complete Development Guide](docs/program-development.md)** - Detailed guide for creating new eBPF monitoring programs

### Quick Example: Create a New Monitoring Program

### 1. Create a New Monitoring Program

```bash
mkdir -p internal/programs/your_monitor
```

### 2. Implement Your Program

Create `internal/programs/your_monitor/your_monitor.go`:

```go
package your_monitor

import (
    "context"
    "encoding/binary"
    "fmt"
    
    "github.com/srodi/ebpf-server/internal/core"
    "github.com/srodi/ebpf-server/internal/events"
    "github.com/srodi/ebpf-server/internal/programs"
    "github.com/srodi/ebpf-server/pkg/logger"
)

const (
    ProgramName        = "your_monitor"
    ProgramDescription = "Monitors your custom events"
    ObjectPath         = "bpf/your_monitor.o"
    TracepointProgram  = "trace_your_event"
    EventsMapName      = "events"
)

type Program struct {
    *programs.BaseProgram
}

func NewProgram() *Program {
    base := programs.NewBaseProgram(ProgramName, ProgramDescription, ObjectPath)
    return &Program{BaseProgram: base}
}

func (p *Program) Attach(ctx context.Context) error {
    if !p.IsLoaded() {
        return fmt.Errorf("program not loaded")
    }
    
    logger.Debugf("Attaching %s program", ProgramName)
    
    if err := p.AttachTracepoint("syscalls", "your_event", TracepointProgram); err != nil {
        return fmt.Errorf("failed to attach: %w", err)
    }
    
    if err := p.StartEventProcessing(ctx, EventsMapName, p.parseEvent); err != nil {
        return fmt.Errorf("failed to start processing: %w", err)
    }
    
    p.SetAttached(true)
    return nil
}

func (p *Program) parseEvent(data []byte) (core.Event, error) {
    if len(data) < 24 {
        return nil, fmt.Errorf("insufficient data: %d bytes", len(data))
    }
    
    pid := binary.LittleEndian.Uint32(data[0:4])
    timestamp := binary.LittleEndian.Uint64(data[4:12])
    command := extractNullTerminatedString(data[12:])
    
    metadata := map[string]interface{}{
        "custom_field": "custom_value",
    }
    
    return events.NewBaseEvent(ProgramName, pid, command, timestamp, metadata), nil
}
```
### 3. Register Your Program

Add to `internal/system/system.go` in the `Initialize()` method:

```go
// Register your program
yourProgram := your_monitor.NewProgram()
if err := s.manager.RegisterProgram(yourProgram); err != nil {
    return fmt.Errorf("failed to register your_monitor: %w", err)
}
logger.Debugf("✅ Registered your monitoring program")
```

### 4. Create eBPF C Code

Create `bpf/your_monitor.c`:

```c
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct your_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
    char custom_field[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/your_event")
int trace_your_event(void *ctx) {
    struct your_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Add your custom logic here
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## API Features

- **Unified Event API**: Single `/api/events` endpoint for all monitoring data
- **Flexible Filtering**: Filter by event type, PID, command, and time windows
- **Program Status**: View program status and metrics via `/api/programs`
- **Auto-Generated Documentation**: OpenAPI 3.0 spec from code annotations
- **Interactive Testing**: Built-in Swagger UI for API exploration

## API Endpoints

### Core Endpoints

- **`GET /health`** - System health and status
- **`GET /api/events`** - Query events with filtering support
- **`GET /api/programs`** - List all programs and their status

### Event Query Examples

```bash
# Get all connection events from the last hour
curl "http://localhost:8080/api/events?type=connection&since=2023-01-01T00:00:00Z"

# Get events for a specific process
curl "http://localhost:8080/api/events?pid=1234&limit=50"

# Get packet drop events with command filter
curl "http://localhost:8080/api/events?type=packet_drop&command=curl"
```

### Query Parameters

- `type`: Event type filter (e.g., "connection", "packet_drop")
- `pid`: Process ID filter
- `command`: Command name filter
- `since`: RFC3339 timestamp for start time
- `until`: RFC3339 timestamp for end time
- `limit`: Maximum results (default: 100)

## Development

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

## Project Structure

```
├── cmd/server/           # Main application entry point
├── internal/
│   ├── core/            # Core interfaces and types
│   ├── events/          # Event system (BaseEvent, streams)
│   ├── programs/        # eBPF program implementations
│   │   ├── base.go      # BaseProgram foundation
│   │   ├── manager.go   # Program manager
│   │   ├── connection/  # Network connection monitoring
│   │   └── packet_drop/ # Packet drop monitoring
│   ├── storage/         # Event storage and querying
│   ├── api/            # HTTP API handlers
│   └── system/         # System initialization and coordination
├── bpf/                # eBPF C programs and headers
├── docs/               # Documentation and API specs
└── pkg/logger/         # Logging utilities
```

## Requirements

- **Linux kernel 4.18+** with eBPF support
- **Root privileges** for eBPF program loading
- **Dependencies**: Go 1.23+, Clang, libbpf-dev, kernel headers

For detailed setup: [docs/setup.md](docs/setup.md) | Development guide: [docs/program-development.md](docs/program-development.md)

## License

MIT License - see [LICENSE](LICENSE) file.
