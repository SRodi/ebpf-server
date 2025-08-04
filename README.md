# eBPF Network Monitor

[![API Documentation](https://img.shields.io/badge/API-Documentation-blue?style=for-the-badge&logo=swagger)](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger.json)
[![OpenAPI Spec](https://img.shields.io/badge/OpenAPI-3.0-green?style=for-the-badge&logo=openapiinitiative)](docs/swagger.json)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)

A modular HTTP API server that uses eBPF to monitor network connections with an extensible plugin architecture.

## Quick Start

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y golang-go clang libbpf-dev linux-headers-$(uname -r)

# Build and run
make build
sudo ./bin/ebpf-server

# Test the API
curl http://localhost:8080/health
curl http://localhost:8080/api/connections/summary?pid=1234&duration=60
```

## Architecture

This project implements a **modular eBPF monitoring system** with:

- **Plugin-style eBPF Programs**: Independent, hot-swappable monitoring modules
- **REST API**: Auto-documented endpoints with OpenAPI support  
- **Manager-based Lifecycle**: Centralized program registration and management
- **Event Storage**: Unified event collection and querying

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Client   │───▶│ HTTP API Server │───▶│  eBPF Manager   │
│ (monitoring)    │    │ (Auto-documented)│    │   (Plugins)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────────────────────┼─────────────────┐
                       │                                 │                 │
                ┌──────▼──────┐                 ┌────────▼────────┐       ┌─▼─┐
                │ Connection  │                 │  Packet Drop    │       │...│
                │  Monitor    │                 │   Monitor       │       └───┘
                └─────────────┘                 └─────────────────┘
```

## Adding New eBPF Programs

### 1. Create Program Package

```bash
mkdir -p internal/bpf/programs/your_program
```

### 2. Implement the BPFProgram Interface

```go
// internal/bpf/programs/your_program/program.go
package your_program

import (
    "context"
    "github.com/srodi/ebpf-server/internal/bpf"
)

type Program struct {
    // Your program implementation
}

func NewProgram(storage bpf.EventStorage) *Program {
    return &Program{
        // Initialize your program
    }
}

// Implement bpf.BPFProgram interface methods:
func (p *Program) GetName() string { return "your_program" }
func (p *Program) GetDescription() string { return "Your program description" }
func (p *Program) GetObjectPath() string { return "bpf/your_program.o" }
func (p *Program) Load() error { /* Load eBPF bytecode */ }
func (p *Program) Attach() error { /* Attach to kernel hooks */ }
func (p *Program) Start(ctx context.Context) error { /* Start event processing */ }
func (p *Program) Stop() error { /* Clean up resources */ }
// ... other required methods
```

### 3. Create Event Type

```go
// internal/bpf/programs/your_program/event.go
package your_program

import (
    "github.com/srodi/ebpf-server/internal/bpf"
)

type Event struct {
    bpf.BaseEvent
    // Your custom event fields
    CustomField string `json:"custom_field"`
}

func (e *Event) GetEventType() string {
    return "your_program"
}

// Implement any additional event methods
```

### 4. Register with Manager

```go
// Add to internal/bpf/loader.go registerDefaultPrograms() function
func registerDefaultPrograms() error {
    storage := globalManager.GetStorage()

    // Existing programs...
    
    // Register your program
    yourProg := your_program.NewProgram(storage)
    if err := globalManager.RegisterProgram(yourProg); err != nil {
        return fmt.Errorf("failed to register your_program: %w", err)
    }

    return nil
}
```

### 5. Add API Endpoints (Optional)

API endpoints are auto-generated, but you can add custom endpoints:

```go
// internal/api/handlers.go - Add custom handlers if needed
func handleYourProgramSummary(w http.ResponseWriter, r *http.Request) {
    // @Summary Get your program statistics
    // @Description Returns event count and metrics for your program
    // @Tags your_program
    // @Produce json
    // @Param pid query int false "Process ID"
    // @Param duration query int true "Time window in seconds"
    // @Success 200 {object} map[string]interface{}
    // @Router /api/your_program/summary [get]
    
    // Implementation...
}
```

## API Documentation

The API is **self-documenting** using embedded OpenAPI annotations. Documentation is automatically generated from code.

### 🌐 Interactive Documentation

```bash
# Start server
sudo ./bin/ebpf-server

# Access interactive docs
open http://localhost:8080/docs
```

###  API Features

- **Auto-Generated Documentation**: OpenAPI 3.0 spec generated from code annotations
- **Interactive Testing**: Built-in Swagger UI for API exploration  
- **Type Safety**: Strongly typed request/response models
- **Error Handling**: Consistent error responses with helpful messages
- **Flexible Filtering**: Query events by PID, command, type, and time windows

## Development

```bash
# Development build with debug logging
make build-dev
sudo ./bin/ebpf-server-dev

# Run tests
make test

# Generate API docs
make docs
```

## Configuration

Environment variables:
- `PORT`: HTTP server port (default: 8080)
- `LOG_LEVEL`: debug, info, warn, error (default: info)
- `DOCS_ENABLED`: Enable API documentation endpoint (default: true)

## Requirements

- Linux kernel 4.18+ with eBPF support
- Root privileges for eBPF program loading
- Go 1.23.0+, Clang, libbpf-dev

For detailed setup instructions, see [docs/setup.md](docs/setup.md).

## License

MIT License - see [LICENSE](LICENSE) file.
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install -y golang clang libbpf-devel kernel-devel
```

**Arch Linux:**
```bash
sudo pacman -S go clang libbpf linux-headers
```

**macOS (for development only):**
```bash
brew install go llvm
```

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/srodi/ebpf-server.git
   cd ebpf-server
   ```

2. **Check system dependencies:**
   ```bash
   make check-deps
   ```

3. **Install Go dependencies:**
   ```bash
   make deps
   ```

4. **Build the project:**
   ```bash
   make build
   ```

5. **Run the server (requires root):**
   ```bash
   sudo make run
   ```
   This starts the HTTP API server on port 8080.

   **Alternative**: Run directly with custom address
   ```bash
   sudo ./bin/ebpf-server -addr :9090
   ```

## Testing

To test that the server is working correctly:

1. **Run the unit tests:**
   ```bash
   make test
   ```

2. **Test the HTTP API server:**
   ```bash
   # Start the server (requires root)
   sudo make run
   
   # Test from another terminal
   curl http://localhost:8080/health
   
   # Test connection summary
   curl -X POST http://localhost:8080/api/connection-summary \
     -H "Content-Type: application/json" \
     -d '{"command":"test","duration":30}'
   
   # Test list connections
   curl http://localhost:8080/api/list-connections
   ```

3. **Generate network activity for monitoring:**
   ```bash
   # In another terminal, create some connections
   curl -s http://httpbin.org/ip > /dev/null
   curl -s https://www.google.com > /dev/null
   
   # Check captured connections
   curl http://localhost:8080/api/list-connections | jq .
   ```

4. **Test with specific processes:**
   ```bash
   # Get summary for curl commands
   curl -X POST http://localhost:8080/api/connection-summary \
     -H "Content-Type: application/json" \
     -d '{"command":"curl","duration":60}'
   
   # Monitor specific PID
   curl -X POST http://localhost:8080/api/connection-summary \
     -H "Content-Type: application/json" \
     -d '{"pid":1234,"duration":30}'
   ```

**Note:** 
- The API captures `connect()` syscall attempts, useful for monitoring **persistent services** and **connection patterns**
- For short-lived processes like individual curl commands, use the **command name** instead of PID
- Current eBPF program monitors TCP `connect()` syscalls only (not ICMP like ping)
- API responses include human-readable messages along with structured data

## Protocol Detection and Testing

The HTTP API server includes enhanced protocol detection that identifies connection types and provides detailed network information:

### Supported Protocols

**✅ Captured Protocols:**
- **TCP** - All TCP connections (HTTP, HTTPS, SSH, etc.)
- **UDP** - UDP connections that use `connect()` (DNS queries, some applications)
- **Unix Domain Sockets** - Local IPC connections

**❌ Not Captured:**
- **UDP with sendto()** - Most UDP traffic uses `sendto()` without `connect()`
- **Raw sockets** - Don't use the `connect()` syscall
- **ICMP** - ping and other ICMP traffic

### Protocol Detection Features

- **Port-based heuristics** - Intelligently identifies protocols by destination port
- **Socket type classification** - Distinguishes STREAM (TCP) vs DGRAM (UDP)
- **Wall clock timestamps** - Human-readable time conversion from boot time
- **Complete connection details** - Source process, destination IP/port, protocol info

### Testing Protocol Detection

```bash
# Start the HTTP API server
sudo make run

# In another terminal, generate test connections
python3 -c "
import socket
import time

print('Testing TCP connection...')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('httpbin.org', 80))
s.close()

print('Testing UDP with connect()...')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 53))  # This will be captured
s.close()

print('Testing UDP with sendto()...')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'test', ('8.8.8.8', 53))  # This will NOT be captured
s.close()

print('Test complete')
"

# Check captured connections using the HTTP API
curl http://localhost:8080/api/list-connections | jq .

# Get summary for python connections
curl -X POST http://localhost:8080/api/connection-summary \
  -H "Content-Type: application/json" \
  -d '{"command":"python3","duration":60}'
```

### Example Protocol Detection Output

```json
{
  "pid": 1234,
  "command": "python3",
  "destination_ip": "8.8.8.8",
  "destination_port": 53,
  "destination": "8.8.8.8:53",
  "address_family": 2,
  "protocol": "UDP",
  "socket_type": "DGRAM",
  "wall_time": "2025-07-29T14:30:56Z"
}
```

### Connection Types You'll See

1. **DNS Queries** - `127.0.0.53:53` (local resolver) or `192.168.x.x:53` (network DNS)
2. **HTTP/HTTPS** - Various IPs on ports 80/443 with TCP protocol
3. **System Services** - Unix domain sockets with `address_family: 1`
4. **Application Traffic** - Protocol determined by port (SSH=22, HTTP=80, HTTPS=443, etc.)

## Development

### Building

```bash
# Build release version (production)
make build

# Build development version with debug symbols and verbose debug logging
make build-dev

# Build and run in development mode
make run-dev
```

**Debug Logging:**
- `make build`: Production build with minimal logging (INFO level and above)
- `make build-dev`: Development build with extensive debug logging showing:
  - Raw eBPF event data and parsing details
  - Connection tracking and storage operations
  - API request processing and response details
  - Ring buffer event processing information

### Testing

```bash
# Run all unit tests
make test

# Run tests with race detection
make test-race

# Test the HTTP API integration
curl http://localhost:8080/health
```

**Test Coverage:**
- **Logger Package**: Debug level functionality, global logger behavior, level switching
- **BPF Types**: Event parsing, IP conversion, protocol/socket type detection, time conversion
- **API Handlers**: HTTP endpoints, request/response handling, error cases, input validation
- **HTTP Server**: Route handling, timeouts, integration testing
- **Integration Testing**: API endpoint testing with various request types

### Code Quality

```bash
# Format code
make fmt

# Run linters
make lint
```

### Development Setup

```bash
# Setup development tools
make dev-setup
```

## Project Structure

```
.
├── bpf/                           # eBPF programs (C)
│   ├── connection.c               # Connection monitoring eBPF program
│   └── packet_drop.c              # Packet drop monitoring eBPF program
├── cmd/
│   └── server/                    # HTTP server application
│       ├── main.go                # Application entry point
│       ├── main_test.go           # Server integration tests
│       └── debug.go               # Debug build configuration
├── docs/                          # Documentation
│   ├── setup.md                   # Installation and setup guide
│   ├── program-development.md     # Guide for adding new eBPF programs
│   └── swagger/                   # Auto-generated API documentation
│       ├── docs.go                # Generated Go bindings
│       ├── swagger.json           # OpenAPI 3.0 specification
│       └── swagger.yaml           # OpenAPI 3.0 specification (YAML)
├── internal/
│   ├── api/                       # HTTP API layer
│   │   ├── docs.go                # API documentation metadata
│   │   ├── handlers.go            # HTTP request handlers with OpenAPI annotations
│   │   └── handlers_test.go       # API handler unit tests
│   └── bpf/                       # eBPF management layer
│       ├── interfaces.go          # Core interfaces (BPFProgram, EventStorage, Manager)
│       ├── manager.go             # Program lifecycle management
│       ├── manager_test.go        # Manager unit tests
│       ├── storage.go             # Event storage implementation
│       ├── storage_test.go        # Storage unit tests
│       ├── loader.go              # eBPF program loading logic
│       ├── loader_test.go         # Loader unit tests
│       ├── base.go                # Base event implementation
│       ├── types.go               # eBPF data structures and utilities
│       ├── types_test.go          # Type conversion unit tests
│       ├── mock_test.go           # Test mocks and utilities
│       ├── integration_test.go    # Integration tests
│       ├── benchmark_test.go      # Performance benchmarks
│       └── programs/              # Modular eBPF program implementations
│           ├── connection/        # Connection monitoring plugin
│           │   ├── program.go     # Program implementation
│           │   ├── event.go       # Event type definition
│           │   └── connection_test.go # Program tests
│           └── packet_drop/       # Packet drop monitoring plugin
│               ├── program.go     # Program implementation
│               ├── event.go       # Event type definition
│               └── packet_drop_test.go # Program tests
├── pkg/
│   └── logger/                    # Custom logging package
│       ├── logger.go              # Logger implementation
│       └── logger_test.go         # Logger unit tests
├── ARCHITECTURE.md                # Detailed architecture documentation
├── go.mod                         # Go module definition
├── go.sum                         # Go module checksums
├── Makefile                       # Build automation
└── README.md                      # This file
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - eBPF programs require root privileges
   - Run with `sudo` or as root user

2. **eBPF Program Load Failed**
   - Check kernel version (requires 4.18+)
   - Ensure kernel headers are installed
   - Verify BTF (BPF Type Format) support

3. **Compilation Errors**
   - Install clang and libbpf development packages
   - Check that kernel headers match running kernel

### Debug Mode

Run with debug symbols and verbose logging for detailed troubleshooting:
```bash
make build-dev
sudo ./bin/ebpf-server-dev
```

Debug builds include detailed logging of:
- eBPF event processing and data parsing
- Ring buffer operations and raw event data  
- Connection tracking and storage operations
- API request/response processing

### Logs

The server logs to stdout. Check for eBPF loading errors and HTTP server startup messages.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting: `make test lint`
5. Commit your changes
6. Push to your fork
7. Create a Pull Request

## Security Considerations

- This server requires root privileges to load eBPF programs
- eBPF programs run in kernel space and should be thoroughly tested
- Network monitoring may capture sensitive information
- Consider running in a containerized environment for isolation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Projects

- [Cilium eBPF Library](https://github.com/cilium/ebpf) - Go eBPF library used in this project
- [eBPF Documentation](https://ebpf.io/) - eBPF learning resources
- [BPFTrace](https://github.com/iovisor/bpftrace) - High-level tracing language for eBPF
- [Falco](https://falco.org/) - Cloud-native runtime security with eBPF

## Support

For questions and support:
- Create an issue on GitHub
- Check the troubleshooting section above
- Review eBPF and kernel documentation for system-specific issues
