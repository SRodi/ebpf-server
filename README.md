# eBPF Network Monitor

An HTTP API server that uses eBPF to monitor network connections and provide real-time network analytics.

## Overview

This project implements an HTTP API server that leverages eBPF (Extended Berkeley Packet Filter) technology to monitor network connections at the kernel level. It provides **RESTful endpoints** to retrieve connection statistics and network metrics, making it easy to integrate with monitoring systems, dashboards, and automation tools.

## Features

- **eBPF-based Network Monitoring**: Efficient kernel-level network connection tracking
- **REST API**: Simple HTTP endpoints for easy integration
- **Real-time Analytics**: Live network connection statistics and metrics  
- **Low Overhead**: Minimal performance impact using eBPF technology
- **JSON Responses**: Structured data with human-readable messages
- **Protocol Detection**: Intelligent identification of TCP/UDP protocols by port

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Client   │───▶│ HTTP API Server │───▶│  eBPF Programs  │
│ (curl, apps,    │    │     (REST)      │    │   (Kernel)      │
│  monitoring)    │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

The server consists of:
- **eBPF Programs** (`bpf/`): Kernel-space programs for network monitoring
- **HTTP API** (`internal/api/`): RESTful endpoints for connection analysis
- **eBPF Loader** (`internal/bpf/`): Go bindings for eBPF program management
- **HTTP Server** (`cmd/server/`): Main server with routing and middleware

## Prerequisites

### System Requirements
- Linux kernel 4.18+ (for eBPF support)
- Root privileges (required for eBPF programs)

### Development Dependencies
- Go 1.23.0 or later
- Clang (for compiling eBPF programs)
- libbpf development headers

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y golang-go clang libbpf-dev linux-headers-$(uname -r)
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

## Usage

### HTTP API Endpoints

The server provides a REST API on port 8080 (default) with the following endpoints:

#### GET /health

Health check endpoint to verify the server is running.

**Response:**
```json
{
  "status": "healthy",
  "service": "ebpf-server",
  "version": "v1.0.0"
}
```

#### POST /api/connection-summary

Get connection attempt statistics for a specific process over a time period.

**Important**: This endpoint captures `connect()` syscall attempts, not actual network latency. It counts how many times a process attempted to establish connections.

**Request Body:**
```json
{
  "pid": 1234,              // Process ID (optional, use either pid OR command)
  "command": "curl",        // Command name (optional, use either pid OR command)
  "duration": 60            // Duration in seconds (1-3600, required)
}
```

**Response:**
```json
{
  "total_attempts": 5,
  "pid": 1234,
  "command": "",
  "duration": 60,
  "message": "Found 5 connection attempts from PID 1234 over 60 seconds"
}
```

#### GET /api/list-connections

List all tracked connection events with optional query parameters.

**Query Parameters:**
- `pid` (integer, optional): Filter connections for specific Process ID
- `limit` (integer, optional): Maximum connections to return per PID (default: 100, max: 1000)

**Example:**
```bash
curl "http://localhost:8080/api/list-connections?pid=1234&limit=50"
```

#### POST /api/list-connections

List all tracked connection events with JSON request body (alternative to GET).

**Request Body:**
```json
{
  "pid": 1234,    // Optional: Filter by PID
  "limit": 100    // Optional: Limit results per PID
}
```

**Response (both GET and POST):**
```json
{
  "total_pids": 3,
  "connections": {
    "1234": [
      {
        "pid": 1234,
        "command": "curl",
        "destination": "93.184.216.34:80",
        "protocol": "TCP",
        "return_code": 0,
        "timestamp": "2025-07-31T14:30:56Z"
      }
    ]
  },
  "truncated": false,
  "message": "Found 1 total connections across 1 processes"
}
```

#### GET /

Service information and API documentation.

**Response:**
```json
{
  "service": "eBPF Network Monitor",
  "version": "v1.0.0",
  "description": "HTTP API for eBPF-based network connection monitoring",
  "endpoints": {
    "POST /api/connection-summary": "Get connection summary for a process",
    "GET|POST /api/list-connections": "List network connections",
    "GET /health": "Service health check"
  }
}
```

### Example Usage

**Start the server:**
```bash
# Build and run (requires root for eBPF)
sudo make run

# Or run directly
sudo ./bin/ebpf-server -addr :8080
```

**Test the API:**
```bash
# Check health
curl http://localhost:8080/health

# Get connection summary for a specific command
curl -X POST http://localhost:8080/api/connection-summary \
  -H "Content-Type: application/json" \
  -d '{
    "command": "curl",
    "duration": 30
  }'

# List all connections
curl http://localhost:8080/api/list-connections

# List connections for specific PID with limit
curl "http://localhost:8080/api/list-connections?pid=1234&limit=10"
```

**Integration with monitoring tools:**
```bash
# Use with Prometheus/monitoring
curl -s http://localhost:8080/api/connection-summary \
  -d '{"command":"nginx","duration":60}' | jq '.total_attempts'

# Use with scripts
CONNECTIONS=$(curl -s http://localhost:8080/api/list-connections | jq '.total_pids')
echo "Currently tracking $CONNECTIONS processes"
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
├── bpf/                    # eBPF programs (C)
│   └── connection.c        # Connection monitoring eBPF program
├── cmd/
│   └── server/
│       ├── main.go        # Application entry point
│       └── debug.go       # Debug build configuration
├── internal/
│   ├── api/               # HTTP API handlers and routes
│   │   ├── handlers.go    # HTTP request handlers
│   │   └── handlers_test.go # API handler unit tests
│   └── bpf/               # eBPF program loader and utilities
│       ├── loader.go      # eBPF program loading logic
│       ├── types.go       # eBPF data structures
│       └── types_test.go  # BPF types unit tests
├── pkg/
│   └── logger/            # Custom logging package
│       ├── logger.go      # Logger implementation
│       └── logger_test.go # Logger unit tests
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── Makefile              # Build automation
└── README.md             # This file
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
