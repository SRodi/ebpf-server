# mcp-ebpf

A Model Context Protocol (MCP) server that uses eBPF to monitor network connections and provide real-time network analytics.

## Overview

This project implements an MCP server that leverages eBPF (Extended Berkeley Packet Filter) technology to monitor network connections at the kernel level. It provides APIs to retrieve connection statistics and network metrics through a simple HTTP interface.

## Features

- **eBPF-based Network Monitoring**: Efficient kernel-level network connection tracking
- **MCP Protocol Support**: Compatible with Model Context Protocol for AI tool integration
- **Real-time Analytics**: Live network connection statistics and metrics
- **Low Overhead**: Minimal performance impact using eBPF technology
- **HTTP API**: Simple REST-like interface for querying network data

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Client   │───▶│   MCP Server    │───▶│  eBPF Programs  │
│                 │    │   (Port 8080)   │    │   (Kernel)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

The server consists of:
- **eBPF Programs** (`bpf/`): Kernel-space programs for network monitoring
- **MCP Handler** (`internal/mcp/`): Protocol implementation and API endpoints
- **eBPF Loader** (`internal/bpf/`): Go bindings for eBPF program management
- **HTTP Server** (`internal/server/`): Web server handling client requests

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
   git clone https://github.com/srodi/mcp-ebpf.git
   cd mcp-ebpf
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
   make run
   ```

The server will start on port 8080 and begin monitoring network connections.

## Usage

### API Endpoints

The server exposes the following MCP-compatible endpoint:

**POST /mcp**

#### get_connection_summary

Get connection statistics for a specific process over a time period. You can query by either PID or command name.

Request format (by PID):
```json
{
  "method": "get_connection_summary",
  "params": {
    "pid": 1234,
    "duration": 60
  }
}
```

Request format (by command name - better for short-lived processes):
```json
{
  "method": "get_connection_summary",
  "params": {
    "command": "curl",
    "duration": 60
  }
}
```

Response format:
```json
{
  "result": {
    "total_attempts": 15,
    "avg_latency_ms": 23.4
  }
}
```

#### list_connections

List all tracked connection events (useful for debugging).

Request format:
```json
{
  "method": "list_connections",
  "params": {}
}
```

Response format:
```json
{
  "result": {
    "1234": [
      {
        "pid": 1234,
        "timestamp_ns": 1674123456789000000,
        "return_code": 0,
        "command": "curl",
        "destination_ip": "93.184.216.34",
        "destination_port": 80,
        "destination": "93.184.216.34:80",
        "address_family": 2,
        "protocol": "TCP",
        "socket_type": "STREAM",
        "wall_time": "2025-07-29T14:30:56Z",
        "note": "timestamp_ns is nanoseconds since boot, wall_time is converted to UTC"
      }
    ]
  }
}
```

### Example Usage

```bash
# First, start the server (requires root privileges)
sudo make run

# Method 1: Query by command name (easier for short-lived processes)
# Generate some curl connections
for i in {1..5}; do
  curl -s http://httpbin.org/ip > /dev/null
  sleep 1
done

# Query all curl connections from the last 60 seconds
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "get_connection_summary",
    "params": {
      "command": "curl",
      "duration": 60
    }
  }' | jq .

# Method 2: Query by PID (for long-running processes)
# Start a long-running connection
curl -s http://httpbin.org/delay/10 > /dev/null &
CURL_PID=$!
echo "curl PID: $CURL_PID"

# Query immediately while process is running
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d "{
    \"method\": \"get_connection_summary\",
    \"params\": {
      \"pid\": $CURL_PID,
      \"duration\": 60
    }
  }" | jq .

# Method 3: Monitor a specific service (most practical use case)
# Example: Monitor SSH connections
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "get_connection_summary",
    "params": {
      "command": "ssh",
      "duration": 3600
    }
  }' | jq .

# List all tracked connections for debugging
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "list_connections",
    "params": {}
  }' | jq .
```

**Note:** 
- The tool is most useful for monitoring **persistent services** (ssh, databases, web servers) or **analyzing historical connection patterns**
- For short-lived processes like individual curl commands, use the **command name** instead of PID
- Current eBPF program monitors TCP `connect()` syscalls only (not ICMP like ping)

## Protocol Detection and Testing

The MCP server includes enhanced protocol detection that identifies connection types and provides detailed network information:

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
# Start the MCP server
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

# Check captured connections
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"list_connections","params":{}}' | jq '.result | to_entries[-1:]'
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
# Run all tests
make test

# Run tests with race detection
make test-race
```

**Test Coverage:**
- **Logger Package**: Debug level functionality, global logger behavior, level switching
- **BPF Types**: Event parsing, IP conversion, protocol/socket type detection, time conversion
- **MCP Handler**: API endpoints, request/response handling, error cases, invalid input
- **HTTP Server**: Route handling, timeouts, integration testing

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
│   ├── bpf/               # eBPF program loader and utilities
│   │   ├── loader.go      # eBPF program loading logic
│   │   ├── types.go       # eBPF data structures
│   │   └── types_test.go  # BPF types unit tests
│   ├── mcp/               # MCP protocol implementation
│   │   ├── handler.go     # HTTP request handlers
│   │   ├── handler_test.go # MCP handler unit tests
│   │   └── schema.go      # Request/response schemas
│   └── server/
│       ├── server.go      # HTTP server setup
│       └── server_test.go # Server unit tests
├── pkg/
│   └── logger/            # Custom logging package
│       ├── logger.go      # Logger implementation
│       └── logger_test.go # Logger unit tests
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── Makefile              # Build automation
└── README.md             # This file
```

## Docker Support

### Build Docker Image

```bash
make docker-build
```

### Run in Docker

```bash
make docker-run
```

Note: Running eBPF programs in Docker requires privileged mode and may have limitations depending on the host kernel.

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
sudo ./bin/mcp-server-dev
```

Debug builds include detailed logging of:
- eBPF event processing and data parsing
- Ring buffer operations and raw event data  
- Connection tracking and storage operations
- API request/response processing

### Logs

The server logs to stdout. Check for eBPF loading errors and HTTP server status.

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
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol specification
- [eBPF Documentation](https://ebpf.io/) - eBPF learning resources

## Support

For questions and support:
- Create an issue on GitHub
- Check the troubleshooting section above
- Review eBPF and kernel documentation for system-specific issues
