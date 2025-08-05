# Setup Guide

This guide covers the setup and installation of the eBPF Network Monitor server.

## Overview

The eBPF Network Monitor is a modular system that uses eBPF programs to monitor network connections and packet drops in real-time. It features:

- **Unified Event API**: Single `/api/events` endpoint for all monitoring data
- **Modular Architecture**: Clean separation between core interfaces, event system, and programs
- **Real-time Monitoring**: Live event streaming from kernel space
- **Interactive Documentation**: Built-in Swagger UI for API exploration

## Table of Contents

- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Server](#running-the-server)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Operating System
- **Linux kernel 4.18+** with eBPF support
- Supported distributions:
  - Ubuntu 18.04+
  - Debian 10+
  - CentOS 8+
  - RHEL 8+
  - Fedora 30+

### Hardware
- **x86_64** architecture (required for current eBPF programs)
- **Minimum 2GB RAM** (4GB+ recommended for production)
- **Root/sudo privileges** (required for eBPF program loading)

### Kernel Features
Verify your kernel supports the required eBPF features:

```bash
# Check kernel version
uname -r

# Verify eBPF support
zgrep CONFIG_BPF_SYSCALL /proc/config.gz
zgrep CONFIG_BPF_JIT /proc/config.gz

# Check if BTF is enabled (recommended)
zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
```

## Dependencies

### Build Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y \
    golang-go \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    git \
    make
```

#### CentOS/RHEL/Fedora
```bash
# CentOS 8/RHEL 8
sudo dnf install -y \
    golang \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    kernel-devel \
    make \
    git

# Fedora
sudo dnf install -y \
    golang \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    kernel-devel \
    make \
    git
```

### Go Version
- **Go 1.23+** is required
- Verify installation: `go version`

### Optional Dependencies

#### For development and testing
```bash
# Ubuntu/Debian
sudo apt install -y \
    bpftool \
    linux-tools-common \
    linux-tools-$(uname -r)

# CentOS/RHEL/Fedora
sudo dnf install -y bpftool
```

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/srodi/ebpf-server.git
cd ebpf-server
```

### 2. Build eBPF Programs
```bash
# Compile eBPF bytecode
make build-bpf
```

### 3. Build Go Server
```bash
# Build production binary
make build

# Or build development binary with debug logging
make build-dev
```

### 4. Verify Build
```bash
ls -la bin/
# Should show ebpf-server binary
```

## Configuration

### Command-Line Options

The server supports these command-line options:

```bash
# Start server on custom address/port
./bin/ebpf-server -addr=":9090"

# Default is :8080
./bin/ebpf-server
```

### Environment Variables

Configure logging and debugging:

```bash
# Logging configuration (handled by logger package)
export EBPF_LOG_LEVEL=debug     # debug, info, warn, error (default: info)

# For development debugging
export EBPF_DEBUG=1             # Enable debug mode
```

### Configuration File (Future Enhancement)

The current version uses command-line configuration. Future versions may support:

```yaml
# config.yaml (not yet implemented)
server:
  host: "0.0.0.0"
  port: 8080
  
logging:
  level: "info"
  format: "json"
```

## Running the Server

### Development Mode
```bash
# Run with debug logging
sudo ./bin/ebpf-server-dev

# Run on custom port
sudo ./bin/ebpf-server-dev -addr=":9090"
```

### Production Mode
```bash
# Run production server (default port 8080)
sudo ./bin/ebpf-server

# Run on custom address/port
sudo ./bin/ebpf-server -addr="0.0.0.0:8080"
```

### Background Service
```bash
# Run as background service
sudo nohup ./bin/ebpf-server > /var/log/ebpf-server.log 2>&1 &
```

### Docker (If Available)
```bash
# Build Docker image
docker build -t ebpf-server .

# Run with required privileges
docker run --privileged \
  -p 8080:8080 \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /proc:/host/proc:ro \
  ebpf-server
```

### Systemd Service

Create `/etc/systemd/system/ebpf-server.service`:

```ini
[Unit]
Description=eBPF Network Monitor Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ebpf-server -addr=":8080"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=EBPF_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Install and start service
sudo cp bin/ebpf-server /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable ebpf-server
sudo systemctl start ebpf-server
```

## Verification

### 1. Check Server Status
```bash
# Check if server is running
curl http://localhost:8080/health

# Expected response:
# {"service":"ebpf-server","status":"healthy","version":"v1.0.0"}
```

### 2. Verify eBPF Programs
```bash
# List active programs
curl http://localhost:8080/api/programs

# Check eBPF programs in kernel
sudo bpftool prog list | grep ebpf-server
```

### 3. Test API Endpoints
```bash
# Test unified events API
curl "http://localhost:8080/api/events?limit=10"

# Test connection events specifically
curl "http://localhost:8080/api/events?type=connection&limit=5"

# Test packet drop events specifically  
curl "http://localhost:8080/api/events?type=packet_drop&limit=5"

# Test events with time filter
curl "http://localhost:8080/api/events?since=2023-01-01T00:00:00Z&limit=10"

# Test events for specific process
curl "http://localhost:8080/api/events?pid=1234&limit=10"
```

### 4. View Documentation
```bash
# Open Swagger documentation in browser
xdg-open http://localhost:8080/docs/

# View available endpoints
curl http://localhost:8080/

# Access Swagger JSON directly
curl http://localhost:8080/docs/swagger.json
```

### 5. Available API Endpoints

The server provides these endpoints:

**Core Unified APIs (Recommended):**
- `GET /api/events` - Query all events with filtering
- `GET /api/programs` - List eBPF program status
- `GET /health` - Health check

**Legacy Specific APIs:**
- `POST /api/connection-summary` - Connection statistics
- `POST /api/packet-drop-summary` - Packet drop statistics  
- `GET /api/list-connections` - List connection events
- `GET /api/list-packet-drops` - List packet drop events

**Documentation:**
- `GET /docs/` - Interactive Swagger UI
- `GET /` - API overview and endpoint list

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Error: permission denied loading eBPF program
# Solution: Run with sudo/root privileges
sudo ./bin/ebpf-server
```

#### Missing Kernel Headers
```bash
# Error: cannot find kernel headers
# Solution: Install kernel headers for your kernel version
sudo apt install linux-headers-$(uname -r)  # Ubuntu/Debian
sudo dnf install kernel-devel kernel-headers  # CentOS/RHEL/Fedora
```

#### eBPF Verifier Errors
```bash
# Check kernel logs for eBPF verifier errors
sudo dmesg | grep bpf

# Common solutions:
# 1. Update to newer kernel version
# 2. Check eBPF program complexity
# 3. Verify struct alignment
```

#### Port Already in Use
```bash
# Error: address already in use
# Solution: Change port using command-line flag or kill existing process
sudo ./bin/ebpf-server -addr=":8081"
# Or
sudo lsof -i :8080
sudo kill <PID>
```

#### No Events Appearing
```bash
# Check if eBPF programs are loaded and attached
sudo bpftool prog list | grep -E "(connection|packet_drop)"
sudo bpftool link list

# Check program status via API
curl http://localhost:8080/api/programs

# Check specific tracepoints exist
sudo ls /sys/kernel/debug/tracing/events/syscalls/ | grep sys_enter_connect
sudo ls /sys/kernel/debug/tracing/events/skb/ | grep kfree_skb

# Generate some test traffic
ping google.com &
curl http://google.com
killall ping

# Check for events
curl "http://localhost:8080/api/events?limit=5"

# Enable more verbose logging  
export EBPF_DEBUG=1
sudo -E ./bin/ebpf-server-dev
```

### Debugging Tools

#### eBPF Debugging
```bash
# List loaded eBPF programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <ID>

# List eBPF maps
sudo bpftool map list

# View map contents
sudo bpftool map dump id <MAP_ID>
```

#### Network Tracing
```bash
# View kernel trace events
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Enable specific tracepoints
echo 1 | sudo tee /sys/kernel/debug/tracing/events/net/net_dev_queue/enable
```

#### System Monitoring
```bash
# Monitor system resources
htop
iostat 1
netstat -tlnp | grep 8080

# Check system logs
journalctl -u ebpf-server -f
```

### Performance Tuning

#### Event Buffer Management
```bash
# Monitor event processing performance
curl "http://localhost:8080/api/programs" | jq '.programs[] | {name, event_count}'

# Check for dropped events in system logs
journalctl -u ebpf-server | grep -i "dropped\|full\|overflow"
```

#### System Resource Optimization
```bash
# Pin server to specific CPUs for consistent performance
taskset -c 0,1 ./bin/ebpf-server

# Set memory limits for production
ulimit -m 1048576  # 1GB limit

# Increase ring buffer size if experiencing drops (future enhancement)
# Currently ring buffer size is compiled into eBPF programs
```

#### API Performance
```bash
# Use specific filters to reduce data transfer
curl "http://localhost:8080/api/events?type=connection&limit=100"

# Use time-based filtering for better performance
curl "http://localhost:8080/api/events?since=$(date -d '1 hour ago' -Iseconds)"
```

### Log Analysis

#### Enable Debug Logging
```bash
export EBPF_LOG_LEVEL=debug
sudo ./bin/ebpf-server-dev 2>&1 | tee debug.log
```

#### Common Log Messages
- `"eBPF program loaded successfully"` - Program loaded correctly
- `"Failed to attach eBPF program"` - Attachment failed, check permissions
- `"Ring buffer event received"` - Events are being processed
- `"Event channel full"` - Consider increasing buffer sizes

### Getting Help

1. **Check logs**: Review server logs for error messages
2. **Verify system**: Ensure all dependencies are installed
3. **Test incrementally**: Start with basic functionality
4. **Check documentation**: Review API documentation at `/docs`
5. **Community support**: Report issues on GitHub

For additional support, please check:
- [Program Development Guide](program-development.md)
- [GitHub Issues](https://github.com/srodi/ebpf-server/issues)
- [API Documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/srodi/ebpf-server/main/docs/swagger/swagger.json)
