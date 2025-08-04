# Setup Guide

## System Requirements

- Linux kernel 4.18+ with eBPF support
- Root privileges for eBPF program loading
- 64-bit architecture (x86_64 or arm64)

## Dependencies

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    golang-go \
    clang \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential
```

### RHEL/CentOS/Fedora

```bash
# RHEL/CentOS 8+
sudo dnf install -y \
    golang \
    clang \
    libbpf-devel \
    kernel-headers \
    kernel-devel

# Fedora
sudo dnf install -y \
    golang \
    clang \
    libbpf-devel \
    kernel-headers \
    kernel-devel
```

### Alpine Linux

```bash
sudo apk add --no-cache \
    go \
    clang \
    libbpf-dev \
    linux-headers \
    musl-dev
```

## Build from Source

```bash
# Clone repository
git clone https://github.com/srodi/ebpf-server.git
cd ebpf-server

# Build eBPF programs
make compile-bpf

# Build server
make build

# Run tests (optional)
make test
```

## Installation

### Production Build

```bash
make build
sudo cp bin/ebpf-server /usr/local/bin/
```

### Development Build

```bash
make build-dev
sudo cp bin/ebpf-server-dev /usr/local/bin/
```

## Running the Server

### Basic Usage

```bash
# Run with default settings
sudo ebpf-server

# Custom port
sudo PORT=9090 ebpf-server

# Debug mode
sudo LOG_LEVEL=debug ebpf-server-dev
```

### Systemd Service

Create `/etc/systemd/system/ebpf-server.service`:

```ini
[Unit]
Description=eBPF Network Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ebpf-server
Restart=always
RestartSec=5
Environment=PORT=8080
Environment=LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable ebpf-server
sudo systemctl start ebpf-server
```

## Docker

```bash
# Build image
docker build -t ebpf-server .

# Run container (privileged mode required for eBPF)
docker run --privileged -p 8080:8080 ebpf-server
```

## Verification

Test the installation:

```bash
# Health check
curl http://localhost:8080/health

# API documentation
curl http://localhost:8080/docs

# Connection monitoring
curl "http://localhost:8080/api/connections/summary?pid=1234&duration=60"
```

## Troubleshooting

### Common Issues

**eBPF not supported:**
```bash
# Check kernel version
uname -r
# Ensure kernel >= 4.18

# Check eBPF support
ls /sys/fs/bpf/
```

**Permission denied:**
```bash
# Ensure running as root
sudo ./bin/ebpf-server
```

**Missing dependencies:**
```bash
# Verify clang installation
clang --version

# Check libbpf
pkg-config --exists libbpf && echo "libbpf found"
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
sudo LOG_LEVEL=debug ./bin/ebpf-server-dev
```

Debug logs include:
- eBPF program loading details
- Kernel attachment points
- Event processing flow
- Ring buffer operations
- API request/response details
