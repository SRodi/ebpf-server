// Package api provides HTTP handlers for the eBPF monitoring server
//
// @title eBPF Network Monitor API
// @version 1.0
// @description A modular HTTP API server that uses eBPF to monitor network connections with an extensible plugin architecture.
// @description
// @description ## Features
// @description - **Plugin-style eBPF Programs**: Independent, hot-swappable monitoring modules
// @description - **Event Storage**: Unified event collection and querying across all programs
// @description - **Manager-based Lifecycle**: Centralized program registration and management
// @description - **Auto-generated Documentation**: This documentation is generated from code annotations
// @description
// @description ## Adding New Programs
// @description New eBPF monitoring programs can be added by implementing the `BPFProgram` interface.
// @description See the [Program Development Guide](https://github.com/srodi/ebpf-server/blob/main/docs/program-development.md) for detailed instructions.
// @description
// @description ## Authentication
// @description This API currently does not require authentication. Consider adding authentication for production deployments.
//
// @contact.name API Support
// @contact.url https://github.com/srodi/ebpf-server/issues
// @contact.email support@example.com
//
// @license.name MIT
// @license.url https://github.com/srodi/ebpf-server/blob/main/LICENSE
//
// @host localhost:8080
// @BasePath /
//
// @tag.name health
// @tag.description Health check and system status endpoints
//
// @tag.name connections
// @tag.description Network connection monitoring endpoints
//
// @tag.name packet_drops
// @tag.description Packet drop monitoring endpoints
//
// @tag.name programs
// @tag.description eBPF program management and information endpoints
//
// @tag.name events
// @tag.description Event querying and retrieval endpoints
package api
