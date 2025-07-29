//go:build debug
// +build debug

package main

import "github.com/srodi/mcp-ebpf/pkg/logger"

func init() {
	// Enable debug logging when built with debug tag
	logger.SetDebug()
}
