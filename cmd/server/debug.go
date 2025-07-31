//go:build debug
// +build debug

package main

import "github.com/srodi/ebpf-server/pkg/logger"

func init() {
	// Enable debug logging when built with debug tag
	logger.SetDebug()
}
