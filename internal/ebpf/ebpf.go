// Package ebpf provides a simple interface for initializing and managing the eBPF monitoring system.
// This package is the main entry point for applications using the eBPF monitoring system.
package ebpf

import (
	"context"
	"fmt"

	"github.com/srodi/ebpf-server/internal/api"
	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// globalSystem holds the system instance
var globalSystem *system.System

// Initialize sets up the eBPF monitoring system.
func Initialize() error {
	logger.Info("Initializing eBPF monitoring system")
	
	globalSystem = system.NewSystem()
	
	if err := globalSystem.Initialize(); err != nil {
		return err
	}
	
	// Initialize API handlers with the system
	api.Initialize(globalSystem)
	
	logger.Info("eBPF monitoring system initialized successfully")
	return nil
}

// Start loads and attaches all eBPF programs.
func Start() error {
	if globalSystem == nil {
		return fmt.Errorf("system not initialized, call Initialize() first")
	}
	
	ctx := context.Background()
	return globalSystem.Start(ctx)
}

// Stop detaches all eBPF programs and cleans up resources.
func Stop() error {
	if globalSystem == nil {
		return nil
	}
	
	ctx := context.Background()
	return globalSystem.Stop(ctx)
}

// IsRunning returns true if the eBPF monitoring system is active.
func IsRunning() bool {
	if globalSystem == nil {
		return false
	}
	
	return globalSystem.IsRunning()
}
