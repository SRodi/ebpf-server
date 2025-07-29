package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/srodi/mcp-ebpf/internal/bpf"
	"github.com/srodi/mcp-ebpf/internal/server"
	"github.com/srodi/mcp-ebpf/pkg/logger"
)

func main() {
	if err := bpf.LoadAndAttach(); err != nil {
		logger.Fatalf("failed to load eBPF: %v", err)
	}
	
	// Setup signal handling for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		logger.Info("Shutting down...")
		bpf.Cleanup()
		os.Exit(0)
	}()
	
	server.Start()
}
