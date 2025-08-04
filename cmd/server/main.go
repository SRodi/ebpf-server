package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/srodi/ebpf-server/internal/api"
	"github.com/srodi/ebpf-server/internal/bpf"
	"github.com/srodi/ebpf-server/pkg/logger"
	
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/srodi/ebpf-server/docs/swagger" // Import generated docs
)

func main() {
	// Parse command-line flags
	var (
		httpAddr = flag.String("addr", ":8080", "HTTP server address")
	)
	flag.Parse()

	// Load and attach eBPF programs
	if err := bpf.LoadAndAttach(); err != nil {
		logger.Fatalf("failed to load eBPF: %v", err)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logger.Info("Shutting down...")
		bpf.Cleanup()
		cancel()
	}()

	// Setup HTTP routes
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/connection-summary", api.HandleConnectionSummary)
	mux.HandleFunc("/api/packet-drop-summary", api.HandlePacketDropSummary)
	mux.HandleFunc("/api/list-connections", api.HandleListConnections)
	mux.HandleFunc("/api/list-packet-drops", api.HandleListPacketDrops)
	mux.HandleFunc("/health", api.HandleHealth)
	
	// New auto-generated API endpoints
	mux.HandleFunc("/api/programs", api.HandlePrograms)
	mux.HandleFunc("/api/events", api.HandleEvents)
	
	// Swagger documentation
	mux.HandleFunc("/docs/", httpSwagger.WrapHandler)

	// Root endpoint with service information
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{
			"service": "eBPF Network Monitor",
			"version": "v1.0.0",
			"description": "HTTP API for eBPF-based network connection and packet drop monitoring",
			"endpoints": {
				"POST /api/connection-summary": "Get connection summary for a process",
				"POST /api/packet-drop-summary": "Get packet drop summary for a process",
				"GET|POST /api/list-connections": "List network connections",
				"GET|POST /api/list-packet-drops": "List packet drops",
				"GET /api/programs": "List active eBPF programs",
				"GET /api/events": "Get filtered events",
				"GET /health": "Service health check"
			},
			"documentation": {
				"api": "/docs/",
				"swagger_json": "/docs/swagger.json",
				"swagger_yaml": "/docs/swagger.yaml"
			}
		}`)); err != nil {
			logger.Error("Failed to write health response", "error", err)
		}
	})

	logger.Infof("Starting eBPF Network Monitor HTTP API on %s...", *httpAddr)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         *httpAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Wait for context cancellation (shutdown signal)
	<-ctx.Done()

	// Graceful shutdown of HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("HTTP server shutdown error: %v", err)
	}

	logger.Info("Server shutdown complete")
}
