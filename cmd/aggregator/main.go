package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/srodi/ebpf-server/internal/aggregator"
	"github.com/srodi/ebpf-server/pkg/logger"

	_ "github.com/srodi/ebpf-server/docs/swagger" // Import generated docs
	httpSwagger "github.com/swaggo/http-swagger"
)

func main() {
	// Parse command-line flags
	var (
		httpAddr = flag.String("addr", ":8081", "HTTP server address")
	)
	flag.Parse()

	logger.Info("Starting eBPF Event Aggregator...")

	// Create aggregator
	agg, err := aggregator.New(&aggregator.Config{
		HTTPAddr: *httpAddr,
	})
	if err != nil {
		logger.Fatalf("Failed to create aggregator: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start aggregator
	if err := agg.Start(ctx); err != nil {
		logger.Fatalf("Failed to start aggregator: %v", err)
	}

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Health endpoint
	mux.HandleFunc("/health", agg.HandleHealth)

	// Events API
	mux.HandleFunc("/api/events", agg.HandleEvents)
	mux.HandleFunc("/api/events/ingest", agg.HandleIngest)
	mux.HandleFunc("/api/stats", agg.HandleStats)

	// Swagger documentation
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:    *httpAddr,
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		logger.Infof("Starting HTTP server on %s", *httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down aggregator...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("HTTP server shutdown error: %v", err)
	}

	// Stop aggregator
	cancel()
	agg.Stop()

	logger.Info("Aggregator stopped")
}
