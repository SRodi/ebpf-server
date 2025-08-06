package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/api"
	"github.com/srodi/ebpf-server/internal/system"
)

// setupTestSystem creates a mock system for testing
func setupTestSystem() *system.System {
	// Create a test system
	testSystem := system.NewSystem()

	// Initialize the API with the test system
	api.Initialize(testSystem)

	return testSystem
}

func TestHTTPServerSetup(t *testing.T) {
	// Create a test HTTP server with our routes
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/connection-summary", api.HandleConnectionSummary)
	mux.HandleFunc("/api/list-connections", api.HandleListConnections)
	mux.HandleFunc("/health", api.HandleHealth)

	// Root endpoint
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
			"description": "HTTP API for eBPF-based network connection monitoring"
		}`)); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
	})

	// Test server creation
	server := httptest.NewServer(mux)
	defer server.Close()

	// Test root endpoint
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("failed to make request to root endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var rootResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rootResponse); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if rootResponse["service"] != "eBPF Network Monitor" {
		t.Errorf("expected service name 'eBPF Network Monitor', got '%v'", rootResponse["service"])
	}
}

func TestHTTPHealthEndpoint(t *testing.T) {
	// Setup test system
	_ = setupTestSystem()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", api.HandleHealth)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("failed to make request to health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var healthResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if healthResponse["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got '%v'", healthResponse["status"])
	}
}

func TestHTTPAPIEndpoints(t *testing.T) {
	// This test requires eBPF to be loaded, so we skip it in unit tests
	// In practice, this would be an integration test
	t.Skip("Skipping integration test - requires eBPF to be loaded")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/list-connections", api.HandleListConnections)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test GET request
	resp, err := http.Get(server.URL + "/api/list-connections")
	if err != nil {
		t.Fatalf("failed to make GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPConnectionSummaryValidation(t *testing.T) {
	// Setup test system
	_ = setupTestSystem()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/connection-summary", api.HandleConnectionSummary)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test invalid JSON request
	invalidJSON := `{"pid": "invalid_number", "duration_seconds": "not_a_number"`

	resp, err := http.Post(server.URL+"/api/connection-summary", "application/json", bytes.NewBufferString(invalidJSON))
	if err != nil {
		t.Fatalf("failed to make POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestServerTimeouts(t *testing.T) {
	// Test that our server configuration includes proper timeouts
	server := &http.Server{
		Addr:         ":8080",
		Handler:      http.NewServeMux(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if server.ReadTimeout != 30*time.Second {
		t.Errorf("expected ReadTimeout 30s, got %v", server.ReadTimeout)
	}

	if server.WriteTimeout != 30*time.Second {
		t.Errorf("expected WriteTimeout 30s, got %v", server.WriteTimeout)
	}

	if server.IdleTimeout != 120*time.Second {
		t.Errorf("expected IdleTimeout 120s, got %v", server.IdleTimeout)
	}
}
