package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleMCPGetConnectionSummary(t *testing.T) {
	// Test request with PID
	reqBody := `{
		"method": "get_connection_summary",
		"params": {
			"pid": 1234,
			"duration": 60
		}
	}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	result, ok := response["result"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected result object in response")
	}

	if _, ok := result["total_attempts"]; !ok {
		t.Errorf("Expected total_attempts in result")
	}

	if _, ok := result["avg_latency_ms"]; !ok {
		t.Errorf("Expected avg_latency_ms in result")
	}
}

func TestHandleMCPGetConnectionSummaryByCommand(t *testing.T) {
	// Test request with command name
	reqBody := `{
		"method": "get_connection_summary",
		"params": {
			"command": "curl",
			"duration": 60
		}
	}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	result, ok := response["result"].(map[string]interface{})
	if !ok {
		t.Errorf("Expected result object in response")
	}

	if _, ok := result["total_attempts"]; !ok {
		t.Errorf("Expected total_attempts in result")
	}

	if _, ok := result["avg_latency_ms"]; !ok {
		t.Errorf("Expected avg_latency_ms in result")
	}
}

func TestHandleMCPListConnections(t *testing.T) {
	reqBody := `{
		"method": "list_connections",
		"params": {}
	}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if _, ok := response["result"]; !ok {
		t.Errorf("Expected result in response")
	}
}

func TestHandleMCPInvalidMethod(t *testing.T) {
	reqBody := `{
		"method": "invalid_method",
		"params": {}
	}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// The handler returns plain text error, not JSON
	body := w.Body.String()
	if !strings.Contains(body, "unknown method") {
		t.Errorf("Expected 'unknown method' in response, got: %s", body)
	}
}

func TestHandleMCPInvalidJSON(t *testing.T) {
	reqBody := `invalid json`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestHandleMCPInvalidParams(t *testing.T) {
	// Test with missing required fields
	reqBody := `{
		"method": "get_connection_summary",
		"params": {}
	}`

	req := httptest.NewRequest("POST", "/mcp", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HandleMCP(w, req)

	// Should still return 200 but with zero results since no PID or command specified
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
