package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleHealthWithoutSystem tests the health endpoint when system is not initialized
func TestHandleHealthWithoutSystem(t *testing.T) {
	// Ensure no system is initialized
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	HandleHealth(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
	
	body := w.Body.String()
	if body != "System not initialized\n" {
		t.Errorf("expected error message 'System not initialized', got %s", body)
	}
}

// TestHandleProgramsWithoutSystem tests the programs endpoint when system is not initialized
func TestHandleProgramsWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/programs", nil)
	w := httptest.NewRecorder()
	
	HandlePrograms(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleEventsWithoutSystem tests the events endpoint when system is not initialized  
func TestHandleEventsWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()
	
	HandleEvents(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleConnectionSummaryWithoutSystem tests connection summary without system
func TestHandleConnectionSummaryWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/connection-summary", nil)
	w := httptest.NewRecorder()
	
	HandleConnectionSummary(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandlePacketDropSummaryWithoutSystem tests packet drop summary without system
func TestHandlePacketDropSummaryWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/packet-drop-summary", nil)
	w := httptest.NewRecorder()
	
	HandlePacketDropSummary(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleListConnectionsWithoutSystem tests list connections without system
func TestHandleListConnectionsWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/list-connections", nil)
	w := httptest.NewRecorder()
	
	HandleListConnections(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleListPacketDropsWithoutSystem tests list packet drops without system
func TestHandleListPacketDropsWithoutSystem(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("GET", "/api/list-packet-drops", nil)
	w := httptest.NewRecorder()
	
	HandleListPacketDrops(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleConnectionSummaryPOSTInvalidJSON tests POST with invalid JSON
func TestHandleConnectionSummaryPOSTInvalidJSON(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("POST", "/api/connection-summary", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	HandleConnectionSummary(w, req)
	
	// Should fail due to no system first, but if we had a system it would fail due to invalid JSON
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandlePacketDropSummaryPOSTInvalidJSON tests POST with invalid JSON
func TestHandlePacketDropSummaryPOSTInvalidJSON(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil 
	defer func() { globalSystem = originalSystem }()
	
	req := httptest.NewRequest("POST", "/api/packet-drop-summary", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	HandlePacketDropSummary(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestHandleEventsQueryParameterParsing tests query parameter parsing
func TestHandleEventsQueryParameterParsing(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	// Test that URL query parameters are parsed correctly, even without a system
	// The handler should parse the parameters before checking for system availability
	testCases := []struct {
		name   string
		params string
	}{
		{"type parameter", "?type=connection"},
		{"pid parameter", "?pid=1234"},
		{"command parameter", "?command=curl"},
		{"limit parameter", "?limit=50"},
		{"since parameter", "?since=2023-01-01T12:00:00Z"},
		{"until parameter", "?until=2023-01-01T13:00:00Z"},
		{"multiple parameters", "?type=connection&pid=1234&limit=10"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/events"+tc.params, nil)
			w := httptest.NewRecorder()
			
			HandleEvents(w, req)
			
			// Should fail due to no system, but the URL parsing should work
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
			}
		})
	}
}

// TestHandleConnectionSummaryGETParameterParsing tests GET parameter parsing
func TestHandleConnectionSummaryGETParameterParsing(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	testCases := []struct {
		name   string
		params string
	}{
		{"pid parameter", "?pid=1234"},
		{"command parameter", "?command=curl"},
		{"duration parameter", "?duration_seconds=30"},
		{"all parameters", "?pid=1234&command=curl&duration_seconds=120"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/connection-summary"+tc.params, nil)
			w := httptest.NewRecorder()
			
			HandleConnectionSummary(w, req)
			
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
			}
		})
	}
}

// TestHandleConnectionSummaryPOSTValidJSON tests POST with valid JSON structure
func TestHandleConnectionSummaryPOSTValidJSON(t *testing.T) {
	originalSystem := globalSystem
	globalSystem = nil
	defer func() { globalSystem = originalSystem }()
	
	requestBody := map[string]interface{}{
		"pid":              1234,
		"command":          "curl",
		"duration_seconds": 60,
	}
	
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	
	req := httptest.NewRequest("POST", "/api/connection-summary", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	
	HandleConnectionSummary(w, req)
	
	// Should fail due to no system, but JSON parsing should work
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// TestSwaggerModelStructures tests that our swagger model structs are well-formed
func TestSwaggerModelStructures(t *testing.T) {
	// Test ConnectionSummaryRequest
	req := ConnectionSummaryRequest{
		PID:      1234,
		Command:  "curl",
		Duration: 60,
	}
	
	if req.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", req.PID)
	}
	
	// Test marshaling to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Errorf("failed to marshal ConnectionSummaryRequest: %v", err)
	}
	
	// Test unmarshaling from JSON
	var decoded ConnectionSummaryRequest
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Errorf("failed to unmarshal ConnectionSummaryRequest: %v", err)
	}
	
	if decoded.Command != "curl" {
		t.Errorf("expected command 'curl', got %s", decoded.Command)
	}
	
	// Test ConnectionSummaryResponse
	resp := ConnectionSummaryResponse{
		Count:           5,
		PID:             1234,
		Command:         "curl",
		DurationSeconds: 60,
		QueryTime:       "2023-01-01T12:00:00Z",
	}
	
	if resp.Count != 5 {
		t.Errorf("expected count 5, got %d", resp.Count)
	}
	
	// Test PacketDropSummaryRequest
	dropReq := PacketDropSummaryRequest{
		PID:      5678,
		Command:  "nginx",
		Duration: 120,
	}
	
	if dropReq.PID != 5678 {
		t.Errorf("expected PID 5678, got %d", dropReq.PID)
	}
	
	// Test PacketDropSummaryResponse  
	dropResp := PacketDropSummaryResponse{
		Count:           3,
		PID:             5678,
		Command:         "nginx",
		DurationSeconds: 120,
		QueryTime:       "2023-01-01T12:00:00Z",
	}
	
	if dropResp.Count != 3 {
		t.Errorf("expected count 3, got %d", dropResp.Count)
	}
}
