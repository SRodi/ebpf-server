package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleHealth)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}
}

func TestHandleHealthWrongMethod(t *testing.T) {
	req, err := http.NewRequest("POST", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleHealth)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}

func TestHandleConnectionSummaryValidation(t *testing.T) {
	tests := []struct {
		name     string
		request  ConnectionSummaryRequest
		wantCode int
	}{
		{
			name: "valid request with PID",
			request: ConnectionSummaryRequest{
				PID:     1234,
				Seconds: 60,
			},
			wantCode: http.StatusOK,
		},
		{
			name: "valid request with command",
			request: ConnectionSummaryRequest{
				Command: "curl",
				Seconds: 30,
			},
			wantCode: http.StatusOK,
		},
		{
			name: "invalid duration - zero",
			request: ConnectionSummaryRequest{
				PID:     1234,
				Seconds: 0,
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "invalid duration - too long",
			request: ConnectionSummaryRequest{
				PID:     1234,
				Seconds: 4000,
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "both PID and command specified",
			request: ConnectionSummaryRequest{
				PID:     1234,
				Command: "curl",
				Seconds: 60,
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name: "neither PID nor command specified",
			request: ConnectionSummaryRequest{
				Seconds: 60,
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest("POST", "/api/connection-summary", bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(HandleConnectionSummary)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.wantCode)
			}
		})
	}
}

func TestHandleListConnectionsGET(t *testing.T) {
	req, err := http.NewRequest("GET", "/api/list-connections", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleListConnections)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	var response ListConnectionsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	// Should have a valid response structure
	if response.Connections == nil {
		t.Error("Expected connections map to be initialized")
	}
}

func TestHandleListConnectionsGETWithParams(t *testing.T) {
	req, err := http.NewRequest("GET", "/api/list-connections?pid=1234&limit=50", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleListConnections)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestHandleListConnectionsPOST(t *testing.T) {
	reqData := ListConnectionsRequest{
		Limit: func(i int) *int { return &i }(100),
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/api/list-connections", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleListConnections)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestHandleListConnectionsLimitValidation(t *testing.T) {
	reqData := ListConnectionsRequest{
		Limit: func(i int) *int { return &i }(1500), // Over the limit
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", "/api/list-connections", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HandleListConnections)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestWriteJSONResponse(t *testing.T) {
	testData := map[string]string{"test": "value"}

	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusOK, testData)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("writeJSONResponse returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("writeJSONResponse returned wrong content type: got %v want %v",
			contentType, "application/json")
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response["test"] != "value" {
		t.Errorf("Expected test=value, got test=%s", response["test"])
	}
}

func TestWriteErrorResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeErrorResponse(rr, http.StatusBadRequest, "test error message")

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("writeErrorResponse returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	var response ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if response.Message != "test error message" {
		t.Errorf("Expected message='test error message', got message='%s'", response.Message)
	}

	if response.Error != "Bad Request" {
		t.Errorf("Expected error='Bad Request', got error='%s'", response.Error)
	}
}
