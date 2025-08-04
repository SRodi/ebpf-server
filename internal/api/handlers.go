package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/srodi/ebpf-server/internal/bpf"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ConnectionSummaryRequest defines the input parameters for the connection summary endpoint
type ConnectionSummaryRequest struct {
	PID         int    `json:"pid,omitempty"`
	Command     string `json:"command,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Seconds     int    `json:"duration"`
}

// ConnectionSummaryResponse defines the output structure for the connection summary endpoint
type ConnectionSummaryResponse struct {
	Total   int    `json:"total_attempts"`
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
	Seconds int    `json:"duration"`
	Message string `json:"message"`
}

// PacketDropSummaryRequest defines the input parameters for the packet drop summary endpoint
type PacketDropSummaryRequest struct {
	PID         int    `json:"pid,omitempty"`
	Command     string `json:"command,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Seconds     int    `json:"duration"`
}

// PacketDropSummaryResponse defines the output structure for the packet drop summary endpoint
type PacketDropSummaryResponse struct {
	Total   int    `json:"total_drops"`
	PID     int    `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
	Seconds int    `json:"duration"`
	Message string `json:"message"`
}

// ListConnectionsRequest defines the input parameters for the list connections endpoint
type ListConnectionsRequest struct {
	PID   *int `json:"pid,omitempty"`   // Optional: Filter connections for specific Process ID
	Limit *int `json:"limit,omitempty"` // Optional: Maximum connections to return per PID (default: 100, max: 1000)
}

// ListPacketDropsRequest defines the input parameters for the list packet drops endpoint
type ListPacketDropsRequest struct {
	PID   *int `json:"pid,omitempty"`   // Optional: Filter drops for specific Process ID
	Limit *int `json:"limit,omitempty"` // Optional: Maximum drops to return per PID (default: 100, max: 1000)
}

// ConnectionInfo represents connection event information
type ConnectionInfo struct {
	PID         uint32 `json:"pid"`
	Command     string `json:"command"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	ReturnCode  int32  `json:"return_code"`
	Timestamp   string `json:"timestamp"`
}

// PacketDropInfo represents packet drop event information
type PacketDropInfo struct {
	PID        uint32 `json:"pid"`
	Command    string `json:"command"`
	DropReason string `json:"drop_reason"`
	SkbLength  uint32 `json:"skb_length"`
	Timestamp  string `json:"timestamp"`
}

// ListConnectionsResponse defines the output format for the list connections endpoint
type ListConnectionsResponse struct {
	TotalPIDs   int                         `json:"total_pids"`
	Connections map[string][]ConnectionInfo `json:"connections"`
	Truncated   bool                        `json:"truncated"`
	Message     string                      `json:"message"`
}

// ListPacketDropsResponse defines the output format for the list packet drops endpoint
type ListPacketDropsResponse struct {
	TotalPIDs int                         `json:"total_pids"`
	Drops     map[string][]PacketDropInfo `json:"drops"`
	Truncated bool                        `json:"truncated"`
	Message   string                      `json:"message"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeJSONResponse writes a JSON response with the given status code
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Errorf("Failed to encode JSON response: %v", err)
	}
}

// writeErrorResponse writes an error response
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	writeJSONResponse(w, statusCode, ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
	})
}

// HandleConnectionSummary handles the /api/connection-summary endpoint
func HandleConnectionSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	var req ConnectionSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	// Handle compatibility between 'command' and 'process_name' fields
	command := req.Command
	if command == "" && req.ProcessName != "" {
		command = req.ProcessName
	}

	// Validate input
	if req.Seconds <= 0 {
		writeErrorResponse(w, http.StatusBadRequest, "duration must be positive")
		return
	}
	if req.Seconds > 3600 {
		writeErrorResponse(w, http.StatusBadRequest, "duration cannot exceed 3600 seconds")
		return
	}
	if req.PID != 0 && command != "" {
		writeErrorResponse(w, http.StatusBadRequest, "cannot specify both PID and command")
		return
	}
	if req.PID == 0 && command == "" {
		writeErrorResponse(w, http.StatusBadRequest, "must specify either PID or command")
		return
	}

	// Get connection summary data
	var total int
	var monitoredPID int
	var monitoredCommand string

	if command != "" {
		total = bpf.GetConnectionSummary(0, command, req.Seconds)
		monitoredCommand = command
		logger.Debugf("Connection summary for command '%s': %d attempts in %d seconds",
			command, total, req.Seconds)
	} else {
		total = bpf.GetConnectionSummary(uint32(req.PID), "", req.Seconds)
		monitoredPID = req.PID
		logger.Debugf("Connection summary for PID %d: %d attempts in %d seconds",
			req.PID, total, req.Seconds)
	}

	// Create human-readable message
	var message string
	if monitoredCommand != "" {
		message = fmt.Sprintf("Found %d connection attempts from command '%s' over %d seconds",
			total, monitoredCommand, req.Seconds)
	} else {
		message = fmt.Sprintf("Found %d connection attempts from PID %d over %d seconds",
			total, monitoredPID, req.Seconds)
	}

	response := ConnectionSummaryResponse{
		Total:   total,
		PID:     monitoredPID,
		Command: monitoredCommand,
		Seconds: req.Seconds,
		Message: message,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// HandlePacketDropSummary handles the /api/packet-drop-summary endpoint
func HandlePacketDropSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	var req PacketDropSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	// Handle compatibility between 'command' and 'process_name' fields
	command := req.Command
	if command == "" && req.ProcessName != "" {
		command = req.ProcessName
	}

	// Validate input
	if req.Seconds <= 0 {
		writeErrorResponse(w, http.StatusBadRequest, "duration must be positive")
		return
	}
	if req.Seconds > 3600 {
		writeErrorResponse(w, http.StatusBadRequest, "duration cannot exceed 3600 seconds")
		return
	}
	if req.PID != 0 && command != "" {
		writeErrorResponse(w, http.StatusBadRequest, "cannot specify both PID and command")
		return
	}
	if req.PID == 0 && command == "" {
		writeErrorResponse(w, http.StatusBadRequest, "must specify either PID or command")
		return
	}

	// Get packet drop summary data
	var total int
	var monitoredPID int
	var monitoredCommand string

	if command != "" {
		total = bpf.GetPacketDropSummary(0, command, req.Seconds)
		monitoredCommand = command
		logger.Debugf("Packet drop summary for command '%s': %d drops in %d seconds",
			command, total, req.Seconds)
	} else {
		total = bpf.GetPacketDropSummary(uint32(req.PID), "", req.Seconds)
		monitoredPID = req.PID
		logger.Debugf("Packet drop summary for PID %d: %d drops in %d seconds",
			req.PID, total, req.Seconds)
	}

	// Create human-readable message
	var message string
	if monitoredCommand != "" {
		message = fmt.Sprintf("Found %d packet drops from command '%s' over %d seconds",
			total, monitoredCommand, req.Seconds)
	} else {
		message = fmt.Sprintf("Found %d packet drops from PID %d over %d seconds",
			total, monitoredPID, req.Seconds)
	}

	response := PacketDropSummaryResponse{
		Total:   total,
		PID:     monitoredPID,
		Command: monitoredCommand,
		Seconds: req.Seconds,
		Message: message,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// HandleListConnections handles the /api/list-connections endpoint
func HandleListConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Handle GET request with query parameters
		handleListConnectionsGET(w, r)
	} else if r.Method == http.MethodPost {
		// Handle POST request with JSON body
		handleListConnectionsPOST(w, r)
	} else {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only GET and POST methods are allowed")
	}
}

func handleListConnectionsGET(w http.ResponseWriter, r *http.Request) {
	var req ListConnectionsRequest

	// Parse query parameters
	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "Invalid PID parameter")
			return
		} else {
			req.PID = &pid
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		} else {
			req.Limit = &limit
		}
	}

	processListConnectionsRequest(w, req)
}

func handleListConnectionsPOST(w http.ResponseWriter, r *http.Request) {
	var req ListConnectionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	processListConnectionsRequest(w, req)
}

func processListConnectionsRequest(w http.ResponseWriter, req ListConnectionsRequest) {
	// Validate input
	if req.Limit != nil && *req.Limit > 1000 {
		writeErrorResponse(w, http.StatusBadRequest, "limit cannot exceed 1000")
		return
	}

	limitValue := 100
	if req.Limit != nil {
		limitValue = *req.Limit
	}

	// Get all connections from the eBPF loader
	allConnections := bpf.GetAllConnections()

	result := struct {
		TotalPIDs   int
		Connections map[string][]ConnectionInfo
		Truncated   bool
	}{
		Connections: make(map[string][]ConnectionInfo),
		Truncated:   false,
	}

	pidCount := 0
	for connectionPID, events := range allConnections {
		// If PID filter is specified, skip non-matching PIDs
		if req.PID != nil && connectionPID != uint32(*req.PID) {
			continue
		}

		pidCount++
		var connections []ConnectionInfo
		pidStr := fmt.Sprintf("%d", connectionPID)

		// Limit connections per PID
		eventCount := 0
		for _, event := range events {
			if eventCount >= limitValue {
				result.Truncated = true
				break
			}

			connections = append(connections, ConnectionInfo{
				PID:         event.PID,
				Command:     event.GetCommand(),
				Destination: event.GetDestination(),
				Protocol:    event.GetProtocol(),
				ReturnCode:  event.Ret,
				Timestamp:   event.GetWallClockTime().Format("2006-01-02T15:04:05Z"),
			})
			eventCount++
		}

		if len(connections) > 0 {
			result.Connections[pidStr] = connections
		}
	}

	result.TotalPIDs = pidCount

	logger.Debugf("List connections result: %d PIDs", result.TotalPIDs)

	// Create human-readable message
	var message string
	if req.PID != nil {
		totalConns := 0
		for _, conns := range result.Connections {
			totalConns += len(conns)
		}
		message = fmt.Sprintf("Found %d connections for PID %d", totalConns, *req.PID)
	} else {
		totalConns := 0
		for _, conns := range result.Connections {
			totalConns += len(conns)
		}
		message = fmt.Sprintf("Found %d total connections across %d processes",
			totalConns, result.TotalPIDs)
		if result.Truncated {
			message += " (results truncated due to limit)"
		}
	}

	response := ListConnectionsResponse{
		TotalPIDs:   result.TotalPIDs,
		Connections: result.Connections,
		Truncated:   result.Truncated,
		Message:     message,
	}

	logger.Debugf("List connections result: %d PIDs, %s", response.TotalPIDs, response.Message)

	writeJSONResponse(w, http.StatusOK, response)
}

// HandleListPacketDrops handles the /api/list-packet-drops endpoint
func HandleListPacketDrops(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListPacketDropsGET(w, r)
	case http.MethodPost:
		handleListPacketDropsPOST(w, r)
	default:
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only GET and POST methods are allowed")
	}
}

// handleListPacketDropsGET processes GET requests for /api/list-packet-drops
func handleListPacketDropsGET(w http.ResponseWriter, r *http.Request) {
	var req ListPacketDropsRequest

	// Parse query parameters
	query := r.URL.Query()

	// Parse PID
	if pidStr := query.Get("pid"); pidStr != "" {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "Invalid PID parameter")
			return
		}
		req.PID = &pid
	}

	// Parse limit
	if limitStr := query.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		req.Limit = &limit
	}

	processListPacketDropsRequest(w, req)
}

// handleListPacketDropsPOST processes POST requests for /api/list-packet-drops
func handleListPacketDropsPOST(w http.ResponseWriter, r *http.Request) {
	var req ListPacketDropsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	processListPacketDropsRequest(w, req)
}

// processListPacketDropsRequest processes the actual packet drops listing logic
func processListPacketDropsRequest(w http.ResponseWriter, req ListPacketDropsRequest) {
	// Validate input
	if req.Limit != nil && *req.Limit > 1000 {
		writeErrorResponse(w, http.StatusBadRequest, "limit cannot exceed 1000")
		return
	}

	limitValue := 100
	if req.Limit != nil {
		limitValue = *req.Limit
	}

	// Get all packet drops from the eBPF loader
	allDrops := bpf.GetAllPacketDrops()

	result := struct {
		TotalPIDs int
		Drops     map[string][]PacketDropInfo
		Truncated bool
	}{
		Drops:     make(map[string][]PacketDropInfo),
		Truncated: false,
	}

	pidCount := 0
	for dropPID, events := range allDrops {
		// If PID filter is specified, skip non-matching PIDs
		if req.PID != nil && dropPID != uint32(*req.PID) {
			continue
		}

		pidCount++
		var drops []PacketDropInfo
		pidStr := fmt.Sprintf("%d", dropPID)

		eventCount := 0
		for _, event := range events {
			if eventCount >= limitValue {
				result.Truncated = true
				break
			}

			drops = append(drops, PacketDropInfo{
				PID:        event.PID,
				Command:    event.GetCommand(),
				DropReason: event.GetDropReasonString(),
				SkbLength:  event.SkbLen,
				Timestamp:  event.GetWallClockTime().Format("2006-01-02 15:04:05.000 MST"),
			})
			eventCount++
		}

		if len(drops) > 0 {
			result.Drops[pidStr] = drops
		}
	}

	result.TotalPIDs = pidCount

	// Create response message
	var message string
	if req.PID != nil {
		totalDropsForPID := len(result.Drops[fmt.Sprintf("%d", *req.PID)])
		message = fmt.Sprintf("Found %d packet drops for PID %d", totalDropsForPID, *req.PID)
	} else {
		totalDrops := 0
		for _, drops := range result.Drops {
			totalDrops += len(drops)
		}
		message = fmt.Sprintf("Found %d packet drops across %d processes", totalDrops, result.TotalPIDs)
	}

	if result.Truncated {
		message += " (results truncated)"
	}

	response := ListPacketDropsResponse{
		TotalPIDs: result.TotalPIDs,
		Drops:     result.Drops,
		Truncated: result.Truncated,
		Message:   message,
	}

	logger.Debugf("List packet drops result: %d PIDs, %s", response.TotalPIDs, response.Message)

	writeJSONResponse(w, http.StatusOK, response)
}

// HandleHealth provides a simple health check endpoint
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only GET method is allowed")
		return
	}

	health := map[string]string{
		"status":  "healthy",
		"service": "ebpf-server",
		"version": "v1.0.0",
	}

	writeJSONResponse(w, http.StatusOK, health)
}
