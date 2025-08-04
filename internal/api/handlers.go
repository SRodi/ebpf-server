package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/srodi/ebpf-server/internal/bpf"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ConnectionSummaryRequest defines the input parameters for the connection summary endpoint
type ConnectionSummaryRequest struct {
	PID         int    `json:"pid,omitempty" example:"1234"`
	Command     string `json:"command,omitempty" example:"curl"`
	ProcessName string `json:"process_name,omitempty" example:"curl"`
	Seconds     int    `json:"duration" example:"60"`
}

// ConnectionSummaryResponse defines the output structure for the connection summary endpoint
type ConnectionSummaryResponse struct {
	Total   int    `json:"total_attempts" example:"42"`
	PID     int    `json:"pid,omitempty" example:"1234"`
	Command string `json:"command,omitempty" example:"curl"`
	Seconds int    `json:"duration" example:"60"`
	Message string `json:"message" example:"Found 42 connection attempts in the last 60 seconds"`
}

// PacketDropSummaryRequest defines the input parameters for the packet drop summary endpoint
type PacketDropSummaryRequest struct {
	PID         int    `json:"pid,omitempty" example:"1234"`
	Command     string `json:"command,omitempty" example:"curl"`
	ProcessName string `json:"process_name,omitempty" example:"curl"`
	Seconds     int    `json:"duration" example:"60"`
}

// PacketDropSummaryResponse defines the output structure for the packet drop summary endpoint
type PacketDropSummaryResponse struct {
	Total   int    `json:"total_drops" example:"15"`
	PID     int    `json:"pid,omitempty" example:"1234"`
	Command string `json:"command,omitempty" example:"curl"`
	Seconds int    `json:"duration" example:"60"`
	Message string `json:"message" example:"Found 15 packet drops from command 'curl' over 60 seconds"`
}

// ListConnectionsRequest defines the input parameters for the list connections endpoint
type ListConnectionsRequest struct {
	PID   *int `json:"pid,omitempty" example:"1234"`   // Optional: Filter connections for specific Process ID
	Limit *int `json:"limit,omitempty" example:"100"` // Optional: Maximum connections to return per PID (default: 100, max: 1000)
}

// ListPacketDropsRequest defines the input parameters for the list packet drops endpoint
type ListPacketDropsRequest struct {
	PID   *int `json:"pid,omitempty" example:"1234"`   // Optional: Filter drops for specific Process ID
	Limit *int `json:"limit,omitempty" example:"100"` // Optional: Maximum drops to return per PID (default: 100, max: 1000)
}

// ConnectionInfo represents connection event information
type ConnectionInfo struct {
	PID         uint32 `json:"pid" example:"1234"`
	Command     string `json:"command" example:"curl"`
	Destination string `json:"destination" example:"192.168.1.100:80"`
	Protocol    string `json:"protocol" example:"TCP"`
	ReturnCode  int32  `json:"return_code" example:"0"`
	Timestamp   string `json:"timestamp" example:"2023-08-04T10:15:30Z"`
}

// PacketDropInfo represents packet drop event information
type PacketDropInfo struct {
	PID        uint32 `json:"pid" example:"1234"`
	Command    string `json:"command" example:"curl"`
	DropReason string `json:"drop_reason" example:"SKB_FREE"`
	SkbLength  uint32 `json:"skb_length" example:"1500"`
	Timestamp  string `json:"timestamp" example:"2023-08-04 10:15:30.123 UTC"`
}

// ListConnectionsResponse defines the output format for the list connections endpoint
type ListConnectionsResponse struct {
	TotalPIDs   int                         `json:"total_pids" example:"2"`
	Connections map[string][]ConnectionInfo `json:"connections"`
	Truncated   bool                        `json:"truncated" example:"false"`
	Message     string                      `json:"message" example:"Found 15 total connections across 2 processes"`
}

// ListPacketDropsResponse defines the output format for the list packet drops endpoint
type ListPacketDropsResponse struct {
	TotalPIDs int                         `json:"total_pids" example:"3"`
	Drops     map[string][]PacketDropInfo `json:"drops"`
	Truncated bool                        `json:"truncated" example:"false"`
	Message   string                      `json:"message" example:"Found 25 packet drops across 3 processes"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error" example:"Bad Request"`
	Message string `json:"message" example:"Invalid parameter value"`
}

// ProgramInfo represents eBPF program information
type ProgramInfo struct {
	Name        string `json:"name" example:"connection"`
	Description string `json:"description" example:"Monitors network connection attempts"`
	Running     bool   `json:"running" example:"true"`
	EventCount  int    `json:"event_count" example:"1234"`
}

// ProgramsResponse represents the programs list response
type ProgramsResponse struct {
	Programs []ProgramInfo `json:"programs"`
	Total    int           `json:"total" example:"2"`
	Message  string        `json:"message" example:"2 eBPF programs currently active"`
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
// @Summary Get connection event statistics
// @Description Returns the count of connection events within a specified time window, filtered by PID or command
// @Tags connections
// @Accept json
// @Produce json
// @Param request body ConnectionSummaryRequest true "Connection summary request"
// @Success 200 {object} ConnectionSummaryResponse
// @Failure 400 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/connection-summary [post]
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
// @Summary Get packet drop event statistics
// @Description Returns the count of packet drop events within a specified time window, filtered by PID or command
// @Tags packet_drops
// @Accept json
// @Produce json
// @Param request body PacketDropSummaryRequest true "Packet drop summary request"
// @Success 200 {object} PacketDropSummaryResponse
// @Failure 400 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/packet-drop-summary [post]
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
// @Summary List connection events
// @Description Returns connection events with optional filtering by PID and limiting results. Supports both GET (query parameters) and POST (JSON body) methods.
// @Tags connections
// @Accept json
// @Produce json
// @Param pid query int false "Process ID to filter by"
// @Param limit query int false "Maximum connections to return per PID (default: 100, max: 1000)"
// @Param request body ListConnectionsRequest false "Connections list request (POST only)"
// @Success 200 {object} ListConnectionsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/list-connections [get]
// @Router /api/list-connections [post]
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
// @Summary List packet drop events
// @Description Returns packet drop events with optional filtering by PID and limiting results. Supports both GET (query parameters) and POST (JSON body) methods.
// @Tags packet_drops
// @Accept json
// @Produce json
// @Param pid query int false "Process ID to filter by"
// @Param limit query int false "Maximum packet drops to return per PID (default: 100, max: 1000)"
// @Param request body ListPacketDropsRequest false "Packet drops list request (POST only)"
// @Success 200 {object} ListPacketDropsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 405 {object} ErrorResponse
// @Router /api/list-packet-drops [get]
// @Router /api/list-packet-drops [post]
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
// @Summary Health check
// @Description Returns the health status of the eBPF server and active programs
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 405 {object} ErrorResponse
// @Router /health [get]
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

// HandlePrograms lists all active eBPF programs
// @Summary List active eBPF programs
// @Description Returns information about all currently registered and running eBPF programs
// @Tags programs
// @Produce json
// @Success 200 {object} ProgramsResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/programs [get]
func HandlePrograms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only GET method is allowed")
		return
	}

	manager := bpf.GetManager()
	if manager == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "eBPF manager not initialized")
		return
	}

	programs := []ProgramInfo{}
	for _, program := range manager.GetPrograms() {
		eventCount := 0
		if allEvents := program.GetAllEvents(); allEvents != nil {
			for _, events := range allEvents {
				eventCount += len(events)
			}
		}

		programs = append(programs, ProgramInfo{
			Name:        program.GetName(),
			Description: program.GetDescription(),
			Running:     program.IsRunning(),
			EventCount:  eventCount,
		})
	}

	response := ProgramsResponse{
		Programs: programs,
		Total:    len(programs),
		Message:  fmt.Sprintf("%d eBPF programs currently active", len(programs)),
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// HandleEvents provides a unified endpoint to query events across all programs
// @Summary Query events across all programs
// @Description Returns events from all eBPF programs with optional filtering by PID, command, event type, and time window
// @Tags events
// @Produce json
// @Param pid query int false "Process ID to filter by"
// @Param command query string false "Command name to filter by"
// @Param event_type query string false "Event type to filter by (e.g., 'connection', 'packet_drop')"
// @Param duration query int false "Time window in seconds (default: 300)" default(300)
// @Param limit query int false "Maximum number of events to return (default: 100)" default(100)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/events [get]
func HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Only GET method is allowed")
		return
	}

	// Parse query parameters
	pidStr := r.URL.Query().Get("pid")
	command := r.URL.Query().Get("command")
	eventType := r.URL.Query().Get("event_type")
	durationStr := r.URL.Query().Get("duration")
	limitStr := r.URL.Query().Get("limit")

	var pid uint32
	if pidStr != "" {
		if pidVal, err := strconv.ParseUint(pidStr, 10, 32); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "Invalid PID parameter")
			return
		} else {
			pid = uint32(pidVal)
		}
	}

	duration := 300 // Default 5 minutes
	if durationStr != "" {
		if dur, err := strconv.Atoi(durationStr); err != nil || dur < 1 || dur > 3600 {
			writeErrorResponse(w, http.StatusBadRequest, "Duration must be between 1 and 3600 seconds")
			return
		} else {
			duration = dur
		}
	}

	limit := 100 // Default limit
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err != nil || l < 1 || l > 1000 {
			writeErrorResponse(w, http.StatusBadRequest, "Limit must be between 1 and 1000")
			return
		} else {
			limit = l
		}
	}

	manager := bpf.GetManager()
	if manager == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "eBPF manager not initialized")
		return
	}

	storage := manager.GetStorage()
	since := bpf.GetSystemBootTime().Add(-time.Duration(duration) * time.Second)

	events, err := storage.Get(pid, command, eventType, since)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query events: %v", err))
		return
	}

	// Limit results
	if len(events) > limit {
		events = events[:limit]
	}

	response := map[string]interface{}{
		"events":   events,
		"total":    len(events),
		"limit":    limit,
		"duration": duration,
		"filters": map[string]interface{}{
			"pid":        pid,
			"command":    command,
			"event_type": eventType,
		},
		"message": fmt.Sprintf("Found %d events in the last %d seconds", len(events), duration),
	}

	writeJSONResponse(w, http.StatusOK, response)
}
