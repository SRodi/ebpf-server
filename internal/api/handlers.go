// Package api provides HTTP handlers for the eBPF monitoring system.
//
//	@title			eBPF Network Monitor API
//	@description	HTTP API for eBPF-based network connection and packet drop monitoring
//	@version		1.0.0
//	@host			localhost:8080
//	@BasePath		/
//	@contact.name	API Support
//	@contact.url	https://github.com/srodi/ebpf-server/issues
//	@contact.email	support@example.com
//	@license.name	MIT
//	@license.url	https://github.com/srodi/ebpf-server/blob/main/LICENSE
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/system"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Global system instance
var globalSystem *system.System

// Initialize sets up the API with the system instance.
func Initialize(sys *system.System) {
	globalSystem = sys
}

// HandleHealth responds with system health information.
//
//	@Summary		Health check
//	@Description	Get the health status of the eBPF monitoring system
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Health status"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/health [get]
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	health := map[string]interface{}{
		"status":  "healthy",
		"running": globalSystem.IsRunning(),
		"time":    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		logger.Errorf("Error encoding health response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandlePrograms returns the status of all eBPF programs.
//
//	@Summary		List eBPF programs
//	@Description	Get the status and information of all loaded eBPF programs
//	@Tags			programs
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"List of eBPF programs"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/programs [get]
func HandlePrograms(w http.ResponseWriter, r *http.Request) {
	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	programs := globalSystem.GetPrograms()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(programs); err != nil {
		logger.Errorf("Error encoding programs response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleEvents returns events matching query parameters.
//
//	@Summary		Query events
//	@Description	Get events filtered by type, PID, command, time range, and limit
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			type		query		string	false	"Event type (connection, packet_drop)"
//	@Param			pid			query		int		false	"Process ID"
//	@Param			command		query		string	false	"Command name"
//	@Param			since		query		string	false	"Start time (RFC3339 format)"
//	@Param			until		query		string	false	"End time (RFC3339 format)"
//	@Param			limit		query		int		false	"Maximum number of events to return (default: 100)"
//	@Success		200			{object}	map[string]interface{}	"Filtered events"
//	@Failure		500			{object}	map[string]string		"Internal server error"
//	@Failure		503			{object}	map[string]string		"Service unavailable"
//	@Router			/api/events [get]
func HandleEvents(w http.ResponseWriter, r *http.Request) {
	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	query := core.Query{}

	if eventType := r.URL.Query().Get("type"); eventType != "" {
		query.EventType = eventType
	}

	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			query.PID = uint32(pid)
		}
	}

	if command := r.URL.Query().Get("command"); command != "" {
		query.Command = command
	}

	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if since, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			query.Since = since
		}
	}

	if untilStr := r.URL.Query().Get("until"); untilStr != "" {
		if until, err := time.Parse(time.RFC3339, untilStr); err == nil {
			query.Until = until
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			query.Limit = limit
		}
	}

	// Default limit to prevent overwhelming responses
	if query.Limit == 0 {
		query.Limit = 100
	}

	ctx := context.Background()
	events, err := globalSystem.QueryEvents(ctx, query)
	if err != nil {
		logger.Errorf("Error querying events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"events": events,
		"count":  len(events),
		"query":  query,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding events response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleConnectionSummary provides connection event summaries.
//
//	@Summary		Get connection statistics
//	@Description	Get count of connection events filtered by PID, command, and time window
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID (GET only)"
//	@Param			command			query		string	false	"Command name (GET only)"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (GET only, default: 60)"
//	@Param			request			body		ConnectionSummaryRequest	false	"Connection summary request (POST only)"
//	@Success		200				{object}	ConnectionSummaryResponse	"Connection statistics"
//	@Failure		400				{object}	map[string]string			"Bad request"
//	@Failure		500				{object}	map[string]string			"Internal server error"
//	@Failure		503				{object}	map[string]string			"Service unavailable"
//	@Router			/api/connection-summary [get]
//	@Router			/api/connection-summary [post]
func HandleConnectionSummary(w http.ResponseWriter, r *http.Request) {
	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse request body for POST requests
	var request struct {
		PID      uint32 `json:"pid"`
		Command  string `json:"command"`
		Duration int    `json:"duration_seconds"`
	}

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Handle GET request with query parameters
		if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
			if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
				request.PID = uint32(pid)
			}
		}
		request.Command = r.URL.Query().Get("command")
		if durationStr := r.URL.Query().Get("duration_seconds"); durationStr != "" {
			if duration, err := strconv.Atoi(durationStr); err == nil {
				request.Duration = duration
			}
		}
	}

	// Default duration to 60 seconds
	if request.Duration == 0 {
		request.Duration = 60
	}

	// Build query
	query := core.Query{
		EventType: "connection",
		PID:       request.PID,
		Command:   request.Command,
		Since:     time.Now().Add(-time.Duration(request.Duration) * time.Second),
	}

	ctx := context.Background()
	count, err := globalSystem.CountEvents(ctx, query)
	if err != nil {
		logger.Errorf("Error counting connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"count":            count,
		"pid":              request.PID,
		"command":          request.Command,
		"duration_seconds": request.Duration,
		"query_time":       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding connection summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandlePacketDropSummary provides packet drop event summaries.
//
//	@Summary		Get packet drop statistics
//	@Description	Get count of packet drop events filtered by PID, command, and time window
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID (GET only)"
//	@Param			command			query		string	false	"Command name (GET only)"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (GET only, default: 60)"
//	@Param			request			body		PacketDropSummaryRequest	false	"Packet drop summary request (POST only)"
//	@Success		200				{object}	PacketDropSummaryResponse	"Packet drop statistics"
//	@Failure		400				{object}	map[string]string			"Bad request"
//	@Failure		500				{object}	map[string]string			"Internal server error"
//	@Failure		503				{object}	map[string]string			"Service unavailable"
//	@Router			/api/packet-drop-summary [get]
//	@Router			/api/packet-drop-summary [post]
func HandlePacketDropSummary(w http.ResponseWriter, r *http.Request) {
	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse request body for POST requests
	var request struct {
		PID      uint32 `json:"pid"`
		Command  string `json:"command"`
		Duration int    `json:"duration_seconds"`
	}

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Handle GET request with query parameters
		if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
			if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
				request.PID = uint32(pid)
			}
		}
		request.Command = r.URL.Query().Get("command")
		if durationStr := r.URL.Query().Get("duration_seconds"); durationStr != "" {
			if duration, err := strconv.Atoi(durationStr); err == nil {
				request.Duration = duration
			}
		}
	}

	// Default duration to 60 seconds
	if request.Duration == 0 {
		request.Duration = 60
	}

	// Build query
	query := core.Query{
		EventType: "packet_drop",
		PID:       request.PID,
		Command:   request.Command,
		Since:     time.Now().Add(-time.Duration(request.Duration) * time.Second),
	}

	ctx := context.Background()
	count, err := globalSystem.CountEvents(ctx, query)
	if err != nil {
		logger.Errorf("Error counting packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"count":            count,
		"pid":              request.PID,
		"command":          request.Command,
		"duration_seconds": request.Duration,
		"query_time":       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding packet drop summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleListConnections returns recent connection events.
//
//	@Summary		List connection events
//	@Description	Get recent connection events grouped by PID
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ConnectionListResponse	"Connection events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-connections [get]
func HandleListConnections(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("🌐 HTTP REQUEST: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	query := core.Query{
		EventType: "connection",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	ctx := context.Background()
	events, err := globalSystem.QueryEvents(ctx, query)
	if err != nil {
		logger.Errorf("Error querying connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)
	}

	response := map[string]interface{}{
		"total_pids":    len(eventsByPID),
		"total_events":  len(events),
		"events_by_pid": eventsByPID,
		"query_time":    time.Now().Format(time.RFC3339),
	}

	logger.Debugf("🌐 HTTP RESPONSE: connections query returned %d events across %d PIDs", len(events), len(eventsByPID))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list connections response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleListPacketDrops returns recent packet drop events.
//
//	@Summary		List packet drop events
//	@Description	Get recent packet drop events grouped by PID
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	PacketDropListResponse	"Packet drop events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-packet-drops [get]
func HandleListPacketDrops(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("🌐 HTTP REQUEST: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	if globalSystem == nil {
		http.Error(w, "System not initialized", http.StatusServiceUnavailable)
		return
	}

	query := core.Query{
		EventType: "packet_drop",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	ctx := context.Background()
	events, err := globalSystem.QueryEvents(ctx, query)
	if err != nil {
		logger.Errorf("Error querying packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)
	}

	response := map[string]interface{}{
		"total_pids":    len(eventsByPID),
		"total_events":  len(events),
		"events_by_pid": eventsByPID,
		"query_time":    time.Now().Format(time.RFC3339),
	}

	logger.Debugf("🌐 HTTP RESPONSE: packet drops query returned %d events across %d PIDs", len(events), len(eventsByPID))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list packet drops response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Swagger models for request/response documentation

// ConnectionSummaryRequest represents the request body for connection summary
type ConnectionSummaryRequest struct {
	PID      uint32 `json:"pid" example:"1234"`            // Process ID
	Command  string `json:"command" example:"curl"`        // Command name
	Duration int    `json:"duration_seconds" example:"60"` // Duration in seconds
}

// ConnectionSummaryResponse represents the response for connection summary
type ConnectionSummaryResponse struct {
	Count           int    `json:"count" example:"5"`                         // Number of connection events
	PID             uint32 `json:"pid" example:"1234"`                        // Process ID
	Command         string `json:"command" example:"curl"`                    // Command name
	DurationSeconds int    `json:"duration_seconds" example:"60"`             // Duration in seconds
	QueryTime       string `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// PacketDropSummaryRequest represents the request body for packet drop summary
type PacketDropSummaryRequest struct {
	PID      uint32 `json:"pid" example:"1234"`            // Process ID
	Command  string `json:"command" example:"nginx"`       // Command name
	Duration int    `json:"duration_seconds" example:"60"` // Duration in seconds
}

// PacketDropSummaryResponse represents the response for packet drop summary
type PacketDropSummaryResponse struct {
	Count           int    `json:"count" example:"3"`                         // Number of packet drop events
	PID             uint32 `json:"pid" example:"1234"`                        // Process ID
	Command         string `json:"command" example:"nginx"`                   // Command name
	DurationSeconds int    `json:"duration_seconds" example:"60"`             // Duration in seconds
	QueryTime       string `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// ConnectionListResponse represents the response for listing connections
type ConnectionListResponse struct {
	TotalPIDs   int                     `json:"total_pids" example:"3"`                    // Number of unique PIDs
	TotalEvents int                     `json:"total_events" example:"10"`                 // Total number of events
	EventsByPID map[uint32][]core.Event `json:"events_by_pid"`                             // Events grouped by PID
	QueryTime   string                  `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// PacketDropListResponse represents the response for listing packet drops
type PacketDropListResponse struct {
	TotalPIDs   int                     `json:"total_pids" example:"2"`                    // Number of unique PIDs
	TotalEvents int                     `json:"total_events" example:"7"`                  // Total number of events
	EventsByPID map[uint32][]core.Event `json:"events_by_pid"`                             // Events grouped by PID
	QueryTime   string                  `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}
