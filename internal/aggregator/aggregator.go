// Package aggregator provides event aggregation functionality for eBPF monitoring.
//
//	@title			eBPF Event Aggregator API
//	@description	HTTP API for aggregating and querying eBPF events from multiple agents
//	@version		1.0.0
//	@host			localhost:8081
//	@BasePath		/
//	@contact.name	API Support
//	@contact.url	https://github.com/srodi/ebpf-server/issues
//	@contact.email	support@example.com
//	@license.name	MIT
//	@license.url	https://github.com/srodi/ebpf-server/blob/main/LICENSE
package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/storage"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Response types for aggregator API endpoints

// AggregatedEventsResponse represents the response for querying aggregated events
type AggregatedEventsResponse struct {
	Events     []core.Event           `json:"events"`                                    // List of aggregated events
	Count      int                    `json:"count" example:"50"`                        // Number of events returned
	TotalCount int                    `json:"total_count" example:"1250"`                // Total number of matching events
	QueryTime  string                 `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
	Filters    AggregatedEventFilters `json:"filters"`                                   // Applied filters
}

// AggregatedEventFilters represents the filters applied to aggregated event queries
type AggregatedEventFilters struct {
	Type  string `json:"type,omitempty" example:"connection"`            // Event type filter
	Node  string `json:"node,omitempty" example:"worker-1"`              // Node name filter
	Since string `json:"since,omitempty" example:"2023-01-01T12:00:00Z"` // Start time filter
	Until string `json:"until,omitempty" example:"2023-01-01T13:00:00Z"` // End time filter
	Limit int    `json:"limit,omitempty" example:"100"`                  // Limit filter
}

// IngestResponse represents the response for event ingestion
type IngestResponse struct {
	EventsProcessed int    `json:"events_processed" example:"25"`                  // Number of events processed
	Success         bool   `json:"success" example:"true"`                         // Ingestion success status
	Message         string `json:"message" example:"Events ingested successfully"` // Status message
	Timestamp       string `json:"timestamp" example:"2023-01-01T12:00:00Z"`       // Processing timestamp
}

// AggregationStatsResponse represents the response for aggregation statistics
type AggregationStatsResponse struct {
	TotalEvents      int64            `json:"total_events" example:"12500"`                     // Total events stored
	EventsByType     map[string]int64 `json:"events_by_type"`                                   // Events grouped by type
	EventsByNode     map[string]int64 `json:"events_by_node"`                                   // Events grouped by node
	ConnectedAgents  int              `json:"connected_agents" example:"5"`                     // Number of connected agents
	LastEventTime    string           `json:"last_event_time" example:"2023-01-01T12:00:00Z"`   // Timestamp of last event
	AggregationStart string           `json:"aggregation_start" example:"2023-01-01T10:00:00Z"` // When aggregation started
	QueryTime        string           `json:"query_time" example:"2023-01-01T12:00:00Z"`        // Query timestamp
}

// AggregatorProgramsResponse represents the response for aggregator programs information
type AggregatorProgramsResponse struct {
	ConnectedAgents []AgentInfo   `json:"connected_agents"`                          // List of connected agents
	AllPrograms     []ProgramInfo `json:"all_programs"`                              // All programs across agents
	TotalAgents     int           `json:"total_agents" example:"3"`                  // Total number of agents
	TotalPrograms   int           `json:"total_programs" example:"6"`                // Total number of programs
	QueryTime       string        `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// AgentInfo represents information about a connected agent
type AgentInfo struct {
	NodeName   string        `json:"node_name" example:"worker-1"`             // Node name
	LastSeen   string        `json:"last_seen" example:"2023-01-01T12:00:00Z"` // Last seen timestamp
	EventCount int64         `json:"event_count" example:"2500"`               // Number of events from this agent
	Programs   []ProgramInfo `json:"programs"`                                 // Programs running on this agent
	Status     string        `json:"status" example:"active"`                  // Agent status
}

// ProgramInfo represents information about an eBPF program
type ProgramInfo struct {
	Name       string `json:"name" example:"connection_tracer"` // Program name
	Type       string `json:"type" example:"kprobe"`            // Program type
	Status     string `json:"status" example:"active"`          // Program status
	Node       string `json:"node" example:"worker-1"`          // Node where program is running
	EventCount int64  `json:"event_count" example:"1250"`       // Events generated by this program
}

// AggregatedListResponse represents the response for listing aggregated connection/packet drop events
type AggregatedListResponse struct {
	TotalPIDs    int                     `json:"total_pids" example:"8"`                    // Number of unique PIDs across all nodes
	TotalEvents  int                     `json:"total_events" example:"45"`                 // Total number of events
	TotalNodes   int                     `json:"total_nodes" example:"3"`                   // Number of nodes with events
	EventsByPID  map[uint32][]core.Event `json:"events_by_pid"`                             // Events grouped by PID
	EventsByNode map[string]int          `json:"events_by_node"`                            // Event count by node
	QueryTime    string                  `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// AggregatedSummaryResponse represents the response for aggregated connection/packet drop summaries
type AggregatedSummaryResponse struct {
	Count           int            `json:"count" example:"15"`                        // Total count across all nodes
	CountByNode     map[string]int `json:"count_by_node"`                             // Count by node
	PID             uint32         `json:"pid,omitempty" example:"1234"`              // Process ID (if filtered)
	Command         string         `json:"command,omitempty" example:"curl"`          // Command name (if filtered)
	DurationSeconds int            `json:"duration_seconds" example:"60"`             // Duration in seconds
	TotalNodes      int            `json:"total_nodes" example:"3"`                   // Number of nodes with events
	QueryTime       string         `json:"query_time" example:"2023-01-01T12:00:00Z"` // Query timestamp
}

// Config represents aggregator configuration.
type Config struct {
	HTTPAddr string
}

// ProgramCache caches program information to avoid expensive queries
type ProgramCache struct {
	data      *AggregatorProgramsResponse
	lastCheck time.Time
	mu        sync.RWMutex
}

// Aggregator collects and aggregates events from multiple eBPF agents.
type Aggregator struct {
	config       *Config
	storage      core.EventSink
	stats        *Stats
	programCache *ProgramCache
	mu           sync.RWMutex
	running      bool
}

// Stats represents aggregation statistics.
type Stats struct {
	TotalEvents   int64            `json:"total_events"`
	EventsByType  map[string]int64 `json:"events_by_type"`
	EventsByNode  map[string]int64 `json:"events_by_node"`
	LastEventTime time.Time        `json:"last_event_time"`
	StartTime     time.Time        `json:"start_time"`
	mu            sync.RWMutex
}

// New creates a new aggregator instance.
func New(config *Config) (*Aggregator, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Create in-memory storage for aggregated events
	eventStorage := storage.NewMemoryStorage()

	return &Aggregator{
		config:  config,
		storage: eventStorage,
		stats: &Stats{
			EventsByType: make(map[string]int64),
			EventsByNode: make(map[string]int64),
			StartTime:    time.Now(),
		},
		programCache: &ProgramCache{},
	}, nil
}

// Start starts the aggregator services.
func (a *Aggregator) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.running {
		return fmt.Errorf("aggregator already running")
	}

	logger.Info("Starting event aggregator")
	a.running = true

	// Start cleanup routine for memory storage
	go a.cleanupRoutine(ctx)

	return nil
}

// Stop stops the aggregator services.
func (a *Aggregator) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return
	}

	logger.Info("Stopping event aggregator")
	a.running = false
}

// IsRunning returns true if the aggregator is running.
func (a *Aggregator) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// HandleEvents handles HTTP requests for querying aggregated events.
//
//	@Summary		Query aggregated events
//	@Description	Retrieve aggregated events with optional filtering by type, node, and time range
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			type		query		string	false	"Event type filter"
//	@Param			node		query		string	false	"Node name filter"
//	@Param			since		query		string	false	"Start time (RFC3339 format)"
//	@Param			until		query		string	false	"End time (RFC3339 format)"
//	@Param			limit		query		int		false	"Maximum number of events to return"
//	@Success		200			{object}	AggregatedEventsResponse	"Events and count"
//	@Failure		405			{string}	string					"Method not allowed"
//	@Failure		500			{string}	string					"Internal server error"
//	@Router			/api/events [get]
func (a *Aggregator) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	query := parseEventQuery(r)

	// Query storage
	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Failed to query events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return events as JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	}); err != nil {
		logger.Errorf("Failed to encode events: %v", err)
	}
}

// HandleIngest handles HTTP requests for ingesting events from agents.
//
//	@Summary		Ingest events from agents
//	@Description	Accept events from eBPF agents for aggregation and storage
//	@Tags			events
//	@Accept			json
//	@Produce		json
//	@Param			events	body		object	true	"Events to ingest"
//	@Success		200		{object}	IngestResponse	"Ingestion result"
//	@Failure		400		{string}	string					"Bad request"
//	@Failure		405		{string}	string					"Method not allowed"
//	@Failure		500		{string}	string					"Internal server error"
//	@Router			/api/events/ingest [post]
func (a *Aggregator) HandleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData struct {
		Events []json.RawMessage `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		logger.Errorf("Failed to decode ingest request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Process each event
	processed := 0
	for _, eventData := range requestData.Events {
		if err := a.ingestEvent(r.Context(), eventData); err != nil {
			logger.Errorf("Failed to ingest event: %v", err)
			continue
		}
		processed++
	}

	// Update stats
	a.updateStats(int64(processed), requestData.Events)

	// Invalidate program cache if we processed events successfully
	// This ensures the cache reflects newly ingested data
	if processed > 0 {
		a.invalidateProgramCache()
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"processed": processed,
		"total":     len(requestData.Events),
	}); err != nil {
		logger.Errorf("Failed to encode ingest response: %v", err)
	}
}

// HandleStats handles HTTP requests for aggregation statistics.
//
//	@Summary		Get aggregation statistics
//	@Description	Retrieve statistics about event aggregation including counts by type and node
//	@Tags			stats
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregationStatsResponse	"Aggregation statistics"
//	@Failure		405	{string}	string					"Method not allowed"
//	@Router			/api/stats [get]
func (a *Aggregator) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a.stats.mu.RLock()
	statsData := map[string]interface{}{
		"total_events":    a.stats.TotalEvents,
		"events_by_type":  a.stats.EventsByType,
		"events_by_node":  a.stats.EventsByNode,
		"last_event_time": a.stats.LastEventTime,
		"start_time":      a.stats.StartTime,
	}
	a.stats.mu.RUnlock()

	// Add current storage info for debugging
	if memStorage, ok := a.storage.(*storage.MemoryStorage); ok {
		// Get a rough count of current events (last hour)
		query := core.Query{
			Since: time.Now().Add(-1 * time.Hour),
		}
		currentEvents, _ := memStorage.Count(context.Background(), query)
		statsData["current_events_last_hour"] = currentEvents

		// Get total events in storage
		allEvents, _ := memStorage.Count(context.Background(), core.Query{})
		statsData["total_events_in_storage"] = allEvents
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statsData); err != nil {
		logger.Errorf("Failed to encode stats: %v", err)
	}
}

// HandlePrograms handles HTTP requests for program information.
// Since the aggregator doesn't run eBPF programs directly, it returns program status from connected agents.
// This endpoint uses caching to avoid expensive queries on each request.
//
//	@Summary		Get program information
//	@Description	Get information about eBPF programs running on connected agents
//	@Tags			programs
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatorProgramsResponse	"Program information"
//	@Failure		405	{string}	string					"Method not allowed"
//	@Router			/api/programs [get]
func (a *Aggregator) HandlePrograms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const cacheDuration = 2 * time.Minute // Cache for 2 minutes

	// Check if we have cached data that's still fresh
	a.programCache.mu.RLock()
	if a.programCache.data != nil && time.Since(a.programCache.lastCheck) < cacheDuration {
		response := a.programCache.data
		a.programCache.mu.RUnlock()

		logger.Debugf("Serving cached program information (age: %v)", time.Since(a.programCache.lastCheck))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cacheDuration.Seconds())))
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Errorf("Failed to encode cached programs response: %v", err)
		}
		return
	}
	a.programCache.mu.RUnlock()

	// Cache is stale or empty, refresh it
	response, err := a.refreshProgramCache()
	if err != nil {
		logger.Errorf("Failed to refresh program cache: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("Serving fresh program information (%d agents, %d programs)",
		response.TotalAgents, response.TotalPrograms)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cacheDuration.Seconds())))
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Failed to encode programs response: %v", err)
	}
}

// refreshProgramCache refreshes the program information cache by querying recent events
func (a *Aggregator) refreshProgramCache() (*AggregatorProgramsResponse, error) {
	// Query recent events to infer connected agents and their programs
	query := core.Query{
		Limit: 1000,                              // Get a good sample of recent events
		Since: time.Now().Add(-10 * time.Minute), // Last 10 minutes
	}

	events, err := a.storage.Query(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for program info: %v", err)
	}

	// Aggregate information about connected agents and their programs
	agents := make(map[string]map[string]interface{}) // node_name -> agent info
	eventTypes := make(map[string]bool)               // unique event types (indicate programs)

	for _, event := range events {
		metadata := event.Metadata()

		// Extract agent information
		nodeName, hasNode := metadata["k8s_node_name"].(string)
		podName, _ := metadata["k8s_pod_name"].(string)
		namespace, _ := metadata["k8s_namespace"].(string)

		if hasNode && nodeName != "" {
			if agents[nodeName] == nil {
				agents[nodeName] = map[string]interface{}{
					"node_name":   nodeName,
					"pod_name":    podName,
					"namespace":   namespace,
					"event_types": make(map[string]bool),
					"last_seen":   event.Time(),
					"event_count": 0,
				}
			}

			// Update agent info
			agent := agents[nodeName]
			eventTypesMap := agent["event_types"].(map[string]bool)
			eventTypesMap[event.Type()] = true
			agent["event_types"] = eventTypesMap
			agent["event_count"] = agent["event_count"].(int) + 1

			// Update last seen if this event is more recent
			if event.Time().After(agent["last_seen"].(time.Time)) {
				agent["last_seen"] = event.Time()
			}
		}

		// Track unique event types across all agents
		eventTypes[event.Type()] = true
	}

	// Convert agents map to slice and format programs
	var connectedAgents []AgentInfo
	var allPrograms []ProgramInfo

	for nodeName, agentInfo := range agents {
		eventTypesMap := agentInfo["event_types"].(map[string]bool)
		var programs []ProgramInfo
		eventCount := int64(agentInfo["event_count"].(int))

		for eventType := range eventTypesMap {
			program := ProgramInfo{
				Name:       eventType + "_tracer",
				Type:       eventType,
				Status:     "active", // Inferred from recent events
				Node:       nodeName,
				EventCount: eventCount,
			}
			programs = append(programs, program)
			allPrograms = append(allPrograms, program)
		}

		agentData := AgentInfo{
			NodeName:   nodeName,
			LastSeen:   agentInfo["last_seen"].(time.Time).Format(time.RFC3339),
			EventCount: eventCount,
			Programs:   programs,
			Status:     "active",
		}
		connectedAgents = append(connectedAgents, agentData)
	}

	response := &AggregatorProgramsResponse{
		ConnectedAgents: connectedAgents,
		AllPrograms:     allPrograms,
		TotalAgents:     len(connectedAgents),
		TotalPrograms:   len(allPrograms),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	// Update cache
	a.programCache.mu.Lock()
	a.programCache.data = response
	a.programCache.lastCheck = time.Now()
	a.programCache.mu.Unlock()

	return response, nil
}

// invalidateProgramCache invalidates the program information cache
func (a *Aggregator) invalidateProgramCache() {
	a.programCache.mu.Lock()
	a.programCache.data = nil
	a.programCache.lastCheck = time.Time{}
	a.programCache.mu.Unlock()
}

// cleanupRoutine runs periodic cleanup of old events to prevent memory bloat
func (a *Aggregator) cleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("Cleanup routine stopping due to context cancellation")
			return
		case <-ticker.C:
			if !a.IsRunning() {
				continue
			}

			// Clean up events older than 2 hours
			maxAge := 2 * time.Hour

			if memStorage, ok := a.storage.(*storage.MemoryStorage); ok {
				logger.Debugf("Running cleanup: removing events older than %v", maxAge)
				memStorage.Cleanup(maxAge)
				logger.Debugf("Cleanup completed")
			}
		}
	}
}

// ingestEvent processes a single event from an agent.
func (a *Aggregator) ingestEvent(ctx context.Context, eventData json.RawMessage) error {
	// Parse event data into a generic event
	var eventMap map[string]interface{}
	if err := json.Unmarshal(eventData, &eventMap); err != nil {
		return fmt.Errorf("failed to parse event: %v", err)
	}

	// Create a simple event wrapper for storage
	event := &SimpleEvent{
		data: eventMap,
	}

	// Store the event
	return a.storage.Store(ctx, event)
}

// updateStats updates aggregation statistics.
func (a *Aggregator) updateStats(processed int64, events []json.RawMessage) {
	a.stats.mu.Lock()
	defer a.stats.mu.Unlock()

	a.stats.TotalEvents += processed
	a.stats.LastEventTime = time.Now()

	// Update per-type and per-node stats
	for _, eventData := range events {
		var eventMap map[string]interface{}
		if err := json.Unmarshal(eventData, &eventMap); err != nil {
			continue
		}

		// Update event type stats
		if eventType, ok := eventMap["type"].(string); ok {
			a.stats.EventsByType[eventType]++
		}

		// Update node stats
		if nodeName, ok := eventMap["k8s_node_name"].(string); ok {
			a.stats.EventsByNode[nodeName]++
		}
	}
}

// parseEventQuery parses HTTP query parameters into a core.Query.
func parseEventQuery(r *http.Request) core.Query {
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

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			query.Limit = limit
		}
	}

	return query
}

// SimpleEvent is a simple implementation of core.Event for aggregated data.
type SimpleEvent struct {
	data map[string]interface{}
}

func (e *SimpleEvent) ID() string {
	if id, ok := e.data["id"].(string); ok {
		return id
	}
	return ""
}

func (e *SimpleEvent) Type() string {
	if eventType, ok := e.data["type"].(string); ok {
		return eventType
	}
	return ""
}

func (e *SimpleEvent) PID() uint32 {
	if pid, ok := e.data["pid"].(float64); ok {
		return uint32(pid)
	}
	return 0
}

func (e *SimpleEvent) Command() string {
	if command, ok := e.data["command"].(string); ok {
		return command
	}
	return ""
}

func (e *SimpleEvent) Timestamp() uint64 {
	if timestamp, ok := e.data["timestamp"].(float64); ok {
		return uint64(timestamp)
	}
	return 0
}

func (e *SimpleEvent) Time() time.Time {
	if timeStr, ok := e.data["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (e *SimpleEvent) Metadata() map[string]interface{} {
	return e.data
}

func (e *SimpleEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.data)
}

// QueryEvents retrieves events matching the criteria (for API compatibility).
func (a *Aggregator) QueryEvents(ctx context.Context, query core.Query) ([]core.Event, error) {
	return a.storage.Query(ctx, query)
}

// CountEvents returns the number of events matching the criteria (for API compatibility).
func (a *Aggregator) CountEvents(ctx context.Context, query core.Query) (int, error) {
	return a.storage.Count(ctx, query)
}

// GetPrograms returns program status (for API compatibility).
// The aggregator doesn't manage eBPF programs directly, so returns empty slice.
func (a *Aggregator) GetPrograms() []core.ProgramStatus {
	return []core.ProgramStatus{}
}

// HandleListConnections returns recent connection events from aggregated data.
//
//	@Summary		List connection events
//	@Description	Get recent connection events grouped by PID from aggregated data
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatedListResponse	"Connection events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-connections [get]
func (a *Aggregator) HandleListConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := core.Query{
		EventType: "connection",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Error querying connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	eventsByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)

		// Extract node information from event metadata
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				eventsByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedListResponse{
		TotalPIDs:    len(eventsByPID),
		TotalEvents:  len(events),
		TotalNodes:   len(nodeSet),
		EventsByPID:  eventsByPID,
		EventsByNode: eventsByNode,
		QueryTime:    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list connections response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleListPacketDrops returns recent packet drop events from aggregated data.
//
//	@Summary		List packet drop events
//	@Description	Get recent packet drop events grouped by PID from aggregated data
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	AggregatedListResponse	"Packet drop events"
//	@Failure		500	{object}	map[string]string		"Internal server error"
//	@Failure		503	{object}	map[string]string		"Service unavailable"
//	@Router			/api/list-packet-drops [get]
func (a *Aggregator) HandleListPacketDrops(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := core.Query{
		EventType: "packet_drop",
		Limit:     100,
		Since:     time.Now().Add(-1 * time.Hour), // Last hour by default
	}

	events, err := a.storage.Query(r.Context(), query)
	if err != nil {
		logger.Errorf("Error querying packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Group by PID for compatibility
	eventsByPID := make(map[uint32][]core.Event)
	eventsByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		pid := event.PID()
		eventsByPID[pid] = append(eventsByPID[pid], event)

		// Extract node information from event metadata
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				eventsByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedListResponse{
		TotalPIDs:    len(eventsByPID),
		TotalEvents:  len(events),
		TotalNodes:   len(nodeSet),
		EventsByPID:  eventsByPID,
		EventsByNode: eventsByNode,
		QueryTime:    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding list packet drops response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleConnectionSummary provides connection event summaries from aggregated data.
//
//	@Summary		Get connection statistics
//	@Description	Get count of connection events filtered by PID, command, and time window from aggregated data
//	@Tags			connections
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID"
//	@Param			command			query		string	false	"Command name"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (default: 60)"
//	@Param			request			body		map[string]interface{}	false	"Connection summary request (POST only)"
//	@Success		200				{object}	AggregatedSummaryResponse	"Connection statistics"
//	@Failure		400				{object}	map[string]string		"Bad request"
//	@Failure		500				{object}	map[string]string		"Internal server error"
//	@Router			/api/connection-summary [get]
//	@Router			/api/connection-summary [post]
func (a *Aggregator) HandleConnectionSummary(w http.ResponseWriter, r *http.Request) {
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

	count, err := a.storage.Count(r.Context(), query)
	if err != nil {
		logger.Errorf("Error counting connection events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("🔍 CONNECTION SUMMARY: query=%+v count=%d", query, count)

	// Get events to analyze by node for detailed response
	eventsQuery := query
	eventsQuery.Limit = 1000 // Reasonable limit for analysis
	events, err := a.storage.Query(r.Context(), eventsQuery)
	if err != nil {
		logger.Errorf("Error querying connection events for node analysis: %v", err)
		// Fall back to basic response without node breakdown
		events = nil
	}

	// Analyze events by node
	countByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				countByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedSummaryResponse{
		Count:           count,
		CountByNode:     countByNode,
		PID:             request.PID,
		Command:         request.Command,
		DurationSeconds: request.Duration,
		TotalNodes:      len(nodeSet),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding connection summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandlePacketDropSummary provides packet drop event summaries from aggregated data.
//
//	@Summary		Get packet drop statistics
//	@Description	Get count of packet drop events filtered by PID, command, and time window from aggregated data
//	@Tags			packet_drops
//	@Accept			json
//	@Produce		json
//	@Param			pid				query		int		false	"Process ID"
//	@Param			command			query		string	false	"Command name"
//	@Param			duration_seconds	query	int		false	"Duration in seconds (default: 60)"
//	@Param			request			body		map[string]interface{}	false	"Packet drop summary request (POST only)"
//	@Success		200				{object}	AggregatedSummaryResponse	"Packet drop statistics"
//	@Failure		400				{object}	map[string]string		"Bad request"
//	@Failure		500				{object}	map[string]string		"Internal server error"
//	@Router			/api/packet-drop-summary [get]
//	@Router			/api/packet-drop-summary [post]
func (a *Aggregator) HandlePacketDropSummary(w http.ResponseWriter, r *http.Request) {
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

	count, err := a.storage.Count(r.Context(), query)
	if err != nil {
		logger.Errorf("Error counting packet drop events: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Debugf("🔍 PACKET DROP SUMMARY: query=%+v count=%d", query, count)

	// Get events to analyze by node for detailed response
	eventsQuery := query
	eventsQuery.Limit = 1000 // Reasonable limit for analysis
	events, err := a.storage.Query(r.Context(), eventsQuery)
	if err != nil {
		logger.Errorf("Error querying packet drop events for node analysis: %v", err)
		// Fall back to basic response without node breakdown
		events = nil
	}

	// Analyze events by node
	countByNode := make(map[string]int)
	nodeSet := make(map[string]bool)

	for _, event := range events {
		if metadata := event.Metadata(); metadata != nil {
			if nodeName, ok := metadata["k8s_node_name"].(string); ok && nodeName != "" {
				countByNode[nodeName]++
				nodeSet[nodeName] = true
			}
		}
	}

	response := AggregatedSummaryResponse{
		Count:           count,
		CountByNode:     countByNode,
		PID:             request.PID,
		Command:         request.Command,
		DurationSeconds: request.Duration,
		TotalNodes:      len(nodeSet),
		QueryTime:       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Errorf("Error encoding packet drop summary response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
