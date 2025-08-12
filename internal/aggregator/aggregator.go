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

// Config represents aggregator configuration.
type Config struct {
	HTTPAddr string
}

// Aggregator collects and aggregates events from multiple eBPF agents.
type Aggregator struct {
	config  *Config
	storage core.EventSink
	stats   *Stats
	mu      sync.RWMutex
	running bool
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
//	@Success		200			{object}	map[string]interface{}	"Events and count"
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
//	@Success		200		{object}	map[string]interface{}	"Ingestion result"
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
//	@Success		200	{object}	map[string]interface{}	"Aggregation statistics"
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statsData); err != nil {
		logger.Errorf("Failed to encode stats: %v", err)
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
