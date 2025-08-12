package aggregator

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthCheck represents the aggregator health status.
type HealthCheck struct {
	Status    string            `json:"status"`
	Component string            `json:"component"`
	Uptime    string            `json:"uptime"`
	Stats     map[string]interface{} `json:"stats"`
}

// HandleHealth handles health check requests.
//
//	@Summary		Health check
//	@Description	Get the health status and basic statistics of the aggregator
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	HealthCheck	"Health status"
//	@Failure		405	{string}	string		"Method not allowed"
//	@Failure		503	{object}	HealthCheck	"Service unavailable"
//	@Router			/health [get]
func (a *Aggregator) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := "unhealthy"
	if a.IsRunning() {
		status = "healthy"
	}

	// Get basic stats
	a.stats.mu.RLock()
	uptime := time.Since(a.stats.StartTime).String()
	totalEvents := a.stats.TotalEvents
	a.stats.mu.RUnlock()

	health := HealthCheck{
		Status:    status,
		Component: "aggregator",
		Uptime:    uptime,
		Stats: map[string]interface{}{
			"total_events": totalEvents,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if status == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(health)
}
