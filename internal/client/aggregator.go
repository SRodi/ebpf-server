// Package client provides client functionality for communicating with the aggregator.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// AggregatorClient communicates with the aggregator service.
type AggregatorClient struct {
	baseURL    string
	httpClient *http.Client
	enabled    bool
	buffer     []core.Event
	mu         sync.Mutex
	batchSize  int
	flushTimer *time.Ticker
	stopCh     chan struct{}
}

// NewAggregatorClient creates a new aggregator client.
func NewAggregatorClient() *AggregatorClient {
	aggregatorURL := os.Getenv("AGGREGATOR_URL")
	if aggregatorURL == "" {
		logger.Debug("AGGREGATOR_URL not set, aggregator client disabled")
		return &AggregatorClient{enabled: false}
	}

	client := &AggregatorClient{
		baseURL: aggregatorURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		enabled:    true,
		buffer:     make([]core.Event, 0, 100),
		batchSize:  50,
		flushTimer: time.NewTicker(10 * time.Second),
		stopCh:     make(chan struct{}),
	}

	// Start background flush routine
	go client.flushRoutine()

	return client
}

// IsEnabled returns true if the client is enabled.
func (c *AggregatorClient) IsEnabled() bool {
	return c.enabled
}

// SendEvent sends a single event to the aggregator.
func (c *AggregatorClient) SendEvent(ctx context.Context, event core.Event) error {
	if !c.enabled {
		return nil
	}

	c.mu.Lock()
	c.buffer = append(c.buffer, event)
	shouldFlush := len(c.buffer) >= c.batchSize
	c.mu.Unlock()

	if shouldFlush {
		return c.flush(ctx)
	}

	return nil
}

// SendEvents sends multiple events to the aggregator.
func (c *AggregatorClient) SendEvents(ctx context.Context, events []core.Event) error {
	if !c.enabled || len(events) == 0 {
		return nil
	}

	c.mu.Lock()
	c.buffer = append(c.buffer, events...)
	shouldFlush := len(c.buffer) >= c.batchSize
	c.mu.Unlock()

	if shouldFlush {
		return c.flush(ctx)
	}

	return nil
}

// Flush sends all buffered events to the aggregator.
func (c *AggregatorClient) Flush(ctx context.Context) error {
	if !c.enabled {
		return nil
	}

	return c.flush(ctx)
}

// Close stops the client and flushes any remaining events.
func (c *AggregatorClient) Close() error {
	if !c.enabled {
		return nil
	}

	close(c.stopCh)
	c.flushTimer.Stop()

	// Final flush
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.flush(ctx)
}

// flush sends buffered events to the aggregator.
func (c *AggregatorClient) flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return nil
	}

	events := make([]core.Event, len(c.buffer))
	copy(events, c.buffer)
	c.buffer = c.buffer[:0] // Clear buffer
	c.mu.Unlock()

	// Convert events to JSON
	jsonEvents := make([]json.RawMessage, len(events))
	for i, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			logger.Errorf("Failed to marshal event: %v", err)
			continue
		}
		jsonEvents[i] = json.RawMessage(data)
	}

	// Send to aggregator
	requestData := map[string]interface{}{
		"events": jsonEvents,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/events/ingest", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aggregator returned status %d", resp.StatusCode)
	}

	logger.Debugf("Sent %d events to aggregator", len(events))
	return nil
}

// flushRoutine periodically flushes buffered events.
func (c *AggregatorClient) flushRoutine() {
	for {
		select {
		case <-c.flushTimer.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := c.flush(ctx); err != nil {
				logger.Errorf("Failed to flush events to aggregator: %v", err)
			}
			cancel()
		case <-c.stopCh:
			return
		}
	}
}
