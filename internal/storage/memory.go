// Package storage provides event storage implementations.
package storage

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// MemoryStorage implements EventSink using in-memory storage.
// This is suitable for development and small-scale deployments.
type MemoryStorage struct {
	events []core.Event
	mu     sync.RWMutex
}

// NewMemoryStorage creates a new in-memory event storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		events: make([]core.Event, 0),
	}
}

// Store saves an event to memory.
func (s *MemoryStorage) Store(ctx context.Context, event core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)

	// Debug log stored events
	logger.Debugf("💾 STORED EVENT: type=%s PID=%d cmd=%s total_events=%d",
		event.Type(), event.PID(), event.Command(), len(s.events))

	return nil
}

// Query retrieves events matching the criteria.
func (s *MemoryStorage) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []core.Event
	totalChecked := 0

	for _, event := range s.events {
		totalChecked++
		if s.matchesQuery(event, query) {
			results = append(results, event)
		}
	}

	// Log only if we're filtering by time and getting unexpected results
	if !query.Since.IsZero() && len(results) == 0 && totalChecked > 0 {
		logger.Debugf("🔍 STORAGE QUERY: type=%s since=%s checked=%d matched=%d",
			query.EventType, query.Since.Format(time.RFC3339), totalChecked, len(results))
	}

	// Sort by timestamp (most recent first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp() > results[j].Timestamp()
	})

	// Apply limit
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}

	return results, nil
}

// Count returns the number of events matching the criteria.
func (s *MemoryStorage) Count(ctx context.Context, query core.Query) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, event := range s.events {
		if s.matchesQuery(event, query) {
			count++
		}
	}

	return count, nil
}

// matchesQuery checks if an event matches the query criteria.
func (s *MemoryStorage) matchesQuery(event core.Event, query core.Query) bool {
	// Filter by event type
	if query.EventType != "" && event.Type() != query.EventType {
		return false
	}

	// Filter by PID
	if query.PID != 0 && event.PID() != query.PID {
		return false
	}

	// Filter by command
	if query.Command != "" && event.Command() != query.Command {
		return false
	}

	// Filter by time range
	eventTime := event.Time()
	if !query.Since.IsZero() && eventTime.Before(query.Since) {
		return false
	}
	if !query.Until.IsZero() && eventTime.After(query.Until) {
		return false
	}

	return true
}

// Cleanup removes old events (for memory management).
func (s *MemoryStorage) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var kept []core.Event

	for _, event := range s.events {
		if event.Time().After(cutoff) {
			kept = append(kept, event)
		}
	}

	s.events = kept
}

// StorageWithSink wraps a storage implementation and automatically stores events from a stream.
type StorageWithSink struct {
	storage core.EventSink
	stream  core.EventStream
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewStorageWithSink creates storage that automatically consumes from an event stream.
func NewStorageWithSink(storage core.EventSink, stream core.EventStream) *StorageWithSink {
	ctx, cancel := context.WithCancel(context.Background())

	s := &StorageWithSink{
		storage: storage,
		stream:  stream,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start consuming events
	go s.consumeEvents()

	return s
}

// Store implements EventSink.
func (s *StorageWithSink) Store(ctx context.Context, event core.Event) error {
	return s.storage.Store(ctx, event)
}

// Query implements EventSink.
func (s *StorageWithSink) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	return s.storage.Query(ctx, query)
}

// Count implements EventSink.
func (s *StorageWithSink) Count(ctx context.Context, query core.Query) (int, error) {
	return s.storage.Count(ctx, query)
}

// Close stops consuming events.
func (s *StorageWithSink) Close() error {
	s.cancel()
	return s.stream.Close()
}

// consumeEvents reads events from the stream and stores them.
func (s *StorageWithSink) consumeEvents() {
	for {
		select {
		case event, ok := <-s.stream.Events():
			if !ok {
				return
			}

			if err := s.storage.Store(s.ctx, event); err != nil {
				// Log the storage error - this could indicate memory pressure,
				// disk space issues, or other critical storage problems
				logger.Errorf("Failed to store event (PID: %d, Type: %s): %v",
					event.PID(), event.Type(), err)

				// For critical storage failures, we continue processing to avoid
				// blocking the event stream, but log the error for monitoring
				// In production, consider implementing:
				// - Metrics/alerting for storage failure rates
				// - Circuit breaker for persistent failures
				// - Backup storage mechanisms
			}

		case <-s.ctx.Done():
			return
		}
	}
}
