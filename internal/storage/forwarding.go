package storage

import (
	"context"

	"github.com/srodi/ebpf-server/internal/client"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ForwardingStorage wraps another storage and forwards events to an aggregator.
type ForwardingStorage struct {
	primary           core.EventSink
	aggregatorClient  *client.AggregatorClient
}

// NewForwardingStorage creates a new forwarding storage.
func NewForwardingStorage(primary core.EventSink, aggregatorClient *client.AggregatorClient) *ForwardingStorage {
	return &ForwardingStorage{
		primary:          primary,
		aggregatorClient: aggregatorClient,
	}
}

// Store saves an event to primary storage and forwards to aggregator.
func (s *ForwardingStorage) Store(ctx context.Context, event core.Event) error {
	// Store in primary storage
	if err := s.primary.Store(ctx, event); err != nil {
		return err
	}

	// Forward to aggregator if enabled
	if s.aggregatorClient != nil && s.aggregatorClient.IsEnabled() {
		if err := s.aggregatorClient.SendEvent(ctx, event); err != nil {
			logger.Debugf("Failed to forward event to aggregator: %v", err)
			// Don't return error - primary storage succeeded
		}
	}

	return nil
}

// Query delegates to primary storage.
func (s *ForwardingStorage) Query(ctx context.Context, query core.Query) ([]core.Event, error) {
	return s.primary.Query(ctx, query)
}

// Count delegates to primary storage.
func (s *ForwardingStorage) Count(ctx context.Context, query core.Query) (int, error) {
	return s.primary.Count(ctx, query)
}
