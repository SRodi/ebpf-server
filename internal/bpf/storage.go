package bpf

import (
	"strings"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

// InMemoryStorage implements EventStorage using in-memory maps
type InMemoryStorage struct {
	mu     sync.RWMutex
	events map[string]map[uint32][]BPFEvent // eventType -> PID -> []BPFEvent
}

// NewInMemoryStorage creates a new in-memory event storage
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		events: make(map[string]map[uint32][]BPFEvent),
	}
}

// Store adds an event to storage
func (s *InMemoryStorage) Store(event BPFEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	eventType := event.GetEventType()
	pid := event.GetPID()

	// Initialize event type map if it doesn't exist
	if s.events[eventType] == nil {
		s.events[eventType] = make(map[uint32][]BPFEvent)
	}

	// Add event to the appropriate slice
	s.events[eventType][pid] = append(s.events[eventType][pid], event)

	return nil
}

// Helper methods for time and command filtering
func (s *InMemoryStorage) matchesTimeFilter(event BPFEvent, since time.Time) bool {
	if since.IsZero() {
		return true // No time filter
	}
	
	// Convert event timestamp to wall clock time
	eventTime := event.GetWallClockTime()
	return eventTime.After(since) || eventTime.Equal(since)
}

func (s *InMemoryStorage) matchesCommandFilter(event BPFEvent, command string) bool {
	if command == "" {
		return true // No command filter
	}
	return strings.Contains(strings.ToLower(event.GetCommand()), strings.ToLower(command))
}

// GetByPID retrieves events for a specific PID within a time window
func (s *InMemoryStorage) GetByPID(pid uint32, since time.Time) ([]BPFEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []BPFEvent

	for _, pidMap := range s.events {
		if events, exists := pidMap[pid]; exists {
			for _, event := range events {
				if s.matchesTimeFilter(event, since) {
					result = append(result, event)
				}
			}
		}
	}

	return result, nil
}

// GetByCommand retrieves events for processes matching a command name
func (s *InMemoryStorage) GetByCommand(command string, since time.Time) ([]BPFEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []BPFEvent
	commandLower := strings.ToLower(command)

	for _, pidMap := range s.events {
		for _, events := range pidMap {
			for _, event := range events {
				if s.matchesTimeFilter(event, since) &&
					strings.Contains(strings.ToLower(event.GetCommand()), commandLower) {
					result = append(result, event)
				}
			}
		}
	}

	return result, nil
}

// GetByType retrieves events of a specific type within a time window
func (s *InMemoryStorage) GetByType(eventType string, since time.Time) ([]BPFEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []BPFEvent

	if pidMap, exists := s.events[eventType]; exists {
		for _, events := range pidMap {
			for _, event := range events {
				if s.matchesTimeFilter(event, since) {
					result = append(result, event)
				}
			}
		}
	}

	return result, nil
}

// Count returns the number of events matching the criteria
func (s *InMemoryStorage) Count(pid uint32, command string, eventType string, since time.Time) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0

	// Determine which event types to search
	eventTypes := []string{}
	if eventType != "" {
		eventTypes = append(eventTypes, eventType)
	} else {
		for et := range s.events {
			eventTypes = append(eventTypes, et)
		}
	}

	for _, et := range eventTypes {
		pidMap, exists := s.events[et]
		if !exists {
			continue
		}

		// Search strategy based on criteria
		if command != "" {
			// Search by command across all PIDs
			for _, events := range pidMap {
				for _, event := range events {
					if s.matchesTimeFilter(event, since) && s.matchesCommandFilter(event, command) {
						count++
					}
				}
			}
		} else if pid != 0 {
			// Search by specific PID
			if events, exists := pidMap[pid]; exists {
				for _, event := range events {
					if s.matchesTimeFilter(event, since) {
						count++
					}
				}
			}
		} else {
			// Count all events in time window
			for _, events := range pidMap {
				for _, event := range events {
					if s.matchesTimeFilter(event, since) {
						count++
					}
				}
			}
		}
	}

	return count
}

// GetAll returns all stored events (for debugging)
func (s *InMemoryStorage) GetAll() map[string]map[uint32][]BPFEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a deep copy to avoid race conditions
	result := make(map[string]map[uint32][]BPFEvent)
	for eventType, pidMap := range s.events {
		result[eventType] = make(map[uint32][]BPFEvent)
		for pid, events := range pidMap {
			eventsCopy := make([]BPFEvent, len(events))
			copy(eventsCopy, events)
			result[eventType][pid] = eventsCopy
		}
	}

	return result
}

// Cleanup removes old events to prevent memory leaks
func (s *InMemoryStorage) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoffTime := time.Now().Add(-maxAge)
	removed := 0

	for eventType, pidMap := range s.events {
		for pid, events := range pidMap {
			newEvents := make([]BPFEvent, 0, len(events))
			for _, event := range events {
				eventTime := event.GetWallClockTime()
				if eventTime.After(cutoffTime) || eventTime.Equal(cutoffTime) {
					newEvents = append(newEvents, event)
				} else {
					removed++
				}
			}
			
			if len(newEvents) == 0 {
				delete(pidMap, pid)
			} else {
				pidMap[pid] = newEvents
			}
		}
		
		// Remove empty event type maps
		if len(pidMap) == 0 {
			delete(s.events, eventType)
		}
	}

	if removed > 0 {
		logger.Infof("Event storage cleanup: removed %d old events", removed)
	}

	return removed
}
