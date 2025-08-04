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

// GetByPID retrieves events for a specific PID within a time window
func (s *InMemoryStorage) GetByPID(pid uint32, since time.Time) ([]BPFEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []BPFEvent
	sinceNano := time.Since(GetSystemBootTime()).Nanoseconds() - time.Since(since).Nanoseconds()

	for _, pidMap := range s.events {
		if events, exists := pidMap[pid]; exists {
			for _, event := range events {
				if int64(event.GetTimestamp()) >= sinceNano {
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
	sinceNano := time.Since(GetSystemBootTime()).Nanoseconds() - time.Since(since).Nanoseconds()
	commandLower := strings.ToLower(command)

	for _, pidMap := range s.events {
		for _, events := range pidMap {
			for _, event := range events {
				if int64(event.GetTimestamp()) >= sinceNano &&
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
	sinceNano := time.Since(GetSystemBootTime()).Nanoseconds() - time.Since(since).Nanoseconds()

	if pidMap, exists := s.events[eventType]; exists {
		for _, events := range pidMap {
			for _, event := range events {
				if int64(event.GetTimestamp()) >= sinceNano {
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
	sinceNano := time.Since(GetSystemBootTime()).Nanoseconds() - time.Since(since).Nanoseconds()

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
			commandLower := strings.ToLower(command)
			for _, events := range pidMap {
				for _, event := range events {
					if int64(event.GetTimestamp()) >= sinceNano &&
						strings.Contains(strings.ToLower(event.GetCommand()), commandLower) {
						count++
					}
				}
			}
		} else if pid != 0 {
			// Search by specific PID
			if events, exists := pidMap[pid]; exists {
				for _, event := range events {
					if int64(event.GetTimestamp()) >= sinceNano {
						count++
					}
				}
			}
		} else {
			// Count all events in time window
			for _, events := range pidMap {
				for _, event := range events {
					if int64(event.GetTimestamp()) >= sinceNano {
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

	cutoffTime := time.Since(GetSystemBootTime()).Nanoseconds() - maxAge.Nanoseconds()
	removed := 0

	for eventType, pidMap := range s.events {
		for pid, events := range pidMap {
			newEvents := make([]BPFEvent, 0, len(events))
			for _, event := range events {
				if int64(event.GetTimestamp()) >= cutoffTime {
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
