package bpf

import (
	"testing"
	"time"
)

func TestInMemoryStorage(t *testing.T) {
	storage := NewInMemoryStorage()

	// Create test events
	event1 := &MockEvent{
		BaseEvent: BaseEvent{PID: 1234, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'t', 'e', 's', 't', '1'}},
		eventType: "test_type",
	}
	event2 := &MockEvent{
		BaseEvent: BaseEvent{PID: 1234, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'t', 'e', 's', 't', '2'}},
		eventType: "test_type",
	}
	event3 := &MockEvent{
		BaseEvent: BaseEvent{PID: 5678, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'o', 't', 'h', 'e', 'r'}},
		eventType: "other_type",
	}

	t.Run("Store and retrieve events", func(t *testing.T) {
		// Store events
		if err := storage.Store(event1); err != nil {
			t.Fatalf("Failed to store event1: %v", err)
		}
		if err := storage.Store(event2); err != nil {
			t.Fatalf("Failed to store event2: %v", err)
		}
		if err := storage.Store(event3); err != nil {
			t.Fatalf("Failed to store event3: %v", err)
		}

		// Test GetByPID
		events, err := storage.GetByPID(1234, time.Now().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("Failed to get events by PID: %v", err)
		}
		if len(events) != 2 {
			t.Errorf("Expected 2 events for PID 1234, got %d", len(events))
		}

		// Test GetByCommand
		events, err = storage.GetByCommand("test", time.Now().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("Failed to get events by command: %v", err)
		}
		if len(events) != 2 {
			t.Errorf("Expected 2 events for command 'test', got %d", len(events))
		}

		// Test GetByType
		events, err = storage.GetByType("test_type", time.Now().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("Failed to get events by type: %v", err)
		}
		if len(events) != 2 {
			t.Errorf("Expected 2 events for type 'test_type', got %d", len(events))
		}
	})

	t.Run("Count events", func(t *testing.T) {
		// Count by PID
		count := storage.Count(1234, "", "", time.Now().Add(-1*time.Hour))
		if count != 2 {
			t.Errorf("Expected count 2 for PID 1234, got %d", count)
		}

		// Count by command
		count = storage.Count(0, "test", "", time.Now().Add(-1*time.Hour))
		if count != 2 {
			t.Errorf("Expected count 2 for command 'test', got %d", count)
		}

		// Count by type
		count = storage.Count(0, "", "test_type", time.Now().Add(-1*time.Hour))
		if count != 2 {
			t.Errorf("Expected count 2 for type 'test_type', got %d", count)
		}

		// Count all
		count = storage.Count(0, "", "", time.Now().Add(-1*time.Hour))
		if count != 3 {
			t.Errorf("Expected count 3 for all events, got %d", count)
		}
	})

	t.Run("GetAll events", func(t *testing.T) {
		allEvents := storage.GetAll()
		if len(allEvents) != 2 {
			t.Errorf("Expected 2 event types, got %d", len(allEvents))
		}

		testTypeEvents, exists := allEvents["test_type"]
		if !exists {
			t.Error("Expected test_type events to exist")
		} else if len(testTypeEvents[1234]) != 2 {
			t.Errorf("Expected 2 test_type events for PID 1234, got %d", len(testTypeEvents[1234]))
		}
	})

	t.Run("Cleanup old events", func(t *testing.T) {
		// Add an old event (simulate by setting timestamp that converts to old wall clock time)
		// Calculate a timestamp that would result in an old wall clock time
		bootTime := GetSystemBootTime()
		twoHoursAgo := time.Now().Add(-2 * time.Hour)
		oldTimestamp := uint64(twoHoursAgo.Sub(bootTime).Nanoseconds())
		
		oldEvent := &MockEvent{
			BaseEvent: BaseEvent{PID: 9999, TS: oldTimestamp, Comm: [16]byte{'o', 'l', 'd'}},
			eventType: "old_type",
		}
		storage.Store(oldEvent)

		// Cleanup events older than 1 hour
		removed := storage.Cleanup(1 * time.Hour)
		if removed != 1 {
			t.Errorf("Expected to remove 1 old event, removed %d", removed)
		}

		// Verify old event was removed
		count := storage.Count(9999, "", "", time.Time{})
		if count != 0 {
			t.Errorf("Expected old event to be cleaned up, but count is %d", count)
		}
	})
}

func TestStorageTimeFiltering(t *testing.T) {
	storage := NewInMemoryStorage()

	now := time.Now()
	bootTime := GetSystemBootTime()
	
	// Create events with different timestamps relative to boot time
	recentTimestamp := uint64(now.Sub(bootTime).Nanoseconds())
	oldTimestamp := uint64(now.Add(-2*time.Hour).Sub(bootTime).Nanoseconds())
	
	recentEvent := &MockEvent{
		BaseEvent: BaseEvent{PID: 1111, TS: recentTimestamp, Comm: [16]byte{'r', 'e', 'c', 'e', 'n', 't'}},
		eventType: "test",
	}
	
	oldEvent := &MockEvent{
		BaseEvent: BaseEvent{PID: 2222, TS: oldTimestamp, Comm: [16]byte{'o', 'l', 'd'}},
		eventType: "test",
	}

	storage.Store(recentEvent)
	storage.Store(oldEvent)

	t.Run("Filter by time window", func(t *testing.T) {
		// Get events from last hour (should only include recent event)
		events, err := storage.GetByType("test", now.Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("Failed to get events: %v", err)
		}

		if len(events) != 1 {
			t.Errorf("Expected 1 recent event, got %d", len(events))
		}

		if len(events) > 0 && events[0].GetPID() != 1111 {
			t.Errorf("Expected recent event PID 1111, got %d", events[0].GetPID())
		}
	})

	t.Run("Count with time filter", func(t *testing.T) {
		// Count recent events only
		count := storage.Count(0, "", "test", now.Add(-1*time.Hour))
		if count != 1 {
			t.Errorf("Expected 1 recent event, got %d", count)
		}

		// Count all events (no time filter)
		count = storage.Count(0, "", "test", time.Time{})
		if count != 2 {
			t.Errorf("Expected 2 total events, got %d", count)
		}
	})
}
