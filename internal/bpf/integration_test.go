package bpf

import (
	"testing"
	"time"
)

func TestIntegration(t *testing.T) {
	t.Run("Full system integration", func(t *testing.T) {
		// Create manager and storage
		manager := NewManager()
		storage := manager.GetStorage()

		// Create and register mock programs
		connectionProg := NewMockProgram("connection", "Connection monitoring", storage)
		packetDropProg := NewMockProgram("packet_drop", "Packet drop monitoring", storage)

		if err := manager.RegisterProgram(connectionProg); err != nil {
			t.Fatalf("Failed to register connection program: %v", err)
		}

		if err := manager.RegisterProgram(packetDropProg); err != nil {
			t.Fatalf("Failed to register packet drop program: %v", err)
		}

		// Load, attach, and start all programs
		if err := manager.LoadAll(); err != nil {
			t.Fatalf("Failed to load programs: %v", err)
		}

		if err := manager.AttachAll(); err != nil {
			t.Fatalf("Failed to attach programs: %v", err)
		}

		if err := manager.StartAll(); err != nil {
			t.Fatalf("Failed to start programs: %v", err)
		}

		// Create test events
		now := time.Now()
		bootTime := GetSystemBootTime()
		timestamp := uint64(now.Sub(bootTime).Nanoseconds())
		
		connectionEvent := &MockEvent{
			BaseEvent: BaseEvent{
				PID:  1234,
				TS:   timestamp,
				Comm: [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			eventType: "connection",
		}

		packetDropEvent := &MockEvent{
			BaseEvent: BaseEvent{
				PID:  1234,
				TS:   timestamp,
				Comm: [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			eventType: "packet_drop",
		}

		// Send events from programs
		connectionProg.SendEvent(connectionEvent)
		packetDropProg.SendEvent(packetDropEvent)

		// Wait for events to be processed
		time.Sleep(100 * time.Millisecond)

		// Test storage contains events
		allEvents := storage.GetAll()
		if len(allEvents) != 2 {
			t.Errorf("Expected 2 event types in storage, got %d", len(allEvents))
		}

		// Test program summaries
		connectionSummary := connectionProg.GetSummary(1234, "", 60)
		if connectionSummary != 1 {
			t.Errorf("Expected 1 connection event, got %d", connectionSummary)
		}

		packetDropSummary := packetDropProg.GetSummary(1234, "", 60)
		if packetDropSummary != 1 {
			t.Errorf("Expected 1 packet drop event, got %d", packetDropSummary)
		}

		// Test aggregated events
		aggregatedChan := manager.GetAggregatedEvents()
		receivedEvents := 0
		timeout := time.After(1 * time.Second)

		// Collect any remaining events from aggregated channel
		for receivedEvents < 2 {
			select {
			case <-aggregatedChan:
				receivedEvents++
			case <-timeout:
				// Timeout is acceptable since events might have been processed already
				break
			}
		}

		// Test querying by command
		connectionEvents, err := storage.GetByCommand("curl", now.Add(-1*time.Minute))
		if err != nil {
			t.Fatalf("Failed to get events by command: %v", err)
		}
		if len(connectionEvents) != 2 {
			t.Errorf("Expected 2 events for 'curl' command, got %d", len(connectionEvents))
		}

		// Test querying by PID
		pidEvents, err := storage.GetByPID(1234, now.Add(-1*time.Minute))
		if err != nil {
			t.Fatalf("Failed to get events by PID: %v", err)
		}
		if len(pidEvents) != 2 {
			t.Errorf("Expected 2 events for PID 1234, got %d", len(pidEvents))
		}

		// Test querying by type
		dropEvents, err := storage.GetByType("packet_drop", now.Add(-1*time.Minute))
		if err != nil {
			t.Fatalf("Failed to get events by type: %v", err)
		}
		if len(dropEvents) != 1 {
			t.Errorf("Expected 1 packet drop event, got %d", len(dropEvents))
		}

		// Clean shutdown
		if err := manager.StopAll(); err != nil {
			t.Fatalf("Failed to stop manager: %v", err)
		}
	})

	t.Run("Backward compatibility", func(t *testing.T) {
		// Test that the old API functions still work
		
		// Before initializing, these should return 0 or empty
		if GetConnectionSummary(1234, "", 60) != 0 {
			t.Error("GetConnectionSummary should return 0 when not initialized")
		}

		if GetPacketDropSummary(1234, "", 60) != 0 {
			t.Error("GetPacketDropSummary should return 0 when not initialized")
		}

		allConnections := GetAllConnections()
		if len(allConnections) != 0 {
			t.Error("GetAllConnections should return empty map when not initialized")
		}

		allDrops := GetAllPacketDrops()
		if len(allDrops) != 0 {
			t.Error("GetAllPacketDrops should return empty map when not initialized")
		}

		// Test IsAvailable
		available := IsAvailable()
		t.Logf("eBPF available (backward compatibility): %v", available)
	})
}

func TestStorageCleanup(t *testing.T) {
	t.Run("Automatic cleanup", func(t *testing.T) {
		manager := NewManager()
		storage := manager.GetStorage()

		// Add old events (simulate old timestamps)
		now := time.Now()
		bootTime := GetSystemBootTime()
		oldTime := now.Add(-2 * time.Hour)
		oldTimestamp := uint64(oldTime.Sub(bootTime).Nanoseconds())
		recentTimestamp := uint64(now.Sub(bootTime).Nanoseconds())
		
		oldEvent := &MockEvent{
			BaseEvent: BaseEvent{
				PID:  9999,
				TS:   oldTimestamp,
				Comm: [16]byte{'o', 'l', 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			eventType: "old_test",
		}

		recentEvent := &MockEvent{
			BaseEvent: BaseEvent{
				PID:  1111,
				TS:   recentTimestamp,
				Comm: [16]byte{'n', 'e', 'w', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			eventType: "new_test",
		}

		if err := storage.Store(oldEvent); err != nil {
			t.Fatalf("Failed to store old event: %v", err)
		}
		if err := storage.Store(recentEvent); err != nil {
			t.Fatalf("Failed to store recent event: %v", err)
		}

		// Verify both events are stored
		if storage.Count(0, "", "", time.Time{}) != 2 {
			t.Error("Expected 2 events before cleanup")
		}

		// Manual cleanup with 1 hour threshold
		removed := storage.Cleanup(1 * time.Hour)
		if removed != 1 {
			t.Errorf("Expected to remove 1 old event, removed %d", removed)
		}

		// Verify only recent event remains
		if storage.Count(0, "", "", time.Time{}) != 1 {
			t.Error("Expected 1 event after cleanup")
		}

		// Verify it's the correct event
		newEvents, err := storage.GetByType("new_test", time.Time{})
		if err != nil {
			t.Fatalf("Failed to get new_test events: %v", err)
		}
		if len(newEvents) != 1 {
			t.Error("Expected new event to remain after cleanup")
		}

		oldEvents, err := storage.GetByType("old_test", time.Time{})
		if err != nil {
			t.Fatalf("Failed to get old_test events: %v", err)
		}
		if len(oldEvents) != 0 {
			t.Error("Expected old event to be removed after cleanup")
		}
	})
}

func TestErrorScenarios(t *testing.T) {
	t.Run("Program registration errors", func(t *testing.T) {
		manager := NewManager()
		program := NewMockProgram("test", "Test program", manager.GetStorage())

		// Register program
		if err := manager.RegisterProgram(program); err != nil {
			t.Fatalf("Failed to register program: %v", err)
		}

		// Try to register same program again
		if err := manager.RegisterProgram(program); err == nil {
			t.Error("Expected error when registering duplicate program")
		}

		// Try to unregister non-existent program
		if err := manager.UnregisterProgram("nonexistent"); err == nil {
			t.Error("Expected error when unregistering non-existent program")
		}
	})

	t.Run("Program lifecycle errors", func(t *testing.T) {
		manager := NewManager()
		program := NewMockProgram("error_test", "Error test program", manager.GetStorage())

		// Set program to fail at attach stage
		program.SetErrors(nil, ErrProgramNotLoaded, nil)
		if err := manager.RegisterProgram(program); err != nil {
			t.Fatalf("Failed to register program: %v", err)
		}

		// Load should succeed
		if err := manager.LoadAll(); err != nil {
			t.Fatalf("Load should succeed: %v", err)
		}

		// Attach should fail
		if err := manager.AttachAll(); err == nil {
			t.Error("Expected attach to fail")
		}
	})

	t.Run("Manager state errors", func(t *testing.T) {
		manager := NewManager()

		// Try to start without any programs
		if err := manager.StartAll(); err != nil {
			t.Fatalf("Starting with no programs should succeed: %v", err)
		}

		// Try to start again (should fail)
		if err := manager.StartAll(); err == nil {
			t.Error("Expected error when starting already running manager")
		}

		// Stop should succeed
		if err := manager.StopAll(); err != nil {
			t.Fatalf("Stop should succeed: %v", err)
		}

		// Stop again should be safe
		if err := manager.StopAll(); err != nil {
			t.Errorf("Double stop should be safe: %v", err)
		}
	})
}
