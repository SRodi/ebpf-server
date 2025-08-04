package bpf

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestManager(t *testing.T) {
	manager := NewManager()

	t.Run("Register and unregister programs", func(t *testing.T) {
		program1 := NewMockProgram("test1", "Test program 1", manager.GetStorage())
		program2 := NewMockProgram("test2", "Test program 2", manager.GetStorage())

		// Register programs
		if err := manager.RegisterProgram(program1); err != nil {
			t.Fatalf("Failed to register program1: %v", err)
		}

		if err := manager.RegisterProgram(program2); err != nil {
			t.Fatalf("Failed to register program2: %v", err)
		}

		// Test duplicate registration
		if err := manager.RegisterProgram(program1); err == nil {
			t.Error("Expected error when registering duplicate program")
		}

		// Test list programs
		programs := manager.ListPrograms()
		if len(programs) != 2 {
			t.Errorf("Expected 2 programs, got %d", len(programs))
		}

		// Test get program
		if prog, exists := manager.GetProgram("test1"); !exists || prog != program1 {
			t.Error("Failed to get registered program")
		}

		// Test unregister
		if err := manager.UnregisterProgram("test1"); err != nil {
			t.Fatalf("Failed to unregister program: %v", err)
		}

		programs = manager.ListPrograms()
		if len(programs) != 1 {
			t.Errorf("Expected 1 program after unregister, got %d", len(programs))
		}

		// Test unregister non-existent
		if err := manager.UnregisterProgram("nonexistent"); err == nil {
			t.Error("Expected error when unregistering non-existent program")
		}
	})

	t.Run("Load, attach, and start programs", func(t *testing.T) {
		manager := NewManager() // Fresh manager
		program := NewMockProgram("test", "Test program", manager.GetStorage())

		if err := manager.RegisterProgram(program); err != nil {
			t.Fatalf("Failed to register program: %v", err)
		}

		// Test load all
		if err := manager.LoadAll(); err != nil {
			t.Fatalf("Failed to load programs: %v", err)
		}

		// Test attach all
		if err := manager.AttachAll(); err != nil {
			t.Fatalf("Failed to attach programs: %v", err)
		}

		// Test start all
		if err := manager.StartAll(); err != nil {
			t.Fatalf("Failed to start programs: %v", err)
		}

		// Verify program state
		if !program.loaded {
			t.Error("Program should be loaded")
		}
		if !program.attached {
			t.Error("Program should be attached")
		}
		if !program.running {
			t.Error("Program should be running")
		}

		// Test stop all
		if err := manager.StopAll(); err != nil {
			t.Fatalf("Failed to stop programs: %v", err)
		}

		if program.running {
			t.Error("Program should be stopped")
		}
	})

	t.Run("Error handling", func(t *testing.T) {
		manager := NewManager()
		program := NewMockProgram("test", "Test program", manager.GetStorage())

		// Set up program to fail at different stages
		loadErr := errors.New("load failed")
		attachErr := errors.New("attach failed")
		startErr := errors.New("start failed")

		program.SetErrors(loadErr, attachErr, startErr)
		if err := manager.RegisterProgram(program); err != nil {
			t.Fatalf("Failed to register program: %v", err)
		}

		// Test load failure
		if err := manager.LoadAll(); err == nil {
			t.Error("Expected load error")
		}

		// Reset errors and test attach failure
		program.SetErrors(nil, attachErr, startErr)
		if err := manager.LoadAll(); err != nil {
			t.Fatalf("Load should succeed: %v", err)
		}
		if err := manager.AttachAll(); err == nil {
			t.Error("Expected attach error")
		}

		// Reset errors and test start failure
		program.SetErrors(nil, nil, startErr)
		if err := manager.AttachAll(); err != nil {
			t.Fatalf("Attach should succeed: %v", err)
		}
		if err := manager.StartAll(); err == nil {
			t.Error("Expected start error")
		}
	})

	t.Run("Event aggregation", func(t *testing.T) {
		manager := NewManager()
		program1 := NewMockProgram("test1", "Test program 1", manager.GetStorage())
		program2 := NewMockProgram("test2", "Test program 2", manager.GetStorage())

		if err := manager.RegisterProgram(program1); err != nil {
			t.Fatalf("Failed to register program1: %v", err)
		}

		if err := manager.RegisterProgram(program2); err != nil {
			t.Fatalf("Failed to register program2: %v", err)
		}

		// Load, attach, and start programs
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
		event1 := &MockEvent{
			BaseEvent: BaseEvent{PID: 1234, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'t', 'e', 's', 't', '1'}},
			eventType: "test1",
		}
		event2 := &MockEvent{
			BaseEvent: BaseEvent{PID: 5678, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'t', 'e', 's', 't', '2'}},
			eventType: "test2",
		}

		// Send events from programs
		program1.SendEvent(event1)
		program2.SendEvent(event2)

		// Collect events from aggregated channel
		aggregatedChan := manager.GetAggregatedEvents()

		receivedEvents := make([]BPFEvent, 0, 2)
		timeout := time.After(2 * time.Second)

		// Collect events with timeout
		for len(receivedEvents) < 2 {
			select {
			case event := <-aggregatedChan:
				receivedEvents = append(receivedEvents, event)
			case <-timeout:
				t.Fatalf("Timeout waiting for events, got %d events", len(receivedEvents))
			}
		}

		// Verify we received both events
		if len(receivedEvents) != 2 {
			t.Errorf("Expected 2 aggregated events, got %d", len(receivedEvents))
		}

		// Stop manager
		if err := manager.StopAll(); err != nil {
			t.Fatalf("Failed to stop manager: %v", err)
		}
	})

	t.Run("IsAvailable", func(t *testing.T) {
		manager := NewManager()
		// On macOS, this should return false
		// On Linux with eBPF support, this should return true
		// We can't test the actual return value since it depends on the system
		available := manager.IsAvailable()
		t.Logf("eBPF available: %v", available)
	})
}

func TestManagerConcurrency(t *testing.T) {
	manager := NewManager()

	// Test concurrent program registration
	t.Run("Concurrent registration", func(t *testing.T) {
		const numPrograms = 10
		done := make(chan bool, numPrograms)

		for i := 0; i < numPrograms; i++ {
			go func(id int) {
				program := NewMockProgram(
					fmt.Sprintf("concurrent%d", id),
					fmt.Sprintf("Concurrent program %d", id),
					manager.GetStorage(),
				)
				err := manager.RegisterProgram(program)
				if err != nil {
					t.Errorf("Failed to register program %d: %v", id, err)
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numPrograms; i++ {
			<-done
		}

		programs := manager.ListPrograms()
		if len(programs) != numPrograms {
			t.Errorf("Expected %d programs, got %d", numPrograms, len(programs))
		}
	})
}

func TestManagerLifecycle(t *testing.T) {
	t.Run("Complete lifecycle", func(t *testing.T) {
		manager := NewManager()
		program := NewMockProgram("lifecycle", "Lifecycle test program", manager.GetStorage())

		// Register
		if err := manager.RegisterProgram(program); err != nil {
			t.Fatalf("Failed to register: %v", err)
		}

		// Load
		if err := manager.LoadAll(); err != nil {
			t.Fatalf("Failed to load: %v", err)
		}

		// Attach
		if err := manager.AttachAll(); err != nil {
			t.Fatalf("Failed to attach: %v", err)
		}

		// Start
		if err := manager.StartAll(); err != nil {
			t.Fatalf("Failed to start: %v", err)
		}

		// Verify running state
		if !manager.running {
			t.Error("Manager should be running")
		}

		// Test double start (should fail)
		if err := manager.StartAll(); err == nil {
			t.Error("Expected error on double start")
		}

		// Send some events
		event := &MockEvent{
			BaseEvent: BaseEvent{PID: 1111, TS: uint64(time.Now().UnixNano()), Comm: [16]byte{'t', 'e', 's', 't'}},
			eventType: "lifecycle",
		}
		program.SendEvent(event)

		// Wait a bit for event processing
		time.Sleep(100 * time.Millisecond)

		// Stop
		if err := manager.StopAll(); err != nil {
			t.Fatalf("Failed to stop: %v", err)
		}

		// Verify stopped state
		if manager.running {
			t.Error("Manager should be stopped")
		}

		// Test double stop (should be safe)
		if err := manager.StopAll(); err != nil {
			t.Errorf("Double stop should be safe: %v", err)
		}
	})
}
