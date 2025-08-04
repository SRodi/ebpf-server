package bpf

import (
	"testing"
	"time"
)

func TestLoaderBackwardCompatibility(t *testing.T) {
	// Save the original global manager state
	originalManager := globalManager
	defer func() {
		globalManager = originalManager
	}()

	t.Run("Functions work without initialization", func(t *testing.T) {
		// Reset global manager to nil
		globalManager = nil

		// These should not panic and return sensible defaults
		if GetConnectionSummary(1234, "", 60) != 0 {
			t.Error("GetConnectionSummary should return 0 when not initialized")
		}

		if GetPacketDropSummary(1234, "", 60) != 0 {
			t.Error("GetPacketDropSummary should return 0 when not initialized")
		}

		connections := GetAllConnections()
		if len(connections) != 0 {
			t.Error("GetAllConnections should return empty when not initialized")
		}

		drops := GetAllPacketDrops()
		if len(drops) != 0 {
			t.Error("GetAllPacketDrops should return empty when not initialized")
		}

		available := IsAvailable()
		t.Logf("IsAvailable without manager: %v", available)
	})

	t.Run("Functions work with mock manager", func(t *testing.T) {
		// Create a mock manager with test programs
		globalManager = NewManager()
		storage := globalManager.GetStorage()

		// Create wrapper programs that implement the interface
		connectionWrapper := &connectionProgramWrapper{storage: storage}
		dropWrapper := &packetDropProgramWrapper{storage: storage}

		globalManager.RegisterProgram(connectionWrapper)
		globalManager.RegisterProgram(dropWrapper)

		// Store some test events
		now := time.Now()
		
		// Create mock connection event
		connEvent := &Event{
			PID:      1234,
			TS:       uint64(now.UnixNano()),
			Ret:      0,
			Comm:     [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			DestIPv4: 0x0100007f, // 127.0.0.1
			DestPort: 8080,
			Family:   2, // AF_INET
			Protocol: 6, // TCP
		}

		// Create mock drop event  
		dropEvent := &DropEvent{
			PID:        1234,
			TS:         uint64(now.UnixNano()),
			Comm:       [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			DropReason: 1,
			SkbLen:     1500,
		}

		// Store events through the wrappers
		connectionWrapper.storage.Store(&connectionEventWrapper{Event: *connEvent})
		dropWrapper.storage.Store(&packetDropEventWrapper{DropEvent: *dropEvent})

		// Test the backward compatibility functions
		connSummary := GetConnectionSummary(1234, "", 60)
		if connSummary != 1 {
			t.Errorf("Expected 1 connection, got %d", connSummary)
		}

		dropSummary := GetPacketDropSummary(1234, "", 60)
		if dropSummary != 1 {
			t.Errorf("Expected 1 packet drop, got %d", dropSummary)
		}

		// Test command-based queries
		connSummaryByCmd := GetConnectionSummary(0, "curl", 60)
		if connSummaryByCmd != 1 {
			t.Errorf("Expected 1 connection for 'curl', got %d", connSummaryByCmd)
		}

		dropSummaryByCmd := GetPacketDropSummary(0, "curl", 60)
		if dropSummaryByCmd != 1 {
			t.Errorf("Expected 1 packet drop for 'curl', got %d", dropSummaryByCmd)
		}

		// Test GetAllConnections
		allConnections := GetAllConnections()
		if len(allConnections) != 1 || len(allConnections[1234]) != 1 {
			t.Errorf("Expected 1 connection for PID 1234, got %v", allConnections)
		}

		// Test GetAllPacketDrops
		allDrops := GetAllPacketDrops()
		if len(allDrops) != 1 || len(allDrops[1234]) != 1 {
			t.Errorf("Expected 1 packet drop for PID 1234, got %v", allDrops)
		}

		// Verify the returned events have correct data
		if connEvent := allConnections[1234][0]; connEvent.GetCommand() != "curl" {
			t.Errorf("Expected command 'curl', got '%s'", connEvent.GetCommand())
		}

		if dropEventRet := allDrops[1234][0]; dropEventRet.GetCommand() != "curl" {
			t.Errorf("Expected command 'curl', got '%s'", dropEventRet.GetCommand())
		}
	})

	t.Run("GetManager returns global manager", func(t *testing.T) {
		manager := GetManager()
		if manager != globalManager {
			t.Error("GetManager should return the global manager")
		}
	})
}

func TestLoaderInitialization(t *testing.T) {
	t.Run("IsAvailable works independently", func(t *testing.T) {
		// Should work even without global manager
		available := IsAvailable()
		t.Logf("eBPF availability: %v", available)
		
		// Should not panic
		if available {
			t.Log("eBPF is available on this system")
		} else {
			t.Log("eBPF is not available on this system (expected on macOS)")
		}
	})
}

// Test the wrapper event types used for backward compatibility
func TestWrapperEvents(t *testing.T) {
	t.Run("Connection event wrapper", func(t *testing.T) {
		event := Event{
			PID:  1234,
			TS:   uint64(time.Now().UnixNano()),
			Comm: [16]byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		}

		wrapper := &connectionEventWrapper{Event: event}

		if wrapper.GetPID() != 1234 {
			t.Errorf("Expected PID 1234, got %d", wrapper.GetPID())
		}

		if wrapper.GetCommand() != "test" {
			t.Errorf("Expected command 'test', got '%s'", wrapper.GetCommand())
		}

		if wrapper.GetEventType() != "connection" {
			t.Errorf("Expected event type 'connection', got '%s'", wrapper.GetEventType())
		}
	})

	t.Run("Packet drop event wrapper", func(t *testing.T) {
		event := DropEvent{
			PID:        5678,
			TS:         uint64(time.Now().UnixNano()),
			Comm:       [16]byte{'d', 'r', 'o', 'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			DropReason: 1,
		}

		wrapper := &packetDropEventWrapper{DropEvent: event}

		if wrapper.GetPID() != 5678 {
			t.Errorf("Expected PID 5678, got %d", wrapper.GetPID())
		}

		if wrapper.GetCommand() != "drop" {
			t.Errorf("Expected command 'drop', got '%s'", wrapper.GetCommand())
		}

		if wrapper.GetEventType() != "packet_drop" {
			t.Errorf("Expected event type 'packet_drop', got '%s'", wrapper.GetEventType())
		}
	})
}

func TestProgramWrappers(t *testing.T) {
	storage := NewInMemoryStorage()

	t.Run("Connection program wrapper", func(t *testing.T) {
		wrapper := &connectionProgramWrapper{storage: storage}

		if wrapper.GetName() != "connection" {
			t.Errorf("Expected name 'connection', got '%s'", wrapper.GetName())
		}

		if wrapper.GetDescription() == "" {
			t.Error("Description should not be empty")
		}

		if wrapper.GetObjectPath() != "bpf/connection.o" {
			t.Errorf("Expected object path 'bpf/connection.o', got '%s'", wrapper.GetObjectPath())
		}

		// Test that it doesn't support actual eBPF operations (since we're mocking)
		if err := wrapper.Load(); err == nil {
			t.Error("Mock wrapper Load should fail")
		}
	})

	t.Run("Packet drop program wrapper", func(t *testing.T) {
		wrapper := &packetDropProgramWrapper{storage: storage}

		if wrapper.GetName() != "packet_drop" {
			t.Errorf("Expected name 'packet_drop', got '%s'", wrapper.GetName())
		}

		if wrapper.GetDescription() == "" {
			t.Error("Description should not be empty")
		}

		if wrapper.GetObjectPath() != "bpf/packet_drop.o" {
			t.Errorf("Expected object path 'bpf/packet_drop.o', got '%s'", wrapper.GetObjectPath())
		}
	})
}
