package connection

import (
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/bpf"
)

func TestConnectionEvent(t *testing.T) {
	t.Run("Event creation and methods", func(t *testing.T) {
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			Ret:      0,
			DestIPv4: 0x0100007f, // 127.0.0.1 in little-endian
			DestPort: 8080,
			Family:   2, // AF_INET
			Protocol: 6, // IPPROTO_TCP
			SockType: 1, // SOCK_STREAM
		}

		// Test basic getters
		if event.GetPID() != 1234 {
			t.Errorf("Expected PID 1234, got %d", event.GetPID())
		}

		if event.GetCommand() != "curl" {
			t.Errorf("Expected command 'curl', got '%s'", event.GetCommand())
		}

		if event.GetEventType() != "connection" {
			t.Errorf("Expected event type 'connection', got '%s'", event.GetEventType())
		}

		// Test IP address parsing
		destIP := event.GetDestIP()
		if destIP != "127.0.0.1" {
			t.Errorf("Expected destination IP '127.0.0.1', got '%s'", destIP)
		}

		// Test destination formatting
		dest := event.GetDestination()
		if dest != "127.0.0.1:8080" {
			t.Errorf("Expected destination '127.0.0.1:8080', got '%s'", dest)
		}

		// Test protocol parsing
		protocol := event.GetProtocol()
		if protocol != "TCP" {
			t.Errorf("Expected protocol 'TCP', got '%s'", protocol)
		}

		// Test socket type parsing
		sockType := event.GetSocketType()
		if sockType != "STREAM" {
			t.Errorf("Expected socket type 'STREAM', got '%s'", sockType)
		}
	})

	t.Run("IPv6 event", func(t *testing.T) {
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  5678,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			DestIPv6: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // ::1
			DestPort: 9000,
			Family:   10, // AF_INET6
			Protocol: 17, // IPPROTO_UDP
			SockType: 2,  // SOCK_DGRAM
		}

		// Test IPv6 address parsing
		destIP := event.GetDestIP()
		if destIP != "::1" {
			t.Errorf("Expected destination IP '::1', got '%s'", destIP)
		}

		// Test IPv6 destination formatting (should have brackets)
		dest := event.GetDestination()
		if dest != "[::1]:9000" {
			t.Errorf("Expected destination '[::1]:9000', got '%s'", dest)
		}

		// Test UDP protocol
		protocol := event.GetProtocol()
		if protocol != "UDP" {
			t.Errorf("Expected protocol 'UDP', got '%s'", protocol)
		}

		// Test DGRAM socket type
		sockType := event.GetSocketType()
		if sockType != "DGRAM" {
			t.Errorf("Expected socket type 'DGRAM', got '%s'", sockType)
		}
	})

	t.Run("JSON marshaling", func(t *testing.T) {
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			Ret:      0,
			DestIPv4: 0x0100007f, // 127.0.0.1
			DestPort: 8080,
			Family:   2, // AF_INET
			Protocol: 6, // TCP
		}

		_, err := event.MarshalJSON()
		if err != nil {
			t.Errorf("JSON marshaling failed: %v", err)
		}
	})

	t.Run("Unknown protocol and socket type", func(t *testing.T) {
		event := &Event{
			Protocol: 255, // Unknown protocol
			SockType: 255, // Unknown socket type
		}

		if event.GetProtocol() != "Unknown" {
			t.Errorf("Expected 'Unknown' protocol, got '%s'", event.GetProtocol())
		}

		if event.GetSocketType() != "Unknown" {
			t.Errorf("Expected 'Unknown' socket type, got '%s'", event.GetSocketType())
		}
	})
}

func TestConnectionProgram(t *testing.T) {
	storage := bpf.NewInMemoryStorage()
	program := NewProgram(storage)

	t.Run("Program properties", func(t *testing.T) {
		if program.GetName() != "connection" {
			t.Errorf("Expected name 'connection', got '%s'", program.GetName())
		}

		if program.GetObjectPath() != "bpf/connection.o" {
			t.Errorf("Expected object path 'bpf/connection.o', got '%s'", program.GetObjectPath())
		}

		desc := program.GetDescription()
		if desc == "" {
			t.Error("Description should not be empty")
		}
	})

	t.Run("Program state", func(t *testing.T) {
		// Initial state
		if program.IsRunning() {
			t.Error("Program should not be running initially")
		}

		// Event channel should be available
		eventChan := program.GetEventChannel()
		if eventChan == nil {
			t.Error("Event channel should not be nil")
		}
	})

	t.Run("Summary and events", func(t *testing.T) {
		// Create and store a test event
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		}

		storage.Store(event)

		// Test summary
		summary := program.GetSummary(1234, "", 60)
		if summary != 1 {
			t.Errorf("Expected summary count 1, got %d", summary)
		}

		// Test get all events
		allEvents := program.GetAllEvents()
		if len(allEvents) == 0 {
			t.Error("Expected to get stored events")
		}
	})
}
