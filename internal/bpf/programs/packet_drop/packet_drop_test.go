package packet_drop

import (
	"strings"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/bpf"
)

func TestPacketDropEvent(t *testing.T) {
	t.Run("Event creation and methods", func(t *testing.T) {
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'c', 'u', 'r', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			DropReason: 1,
			SkbLen:     1500,
		}

		// Test basic getters
		if event.GetPID() != 1234 {
			t.Errorf("Expected PID 1234, got %d", event.GetPID())
		}

		if event.GetCommand() != "curl" {
			t.Errorf("Expected command 'curl', got '%s'", event.GetCommand())
		}

		if event.GetEventType() != "packet_drop" {
			t.Errorf("Expected event type 'packet_drop', got '%s'", event.GetEventType())
		}

		// Test drop reason parsing
		reason := event.GetDropReasonString()
		if reason != "SKB_FREE" {
			t.Errorf("Expected drop reason 'SKB_FREE', got '%s'", reason)
		}
	})

	t.Run("Drop reason types", func(t *testing.T) {
		testCases := []struct {
			reason   uint32
			expected string
		}{
			{1, "SKB_FREE"},
			{2, "TCP_DROP"},
			{999, "UNKNOWN(999)"},
		}

		for _, tc := range testCases {
			event := &Event{DropReason: tc.reason}
			actual := event.GetDropReasonString()
			if actual != tc.expected {
				t.Errorf("Drop reason %d: expected '%s', got '%s'", tc.reason, tc.expected, actual)
			}
		}
	})

	t.Run("JSON marshaling", func(t *testing.T) {
		event := &Event{
			BaseEvent: bpf.BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			DropReason: 1,
			SkbLen:     1500,
		}

		data, err := event.MarshalJSON()
		if err != nil {
			t.Errorf("JSON marshaling failed: %v", err)
		}

		// Basic check that JSON contains expected fields
		jsonStr := string(data)
		expectedFields := []string{
			"\"pid\":1234",
			"\"command\":\"test\"",
			"\"drop_reason_code\":1",
			"\"drop_reason\":\"SKB_FREE\"",
			"\"skb_length\":1500",
		}

		for _, field := range expectedFields {
			if !strings.Contains(jsonStr, field) {
				t.Errorf("JSON should contain '%s', got: %s", field, jsonStr)
			}
		}
	})
}

func TestPacketDropProgram(t *testing.T) {
	storage := bpf.NewInMemoryStorage()
	program := NewProgram(storage)

	t.Run("Program properties", func(t *testing.T) {
		if program.GetName() != "packet_drop" {
			t.Errorf("Expected name 'packet_drop', got '%s'", program.GetName())
		}

		if program.GetObjectPath() != "bpf/packet_drop.o" {
			t.Errorf("Expected object path 'bpf/packet_drop.o', got '%s'", program.GetObjectPath())
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
			DropReason: 1,
			SkbLen:     1500,
		}

		err := storage.Store(event)
		if err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}

		// Test summary by PID
		summary := program.GetSummary(1234, "", 60)
		if summary != 1 {
			t.Errorf("Expected summary count 1 for PID, got %d", summary)
		}

		// Test summary by command
		summary = program.GetSummary(0, "test", 60)
		if summary != 1 {
			t.Errorf("Expected summary count 1 for command, got %d", summary)
		}

		// Test get all events
		allEvents := program.GetAllEvents()
		if len(allEvents) == 0 {
			t.Error("Expected to get stored events")
		}
	})
}
