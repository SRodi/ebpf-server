package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
)

// TestBaseEvent tests the BaseEvent implementation
func TestBaseEvent(t *testing.T) {
	metadata := map[string]interface{}{
		"dest": "127.0.0.1:80",
		"proto": "tcp",
	}

	event := NewBaseEvent("connection", 1234, "curl", 1000000, metadata)

	// Test that ID is generated
	if event.ID() == "" {
		t.Error("expected non-empty ID")
	}

	// Test type
	if event.Type() != "connection" {
		t.Errorf("expected type 'connection', got %s", event.Type())
	}

	// Test PID
	if event.PID() != 1234 {
		t.Errorf("expected PID 1234, got %d", event.PID())
	}

	// Test command
	if event.Command() != "curl" {
		t.Errorf("expected command 'curl', got %s", event.Command())
	}

	// Test timestamp
	if event.Timestamp() != 1000000 {
		t.Errorf("expected timestamp 1000000, got %d", event.Timestamp())
	}

	// Test time is set
	if event.Time().IsZero() {
		t.Error("expected non-zero time")
	}

	// Test metadata
	eventMetadata := event.Metadata()
	if dest, ok := eventMetadata["dest"]; !ok || dest != "127.0.0.1:80" {
		t.Errorf("expected metadata dest '127.0.0.1:80', got %v", dest)
	}

	// Test JSON marshaling
	jsonData, err := event.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal event to JSON: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("expected non-empty JSON data")
	}

	// Verify JSON contains expected fields
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if result["type"] != "connection" {
		t.Errorf("expected JSON type 'connection', got %v", result["type"])
	}

	if result["pid"] != float64(1234) { // JSON numbers are float64
		t.Errorf("expected JSON PID 1234, got %v", result["pid"])
	}
}

// TestChannelStream tests the ChannelStream implementation
func TestChannelStream(t *testing.T) {
	stream := NewChannelStream(2) // buffered channel

	// Test that we can get the events channel
	eventsChan := stream.Events()
	if eventsChan == nil {
		t.Fatal("expected non-nil events channel")
	}

	// Create some test events
	event1 := NewBaseEvent("test1", 100, "cmd1", 1000, map[string]interface{}{"test": 1})
	event2 := NewBaseEvent("test2", 200, "cmd2", 2000, map[string]interface{}{"test": 2})

	// Send events directly to the underlying channel (for testing)
	// In real usage, you'd use the Send method
	go func() {
		stream.events <- event1
		stream.events <- event2
		stream.Close()
	}()

	// Collect events
	var receivedEvents []core.Event
	for event := range stream.Events() {
		receivedEvents = append(receivedEvents, event)
	}

	// Verify events
	if len(receivedEvents) != 2 {
		t.Errorf("expected 2 events, got %d", len(receivedEvents))
	}

	if receivedEvents[0].Type() != "test1" {
		t.Errorf("expected first event type 'test1', got %s", receivedEvents[0].Type())
	}

	if receivedEvents[1].Type() != "test2" {
		t.Errorf("expected second event type 'test2', got %s", receivedEvents[1].Type())
	}
}

// TestChannelStreamSend tests sending events to ChannelStream
func TestChannelStreamSend(t *testing.T) {
	stream := NewChannelStream(1)

	event := NewBaseEvent("test", 123, "cmd", 1000, map[string]interface{}{})

	// Test sending
	if !stream.Send(event) {
		t.Fatal("failed to send event to stream")
	}

	// Receive the event
	select {
	case receivedEvent := <-stream.Events():
		if receivedEvent.Type() != "test" {
			t.Errorf("expected event type 'test', got %s", receivedEvent.Type())
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for event")
	}

	// Close and test sending fails
	stream.Close()

	if stream.Send(event) {
		t.Error("expected sending to closed stream to return false")
	}
}

// TestMergedStreamBasic tests basic MergedStream functionality
func TestMergedStreamBasic(t *testing.T) {
	// Create a simple test without complex concurrency
	source := NewChannelStream(5)
	streams := []core.EventStream{source}
	merged := NewMergedStream(streams)

	// Send one event
	event := NewBaseEvent("test", 123, "cmd", 1000, map[string]interface{}{})
	if !source.Send(event) {
		t.Fatal("failed to send event")
	}

	// Receive the event with timeout
	select {
	case receivedEvent := <-merged.Events():
		if receivedEvent.Type() != "test" {
			t.Errorf("expected event type 'test', got %s", receivedEvent.Type())
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for event from merged stream")
	}

	// Clean up
	source.Close()
	merged.Close()
}

// TestMergedStreamMultipleSources tests merging from multiple sources
func TestMergedStreamMultipleSources(t *testing.T) {
	// Create two source streams
	source1 := NewChannelStream(5)
	source2 := NewChannelStream(5)
	streams := []core.EventStream{source1, source2}
	merged := NewMergedStream(streams)

	// Send events from both sources
	event1 := NewBaseEvent("type1", 1, "cmd1", 1000, map[string]interface{}{})
	event2 := NewBaseEvent("type2", 2, "cmd2", 2000, map[string]interface{}{})

	source1.Send(event1)
	source2.Send(event2)

	// Collect events with timeout
	var events []core.Event
	timeout := time.After(1 * time.Second)
	eventCount := 0

	for eventCount < 2 {
		select {
		case event := <-merged.Events():
			events = append(events, event)
			eventCount++
		case <-timeout:
			t.Fatalf("timeout waiting for events, got %d of 2", eventCount)
		}
	}

	// Verify we got both events
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	types := make(map[string]bool)
	for _, event := range events {
		types[event.Type()] = true
	}

	if !types["type1"] || !types["type2"] {
		t.Error("missing expected event types")
	}

	// Clean up
	source1.Close()
	source2.Close()
	merged.Close()
}

// TestBaseEventUniqueIDs tests that BaseEvent generates unique IDs
func TestBaseEventUniqueIDs(t *testing.T) {
	const numEvents = 1000
	ids := make(map[string]bool)

	for i := 0; i < numEvents; i++ {
		event := NewBaseEvent("test", uint32(i), "cmd", uint64(i), map[string]interface{}{})
		id := event.ID()

		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true

		if len(id) == 0 {
			t.Error("empty ID generated")
		}
	}

	if len(ids) != numEvents {
		t.Errorf("expected %d unique IDs, got %d", numEvents, len(ids))
	}
}

// TestBaseEventJSONRoundTrip tests JSON marshaling and unmarshaling
func TestBaseEventJSONRoundTrip(t *testing.T) {
	originalMetadata := map[string]interface{}{
		"string_field": "value",
		"int_field":    42,
		"bool_field":   true,
		"float_field":  3.14,
	}

	original := NewBaseEvent("test_type", 9999, "test_command", 123456789, originalMetadata)

	// Marshal to JSON
	jsonData, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal to JSON: %v", err)
	}

	// Unmarshal back
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Verify fields
	if result["type"] != "test_type" {
		t.Errorf("expected type 'test_type', got %v", result["type"])
	}

	if result["pid"] != float64(9999) {
		t.Errorf("expected PID 9999, got %v", result["pid"])
	}

	if result["command"] != "test_command" {
		t.Errorf("expected command 'test_command', got %v", result["command"])
	}

	if result["timestamp"] != float64(123456789) {
		t.Errorf("expected timestamp 123456789, got %v", result["timestamp"])
	}

	// Verify metadata (fields are merged at root level, not nested)
	if result["string_field"] != "value" {
		t.Errorf("expected string_field 'value', got %v", result["string_field"])
	}

	if result["int_field"] != float64(42) {
		t.Errorf("expected int_field 42, got %v", result["int_field"])
	}

	if result["bool_field"] != true {
		t.Errorf("expected bool_field true, got %v", result["bool_field"])
	}

	if result["float_field"] != 3.14 {
		t.Errorf("expected float_field 3.14, got %v", result["float_field"])
	}
}

// TestChannelStreamCapacity tests buffer capacity behavior
func TestChannelStreamCapacity(t *testing.T) {
	stream := NewChannelStream(1) // capacity of 1

	event1 := NewBaseEvent("test1", 1, "cmd", 1000, map[string]interface{}{})
	event2 := NewBaseEvent("test2", 2, "cmd", 2000, map[string]interface{}{})

	// Send first event (should succeed)
	if !stream.Send(event1) {
		t.Fatal("failed to send first event")
	}

	// Second event may fail if buffer is full (non-blocking Send)
	// This is expected behavior for non-blocking send
	result := stream.Send(event2)
	t.Logf("Send result for second event (when buffer might be full): %v", result)

	// Consume the first event to make space
	select {
	case receivedEvent := <-stream.Events():
		if receivedEvent.Type() != "test1" {
			t.Errorf("expected first event type 'test1', got %s", receivedEvent.Type())
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for first event")
	}

	// Now second event should succeed
	if !stream.Send(event2) {
		t.Error("failed to send second event after consuming first")
	}

	// Consume second event
	select {
	case receivedEvent := <-stream.Events():
		if receivedEvent.Type() != "test2" {
			t.Errorf("expected second event type 'test2', got %s", receivedEvent.Type())
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for second event")
	}

	stream.Close()
}
