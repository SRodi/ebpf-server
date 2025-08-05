package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// MockEvent implements the Event interface for testing
type MockEvent struct {
	id        string
	eventType string
	pid       uint32
	command   string
	timestamp uint64
	time      time.Time
	metadata  map[string]interface{}
}

func (m *MockEvent) ID() string                        { return m.id }
func (m *MockEvent) Type() string                      { return m.eventType }
func (m *MockEvent) PID() uint32                       { return m.pid }
func (m *MockEvent) Command() string                   { return m.command }
func (m *MockEvent) Timestamp() uint64                 { return m.timestamp }
func (m *MockEvent) Time() time.Time                   { return m.time }
func (m *MockEvent) Metadata() map[string]interface{} { return m.metadata }

func (m *MockEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"id":        m.id,
		"type":      m.eventType,
		"pid":       m.pid,
		"command":   m.command,
		"timestamp": m.timestamp,
		"time":      m.time.Format(time.RFC3339),
		"metadata":  m.metadata,
	})
}

// MockEventParser implements EventParser for testing
type MockEventParser struct {
	eventType string
	parseFunc func([]byte) (Event, error)
}

func (m *MockEventParser) Parse(data []byte) (Event, error) {
	if m.parseFunc != nil {
		return m.parseFunc(data)
	}
	return &MockEvent{
		id:        "test-id",
		eventType: m.eventType,
		pid:       1234,
		command:   "test-cmd",
		timestamp: uint64(time.Now().UnixNano()),
		time:      time.Now(),
		metadata:  map[string]interface{}{"test": "data"},
	}, nil
}

func (m *MockEventParser) EventType() string {
	return m.eventType
}

// MockEventStream implements EventStream for testing
type MockEventStream struct {
	events chan Event
	closed bool
}

func (m *MockEventStream) Events() <-chan Event { return m.events }
func (m *MockEventStream) Close() error {
	if !m.closed {
		close(m.events)
		m.closed = true
	}
	return nil
}

// MockEventSink implements EventSink for testing
type MockEventSink struct {
	events []Event
}

func (m *MockEventSink) Consume(stream EventStream) error {
	for event := range stream.Events() {
		m.events = append(m.events, event)
	}
	return nil
}

func (m *MockEventSink) GetEvents() []Event {
	return m.events
}

// MockProgram implements Program for testing
type MockProgram struct {
	name        string
	description string
	loaded      bool
	attached    bool
	stream      EventStream
}

func (m *MockProgram) Name() string                              { return m.name }
func (m *MockProgram) Description() string                      { return m.description }
func (m *MockProgram) Load(ctx context.Context) error           { m.loaded = true; return nil }
func (m *MockProgram) Attach(ctx context.Context) error         { m.attached = true; return nil }
func (m *MockProgram) Detach(ctx context.Context) error         { m.attached = false; return nil }
func (m *MockProgram) IsLoaded() bool                           { return m.loaded }
func (m *MockProgram) IsAttached() bool                         { return m.attached }
func (m *MockProgram) EventStream() EventStream                 { return m.stream }
func (m *MockProgram) GetStats() (uint64, uint64, float64)      { return 0, 0, 0.0 }

// MockManager implements Manager for testing
type MockManager struct {
	programs []Program
	running  bool
}

func (m *MockManager) RegisterProgram(program Program) error     { m.programs = append(m.programs, program); return nil }
func (m *MockManager) LoadAll(ctx context.Context) error        { m.running = true; return nil }
func (m *MockManager) AttachAll(ctx context.Context) error      { return nil }
func (m *MockManager) DetachAll(ctx context.Context) error      { return nil }
func (m *MockManager) Programs() []Program                      { return m.programs }
func (m *MockManager) GetProgramStatus() []ProgramStatus        { return []ProgramStatus{} }
func (m *MockManager) EventStream() EventStream                 { return &MockEventStream{events: make(chan Event)} }
func (m *MockManager) IsRunning() bool                          { return m.running }

// TestEvent tests the Event interface
func TestEvent(t *testing.T) {
	now := time.Now()
	timestamp := uint64(now.UnixNano())
	
	event := &MockEvent{
		id:        "test-123",
		eventType: "connection",
		pid:       1234,
		command:   "curl",
		timestamp: timestamp,
		time:      now,
		metadata:  map[string]interface{}{"dest": "127.0.0.1:80"},
	}

	if event.ID() != "test-123" {
		t.Errorf("expected ID 'test-123', got %s", event.ID())
	}

	if event.Type() != "connection" {
		t.Errorf("expected type 'connection', got %s", event.Type())
	}

	if event.PID() != 1234 {
		t.Errorf("expected PID 1234, got %d", event.PID())
	}

	if event.Command() != "curl" {
		t.Errorf("expected command 'curl', got %s", event.Command())
	}

	if event.Timestamp() != timestamp {
		t.Errorf("expected timestamp %d, got %d", timestamp, event.Timestamp())
	}

	if !event.Time().Equal(now) {
		t.Errorf("expected time %v, got %v", now, event.Time())
	}

	metadata := event.Metadata()
	if dest, ok := metadata["dest"]; !ok || dest != "127.0.0.1:80" {
		t.Errorf("expected metadata dest '127.0.0.1:80', got %v", dest)
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event to JSON: %v", err)
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal event JSON: %v", err)
	}

	if unmarshaled["id"] != "test-123" {
		t.Errorf("expected JSON id 'test-123', got %v", unmarshaled["id"])
	}
}

// TestEventParser tests the EventParser interface
func TestEventParser(t *testing.T) {
	parser := &MockEventParser{
		eventType: "test",
	}

	if parser.EventType() != "test" {
		t.Errorf("expected event type 'test', got %s", parser.EventType())
	}

	event, err := parser.Parse([]byte("test data"))
	if err != nil {
		t.Fatalf("unexpected error parsing data: %v", err)
	}

	if event.Type() != "test" {
		t.Errorf("expected parsed event type 'test', got %s", event.Type())
	}
}

// TestEventStream tests the EventStream interface
func TestEventStream(t *testing.T) {
	stream := &MockEventStream{
		events: make(chan Event, 2),
	}

	// Send some events
	event1 := &MockEvent{id: "1", eventType: "test"}
	event2 := &MockEvent{id: "2", eventType: "test"}

	stream.events <- event1
	stream.events <- event2

	// Read events with proper synchronization
	events := make([]Event, 0, 2)
	done := make(chan bool)
	go func() {
		defer close(done)
		for event := range stream.Events() {
			events = append(events, event)
		}
	}()

	// Close stream
	if err := stream.Close(); err != nil {
		t.Fatalf("unexpected error closing stream: %v", err)
	}

	// Wait for goroutine to finish
	<-done

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}

	if events[0].ID() != "1" {
		t.Errorf("expected first event ID '1', got %s", events[0].ID())
	}

	if events[1].ID() != "2" {
		t.Errorf("expected second event ID '2', got %s", events[1].ID())
	}
}

// TestEventSink tests the EventSink interface
func TestEventSink(t *testing.T) {
	sink := &MockEventSink{
		events: make([]Event, 0),
	}

	stream := &MockEventStream{
		events: make(chan Event, 2),
	}

	// Send events to stream
	event1 := &MockEvent{id: "1", eventType: "test"}
	event2 := &MockEvent{id: "2", eventType: "test"}

	go func() {
		stream.events <- event1
		stream.events <- event2
		stream.Close()
	}()

	// Consume events
	if err := sink.Consume(stream); err != nil {
		t.Fatalf("unexpected error consuming events: %v", err)
	}

	events := sink.GetEvents()
	if len(events) != 2 {
		t.Errorf("expected 2 consumed events, got %d", len(events))
	}
}

// TestProgram tests the Program interface
func TestProgram(t *testing.T) {
	stream := &MockEventStream{
		events: make(chan Event),
	}

	program := &MockProgram{
		name:        "test-program",
		description: "Test program for connections",
		stream:      stream,
	}

	if program.Name() != "test-program" {
		t.Errorf("expected name 'test-program', got %s", program.Name())
	}

	if program.Description() != "Test program for connections" {
		t.Errorf("expected description 'Test program for connections', got %s", program.Description())
	}

	if program.IsLoaded() {
		t.Error("program should not be loaded initially")
	}

	if program.IsAttached() {
		t.Error("program should not be attached initially")
	}

	ctx := context.Background()

	// Test loading
	if err := program.Load(ctx); err != nil {
		t.Fatalf("unexpected error loading program: %v", err)
	}

	if !program.IsLoaded() {
		t.Error("program should be loaded after Load()")
	}

	// Test attaching
	if err := program.Attach(ctx); err != nil {
		t.Fatalf("unexpected error attaching program: %v", err)
	}

	if !program.IsAttached() {
		t.Error("program should be attached after Attach()")
	}

	// Test event stream
	if program.EventStream() != stream {
		t.Error("program should return the correct event stream")
	}

	// Test detaching
	if err := program.Detach(ctx); err != nil {
		t.Fatalf("unexpected error detaching program: %v", err)
	}

	if program.IsAttached() {
		t.Error("program should not be attached after Detach()")
	}
}

// TestManager tests the Manager interface
func TestManager(t *testing.T) {
	manager := &MockManager{
		programs: make([]Program, 0),
	}

	if manager.IsRunning() {
		t.Error("manager should not be running initially")
	}

	// Test adding programs
	program1 := &MockProgram{name: "prog1", description: "Connection program"}
	program2 := &MockProgram{name: "prog2", description: "Packet drop program"}

	if err := manager.RegisterProgram(program1); err != nil {
		t.Fatalf("unexpected error registering program1: %v", err)
	}

	if err := manager.RegisterProgram(program2); err != nil {
		t.Fatalf("unexpected error registering program2: %v", err)
	}

	programs := manager.Programs()
	if len(programs) != 2 {
		t.Errorf("expected 2 programs, got %d", len(programs))
	}

	// Test loading all
	ctx := context.Background()
	if err := manager.LoadAll(ctx); err != nil {
		t.Fatalf("unexpected error loading all programs: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("manager should be running after LoadAll()")
	}

	// Test attaching all
	if err := manager.AttachAll(ctx); err != nil {
		t.Fatalf("unexpected error attaching all programs: %v", err)
	}

	// Test detaching all
	if err := manager.DetachAll(ctx); err != nil {
		t.Fatalf("unexpected error detaching all programs: %v", err)
	}

	// Test getting program status
	status := manager.GetProgramStatus()
	if status == nil {
		t.Error("expected non-nil program status")
	}

	// Test event stream
	stream := manager.EventStream()
	if stream == nil {
		t.Error("expected non-nil event stream")
	}
}

// TestQuery tests the Query struct
func TestQuery(t *testing.T) {
	now := time.Now()
	query := Query{
		EventType: "connection",
		PID:       1234,
		Command:   "curl",
		Since:     now.Add(-1 * time.Hour),
		Until:     now,
		Limit:     100,
	}

	if query.EventType != "connection" {
		t.Errorf("expected event type 'connection', got %s", query.EventType)
	}

	if query.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", query.PID)
	}

	if query.Command != "curl" {
		t.Errorf("expected command 'curl', got %s", query.Command)
	}

	if query.Limit != 100 {
		t.Errorf("expected limit 100, got %d", query.Limit)
	}

	if query.Since.After(now.Add(-1*time.Hour)) || query.Since.Before(now.Add(-2*time.Hour)) {
		t.Errorf("expected since time around 1 hour ago, got %v", query.Since)
	}

	if query.Until.After(now.Add(time.Minute)) || query.Until.Before(now.Add(-time.Minute)) {
		t.Errorf("expected until time around now, got %v", query.Until)
	}
}

// TestDefaultQuery tests query with default values
func TestDefaultQuery(t *testing.T) {
	query := Query{}

	if query.EventType != "" {
		t.Errorf("expected empty event type, got %s", query.EventType)
	}

	if query.PID != 0 {
		t.Errorf("expected PID 0, got %d", query.PID)
	}

	if query.Command != "" {
		t.Errorf("expected empty command, got %s", query.Command)
	}

	if query.Limit != 0 {
		t.Errorf("expected limit 0, got %d", query.Limit)
	}
}
