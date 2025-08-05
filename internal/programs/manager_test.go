package programs

import (
	"context"
	"fmt"
	"testing"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
)

// MockProgram for testing the Manager
type MockProgram struct {
	name        string
	description string
	loaded      bool
	attached    bool
	stream      *events.ChannelStream
}

func (m *MockProgram) Name() string                        { return m.name }
func (m *MockProgram) Description() string                 { return m.description }
func (m *MockProgram) Load(ctx context.Context) error      { m.loaded = true; return nil }
func (m *MockProgram) Attach(ctx context.Context) error    { m.attached = true; return nil }
func (m *MockProgram) Detach(ctx context.Context) error    { m.attached = false; return nil }
func (m *MockProgram) IsLoaded() bool                      { return m.loaded }
func (m *MockProgram) IsAttached() bool                    { return m.attached }
func (m *MockProgram) EventStream() core.EventStream       { return m.stream }
func (m *MockProgram) GetStats() (uint64, uint64, float64) { return 0, 0, 0.0 }

// TestManagerBasic tests basic Manager functionality
func TestManagerBasic(t *testing.T) {
	manager := NewManager()

	if manager.IsRunning() {
		t.Error("manager should not be running initially")
	}

	// Test empty manager
	programs := manager.Programs()
	if len(programs) != 0 {
		t.Errorf("expected 0 programs initially, got %d", len(programs))
	}

	status := manager.GetProgramStatus()
	if len(status) != 0 {
		t.Errorf("expected 0 program status initially, got %d", len(status))
	}
}

// TestManagerRegisterProgram tests program registration
func TestManagerRegisterProgram(t *testing.T) {
	manager := NewManager()

	// Create mock programs
	stream1 := events.NewChannelStream(10)
	stream2 := events.NewChannelStream(10)

	program1 := &MockProgram{
		name:        "connection",
		description: "Connection monitoring program",
		stream:      stream1,
	}

	program2 := &MockProgram{
		name:        "packet_drop",
		description: "Packet drop monitoring program",
		stream:      stream2,
	}

	// Register programs
	if err := manager.RegisterProgram(program1); err != nil {
		t.Fatalf("failed to register program1: %v", err)
	}

	if err := manager.RegisterProgram(program2); err != nil {
		t.Fatalf("failed to register program2: %v", err)
	}

	// Verify programs are registered
	programs := manager.Programs()
	if len(programs) != 2 {
		t.Errorf("expected 2 programs, got %d", len(programs))
	}

	// Verify program status
	status := manager.GetProgramStatus()
	if len(status) != 2 {
		t.Errorf("expected 2 program status, got %d", len(status))
	}

	// Find and verify each program status
	statusMap := make(map[string]core.ProgramStatus)
	for _, s := range status {
		statusMap[s.Name] = s
	}

	if connStatus, ok := statusMap["connection"]; ok {
		if connStatus.Description != "Connection monitoring program" {
			t.Errorf("expected connection description, got %s", connStatus.Description)
		}
		if connStatus.Loaded {
			t.Error("connection program should not be loaded initially")
		}
		if connStatus.Attached {
			t.Error("connection program should not be attached initially")
		}
	} else {
		t.Error("connection program status not found")
	}
}

// TestManagerLoadAttachDetach tests the load/attach/detach lifecycle
func TestManagerLoadAttachDetach(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	// Create mock program
	stream := events.NewChannelStream(10)
	program := &MockProgram{
		name:        "test",
		description: "Test program",
		stream:      stream,
	}

	if err := manager.RegisterProgram(program); err != nil {
		t.Fatalf("failed to register program: %v", err)
	}

	// Test LoadAll
	if err := manager.LoadAll(ctx); err != nil {
		t.Fatalf("failed to load all programs: %v", err)
	}

	// Manager should not be running yet (only loaded, not attached)
	if manager.IsRunning() {
		t.Error("manager should not be running after LoadAll (only loaded, not attached)")
	}

	// Verify program is loaded
	status := manager.GetProgramStatus()
	if len(status) != 1 {
		t.Fatalf("expected 1 program status, got %d", len(status))
	}

	if !status[0].Loaded {
		t.Error("program should be loaded after LoadAll")
	}

	// Test AttachAll
	if err := manager.AttachAll(ctx); err != nil {
		t.Fatalf("failed to attach all programs: %v", err)
	}

	// Manager should be running after AttachAll
	if !manager.IsRunning() {
		t.Error("manager should be running after AttachAll")
	}

	// Verify program is attached
	status = manager.GetProgramStatus()
	if !status[0].Attached {
		t.Error("program should be attached after AttachAll")
	}

	// Test DetachAll
	if err := manager.DetachAll(ctx); err != nil {
		t.Fatalf("failed to detach all programs: %v", err)
	}

	// Manager should not be running after DetachAll
	if manager.IsRunning() {
		t.Error("manager should not be running after DetachAll")
	}

	// Verify program is detached
	status = manager.GetProgramStatus()
	if status[0].Attached {
		t.Error("program should be detached after DetachAll")
	}
}

// TestManagerEventStream tests the unified event stream
func TestManagerEventStream(t *testing.T) {
	manager := NewManager()
	ctx := context.Background()

	// Create mock programs with streams
	stream1 := events.NewChannelStream(10)
	stream2 := events.NewChannelStream(10)

	program1 := &MockProgram{
		name:   "prog1",
		stream: stream1,
	}

	program2 := &MockProgram{
		name:   "prog2",
		stream: stream2,
	}

	if err := manager.RegisterProgram(program1); err != nil {
		t.Fatalf("failed to register program1: %v", err)
	}
	if err := manager.RegisterProgram(program2); err != nil {
		t.Fatalf("failed to register program2: %v", err)
	}

	// Load and attach programs to create the unified stream
	if err := manager.LoadAll(ctx); err != nil {
		t.Fatalf("failed to load programs: %v", err)
	}

	if err := manager.AttachAll(ctx); err != nil {
		t.Fatalf("failed to attach programs: %v", err)
	}

	// Get unified event stream (should now be available)
	unifiedStream := manager.EventStream()
	if unifiedStream == nil {
		t.Fatal("expected non-nil unified event stream after AttachAll")
	}

	// Send events to individual streams
	event1 := events.NewBaseEvent("type1", 100, "cmd1", 1000, map[string]interface{}{})
	event2 := events.NewBaseEvent("type2", 200, "cmd2", 2000, map[string]interface{}{})

	stream1.Send(event1)
	stream2.Send(event2)

	// Try to receive events from unified stream
	// Note: This test might be flaky depending on timing
	receivedEvents := 0

	// Use select with timeout to avoid hanging
eventLoop:
	for receivedEvents < 2 {
		select {
		case event := <-unifiedStream.Events():
			receivedEvents++
			t.Logf("Received event type: %s, PID: %d", event.Type(), event.PID())
		default:
			// If no events immediately available, break to avoid hanging
			break eventLoop
		}
	}

	t.Logf("Received %d events from unified stream", receivedEvents)

	// Clean up
	if err := manager.DetachAll(ctx); err != nil {
		t.Errorf("failed to detach programs: %v", err)
	}
	stream1.Close()
	stream2.Close()
}

// TestManagerDuplicateRegistration tests handling of duplicate program registration
func TestManagerDuplicateRegistration(t *testing.T) {
	manager := NewManager()

	stream := events.NewChannelStream(10)
	program := &MockProgram{
		name:   "test",
		stream: stream,
	}

	// Register program first time
	if err := manager.RegisterProgram(program); err != nil {
		t.Fatalf("failed to register program first time: %v", err)
	}

	// Register same program again - should return error
	if err := manager.RegisterProgram(program); err == nil {
		t.Error("expected error when registering duplicate program")
	}

	// Verify only one program is registered
	programs := manager.Programs()
	if len(programs) != 1 {
		t.Errorf("expected 1 program after duplicate registration, got %d", len(programs))
	}
}

// TestManagerWithNilProgram tests handling of nil program registration
func TestManagerWithNilProgram(t *testing.T) {
	manager := NewManager()

	// Try to register nil program
	if err := manager.RegisterProgram(nil); err == nil {
		t.Error("expected error when registering nil program")
	}

	// Verify no programs are registered
	programs := manager.Programs()
	if len(programs) != 0 {
		t.Errorf("expected 0 programs after nil registration, got %d", len(programs))
	}
}

// TestManagerConcurrency tests concurrent access to manager
func TestManagerConcurrency(t *testing.T) {
	manager := NewManager()

	// Register programs from multiple goroutines
	numGoroutines := 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			stream := events.NewChannelStream(10)
			program := &MockProgram{
				name:   fmt.Sprintf("program_%d", id),
				stream: stream,
			}

			errors <- manager.RegisterProgram(program)
		}(i)
	}

	// Collect errors
	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("concurrent registration failed: %v", err)
		}
	}

	// Verify all programs are registered
	programs := manager.Programs()
	if len(programs) != numGoroutines {
		t.Errorf("expected %d programs, got %d", numGoroutines, len(programs))
	}

	// Test concurrent status queries instead of conflicting operations
	statusErrors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			status := manager.GetProgramStatus()
			if len(status) != numGoroutines {
				statusErrors <- fmt.Errorf("expected %d status entries, got %d", numGoroutines, len(status))
			} else {
				statusErrors <- nil
			}
		}()
	}

	// Collect status errors
	for i := 0; i < numGoroutines; i++ {
		if err := <-statusErrors; err != nil {
			t.Errorf("concurrent status query failed: %v", err)
		}
	}
}
