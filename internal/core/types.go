// Package core defines the fundamental types and interfaces for the eBPF monitoring system.
// It provides the contracts that all other components must implement.
package core

import (
	"context"
	"encoding/json"
	"time"
)

// Event represents a single eBPF event with metadata.
// All events in the system implement this interface.
type Event interface {
	// ID returns a unique identifier for this event
	ID() string
	
	// Type returns the event type (e.g., "connection", "packet_drop")
	Type() string
	
	// PID returns the process ID that generated this event
	PID() uint32
	
	// Command returns the command name of the process
	Command() string
	
	// Timestamp returns the kernel timestamp (nanoseconds since boot)
	Timestamp() uint64
	
	// Time returns the wall clock time when the event occurred
	Time() time.Time
	
	// Metadata returns event-specific data as a map
	Metadata() map[string]interface{}
	
	// JSON serialization
	json.Marshaler
}

// EventParser converts raw binary data from eBPF programs into Event objects.
type EventParser interface {
	// Parse converts raw bytes into an Event
	Parse(data []byte) (Event, error)
	
	// EventType returns the type of events this parser handles
	EventType() string
}

// EventStream provides a channel-based interface for receiving events.
type EventStream interface {
	// Events returns a channel that delivers events
	Events() <-chan Event
	
	// Close stops the event stream and closes the channel
	Close() error
}

// EventSink stores events for later retrieval.
type EventSink interface {
	// Store saves an event
	Store(ctx context.Context, event Event) error
	
	// Query retrieves events matching the given criteria
	Query(ctx context.Context, query Query) ([]Event, error)
	
	// Count returns the number of events matching the criteria
	Count(ctx context.Context, query Query) (int, error)
}

// Program represents an eBPF program that can be loaded and attached to the kernel.
type Program interface {
	// Name returns the program name
	Name() string
	
	// Description returns a human-readable description
	Description() string
	
	// Load compiles and loads the eBPF program into the kernel
	Load(ctx context.Context) error
	
	// Attach attaches the program to appropriate kernel hooks
	Attach(ctx context.Context) error
	
	// Detach detaches the program from kernel hooks
	Detach(ctx context.Context) error
	
	// IsLoaded returns true if the program is loaded
	IsLoaded() bool
	
	// IsAttached returns true if the program is attached
	IsAttached() bool
	
	// EventStream returns a stream of events from this program
	EventStream() EventStream
}

// Manager orchestrates multiple eBPF programs and provides a unified interface.
type Manager interface {
	// RegisterProgram adds a program to the manager
	RegisterProgram(program Program) error
	
	// LoadAll loads all registered programs
	LoadAll(ctx context.Context) error
	
	// AttachAll attaches all loaded programs
	AttachAll(ctx context.Context) error
	
	// DetachAll detaches all programs
	DetachAll(ctx context.Context) error
	
	// Programs returns all registered programs
	Programs() []Program
	
	// GetProgramStatus returns status of all programs
	GetProgramStatus() []ProgramStatus
	
	// EventStream returns a unified stream of events from all programs
	EventStream() EventStream
	
	// IsRunning returns true if the manager is active
	IsRunning() bool
}

// Query represents search criteria for events.
type Query struct {
	// EventType filters by event type (optional)
	EventType string
	
	// PID filters by process ID (optional, 0 means no filter)
	PID uint32
	
	// Command filters by command name (optional)
	Command string
	
	// Since filters events after this time (optional)
	Since time.Time
	
	// Until filters events before this time (optional)
	Until time.Time
	
	// Limit limits the number of results (optional, 0 means no limit)
	Limit int
}

// ProgramStatus represents the current state of a program.
type ProgramStatus struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Loaded      bool   `json:"loaded"`
	Attached    bool   `json:"attached"`
	EventCount  int64  `json:"event_count"`
}
