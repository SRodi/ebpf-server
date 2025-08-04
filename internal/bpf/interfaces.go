package bpf

import (
	"context"
	"time"
)

// BPFEvent represents a generic eBPF event with common fields
type BPFEvent interface {
	// GetPID returns the process ID that generated this event
	GetPID() uint32
	
	// GetTimestamp returns the eBPF timestamp (nanoseconds since boot)
	GetTimestamp() uint64
	
	// GetCommand returns the command name that generated this event
	GetCommand() string
	
	// GetWallClockTime converts eBPF timestamp to wall clock time
	GetWallClockTime() time.Time
	
	// GetEventType returns a string identifying the event type (e.g., "connection", "packet_drop")
	GetEventType() string
}

// BPFProgram represents a single eBPF program that can be loaded and managed
type BPFProgram interface {
	// GetName returns the unique name/identifier for this program
	GetName() string
	
	// GetDescription returns a human-readable description of what this program does
	GetDescription() string
	
	// GetObjectPath returns the path to the compiled eBPF object file
	GetObjectPath() string
	
	// Load compiles and loads the eBPF program into the kernel
	Load() error
	
	// Attach attaches the loaded program to the appropriate kernel hooks
	Attach() error
	
	// Start begins processing events from this program
	Start(ctx context.Context) error
	
	// Stop stops processing events and cleans up resources
	Stop() error
	
	// IsRunning returns true if the program is currently running
	IsRunning() bool
	
	// GetEventChannel returns a channel that receives events from this program
	GetEventChannel() <-chan BPFEvent
	
	// GetSummary returns aggregated statistics for this program
	GetSummary(pid uint32, command string, durationSeconds int) int
	
	// GetAllEvents returns all tracked events (for debugging/admin purposes)
	GetAllEvents() map[uint32][]BPFEvent
}

// BPFManager manages multiple eBPF programs
type BPFManager interface {
	// RegisterProgram adds a new eBPF program to be managed
	RegisterProgram(program BPFProgram) error
	
	// UnregisterProgram removes an eBPF program from management
	UnregisterProgram(name string) error
	
	// LoadAll loads all registered programs
	LoadAll() error
	
	// AttachAll attaches all loaded programs
	AttachAll() error
	
	// StartAll starts event processing for all programs
	StartAll() error
	
	// StopAll stops all programs and cleans up resources
	StopAll() error
	
	// GetProgram returns a specific program by name
	GetProgram(name string) (BPFProgram, bool)
	
	// ListPrograms returns a list of all registered program names
	ListPrograms() []string
	
	// IsAvailable checks if eBPF is available on the current system
	IsAvailable() bool
	
	// GetAggregatedEvents returns events from all programs combined
	GetAggregatedEvents() <-chan BPFEvent
}

// EventStorage provides storage and retrieval of eBPF events
type EventStorage interface {
	// Store adds an event to storage
	Store(event BPFEvent) error
	
	// Get retrieves events matching the given criteria within a time window
	Get(pid uint32, command string, eventType string, since time.Time) ([]BPFEvent, error)
	
	// GetByPID retrieves events for a specific PID within a time window
	GetByPID(pid uint32, since time.Time) ([]BPFEvent, error)
	
	// GetByCommand retrieves events for processes matching a command name
	GetByCommand(command string, since time.Time) ([]BPFEvent, error)
	
	// GetByType retrieves events of a specific type within a time window
	GetByType(eventType string, since time.Time) ([]BPFEvent, error)
	
	// Count returns the number of events matching the criteria
	Count(pid uint32, command string, eventType string, since time.Time) int
	
	// GetAll returns all stored events (for debugging)
	GetAll() map[string]map[uint32][]BPFEvent // eventType -> PID -> []BPFEvent
	
	// Cleanup removes old events to prevent memory leaks
	Cleanup(maxAge time.Duration) int
}
