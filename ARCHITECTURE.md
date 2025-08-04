# eBPF Program Architecture

This document describes the modular eBPF program management architecture that makes the project easy to maintain and extend.

## Architecture Overview

The refactored architecture separates concerns into distinct, well-defined components:

```
internal/bpf/
├── interfaces.go     # Core interfaces and contracts
├── base.go          # Common functionality for all events
├── storage.go       # Event storage implementation
├── manager.go       # Multi-program manager
├── loader.go        # Main entry point and backward compatibility
├── types.go         # Legacy event types (preserved for compatibility)
└── programs/        # Individual eBPF programs
    ├── connection/
    │   ├── event.go     # Connection event definitions
    │   └── program.go   # Connection program implementation
    └── packet_drop/
        ├── event.go     # Packet drop event definitions
        └── program.go   # Packet drop program implementation
```

## Core Interfaces

### BPFEvent
All eBPF events must implement this interface:
```go
type BPFEvent interface {
    GetPID() uint32
    GetTimestamp() uint64
    GetCommand() string
    GetWallClockTime() time.Time
    GetEventType() string
}
```

### BPFProgram
All eBPF programs must implement this interface:
```go
type BPFProgram interface {
    GetName() string
    GetDescription() string
    GetObjectPath() string
    Load() error
    Attach() error
    Start(ctx context.Context) error
    Stop() error
    IsRunning() bool
    GetEventChannel() <-chan BPFEvent
    GetSummary(pid uint32, command string, durationSeconds int) int
    GetAllEvents() map[uint32][]BPFEvent
}
```

### BPFManager
Manages multiple eBPF programs:
```go
type BPFManager interface {
    RegisterProgram(program BPFProgram) error
    UnregisterProgram(name string) error
    LoadAll() error
    AttachAll() error
    StartAll() error
    StopAll() error
    GetProgram(name string) (BPFProgram, bool)
    ListPrograms() []string
    IsAvailable() bool
    GetAggregatedEvents() <-chan BPFEvent
}
```

## Adding New eBPF Programs

To add a new eBPF program (e.g., file system monitoring):

### 1. Create the Program Directory
```bash
mkdir -p internal/bpf/programs/filesystem
```

### 2. Define the Event Type
Create `internal/bpf/programs/filesystem/event.go`:
```go
package filesystem

import (
    "github.com/srodi/ebpf-server/internal/bpf"
)

type Event struct {
    bpf.BaseEvent
    Path     [256]byte `json:"-"`
    Operation uint32   `json:"operation"`
}

func (e *Event) GetEventType() string {
    return "filesystem"
}

func (e *Event) GetPath() string {
    // Convert null-terminated byte array to string
    for i, b := range e.Path {
        if b == 0 {
            return string(e.Path[:i])
        }
    }
    return string(e.Path[:])
}
```

### 3. Implement the Program
Create `internal/bpf/programs/filesystem/program.go`:
```go
package filesystem

import (
    "context"
    "github.com/cilium/ebpf"
    "github.com/srodi/ebpf-server/internal/bpf"
)

type Program struct {
    name        string
    description string
    objectPath  string
    // ... other fields similar to connection program
    storage bpf.EventStorage
}

func NewProgram(storage bpf.EventStorage) *Program {
    return &Program{
        name:        "filesystem",
        description: "Monitors file system operations",
        objectPath:  "bpf/filesystem.o",
        storage:     storage,
    }
}

// Implement all BPFProgram interface methods...
```

### 4. Register the Program
In `loader.go`, add the new program to `registerDefaultPrograms()`:
```go
func registerDefaultPrograms() error {
    storage := globalManager.GetStorage()

    // Existing programs...
    
    // Register filesystem monitoring program
    filesystemProg := filesystem.NewProgram(storage)
    if err := globalManager.RegisterProgram(filesystemProg); err != nil {
        return fmt.Errorf("failed to register filesystem program: %w", err)
    }

    return nil
}
```

### 5. Create the eBPF C Program
Create `bpf/filesystem.c` with the corresponding C struct and eBPF logic.

## Program Independence

Each eBPF program is completely independent:

- **Load**: Each program loads its own eBPF object file
- **Attach**: Each program attaches to its own kernel hooks
- **Process**: Each program processes events in its own goroutine
- **Store**: All programs share the same storage interface but store events by type
- **Fail**: If one program fails, others continue running

## Event Storage

The `EventStorage` interface provides a consistent way to store and retrieve events:

```go
// Store an event
storage.Store(event)

// Get events by criteria
events, err := storage.GetByPID(1234, time.Now().Add(-1*time.Hour))
events, err := storage.GetByCommand("curl", time.Now().Add(-30*time.Minute))
events, err := storage.GetByType("connection", time.Now().Add(-1*time.Hour))

// Count events
count := storage.Count(0, "curl", "", time.Now().Add(-1*time.Hour))
```

## Manager Usage

The manager provides high-level control over all programs:

```go
manager := bpf.NewManager()

// Register programs
manager.RegisterProgram(connectionProgram)
manager.RegisterProgram(packetDropProgram)

// Lifecycle management
manager.LoadAll()     // Load all registered programs
manager.AttachAll()   // Attach all loaded programs  
manager.StartAll()    // Start event processing
manager.StopAll()     // Stop and cleanup

// Query programs
programs := manager.ListPrograms()
if prog, exists := manager.GetProgram("connection"); exists {
    summary := prog.GetSummary(0, "curl", 300) // Last 5 minutes
}

// Aggregated events from all programs
for event := range manager.GetAggregatedEvents() {
    fmt.Printf("Event from %s: PID %d\n", event.GetEventType(), event.GetPID())
}
```

## Backward Compatibility

The refactored architecture maintains full backward compatibility:

- All existing API functions continue to work
- Event structures remain unchanged
- HTTP endpoints continue to function
- No changes required in client code

## Benefits

### Scalability
- Easy to add new eBPF programs without modifying existing code
- Each program is self-contained and independent
- Manager handles all programs uniformly

### Maintainability  
- Clear separation of concerns
- Well-defined interfaces
- Each program can be developed and tested independently
- Consistent error handling and logging

### Extensibility
- Plugin-like architecture for eBPF programs
- Shared storage and event processing infrastructure
- Easy to add new event types and attach points

### Robustness
- Program failures are isolated
- Graceful degradation when programs fail to load/attach
- Consistent lifecycle management

## Testing

Each component can be tested independently:

```go
// Test individual programs
program := connection.NewProgram(mockStorage)
err := program.Load()

// Test manager
manager := bpf.NewManager()
manager.RegisterProgram(mockProgram)
err := manager.StartAll()

// Test storage
storage := bpf.NewInMemoryStorage()
storage.Store(mockEvent)
events, _ := storage.GetByPID(1234, time.Now())
```

## Performance Considerations

- **Event Channels**: Each program has buffered channels to prevent blocking
- **Storage**: In-memory storage with periodic cleanup
- **Aggregation**: Non-blocking event forwarding to prevent bottlenecks
- **Concurrency**: Each program processes events in separate goroutines

## Future Enhancements

The architecture easily supports future enhancements:

- **Persistent Storage**: Implement database-backed EventStorage
- **Event Filtering**: Add filtering capabilities to reduce storage
- **Metrics**: Add Prometheus metrics for each program
- **Configuration**: Add per-program configuration support
- **Hot Reload**: Add capability to reload individual programs
- **Remote Storage**: Implement distributed event storage
