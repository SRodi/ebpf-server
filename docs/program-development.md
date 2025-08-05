# eBPF Program Development Guide

This guide explains how to develop new eBPF monitoring programs for the eBPF Network Monitor server. The server uses a modular architecture where each eBPF program operates independently and contributes events to a unified event stream and storage system.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Program Structure](#program-structure)
- [Core Interfaces](#core-interfaces)
- [Step-by-Step Implementation](#step-by-step-implementation)
- [Event System](#event-system)
- [Manager Integration](#manager-integration)
- [API Integration](#api-integration)
- [Testing Your Program](#testing-your-program)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Architecture Overview

The eBPF server follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                        System Layer                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Manager                                  │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
│  │  │ Connection  │  │ Packet Drop │  │   Your New  │       │  │
│  │  │ Program     │  │ Program     │  │   Program   │       │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                   ┌────────┴────────┐
                   │                 │
          ┌────────▼────────┐  ┌─────▼─────┐
          │ Event Storage   │  │ HTTP API  │
          │ (Unified)       │  │ Handlers  │
          └─────────────────┘  └───────────┘
```

### Key Components

1. **Core Interfaces**: Define contracts for Events, Programs, Managers, and Storage
2. **Event System**: Unified event creation, streaming, and storage
3. **Program Manager**: Coordinates program lifecycle and provides unified event streams
4. **Storage Layer**: Persistent event storage with query capabilities  
5. **API Layer**: HTTP endpoints for querying events and program status
6. **System Layer**: Top-level coordination and initialization

## Program Structure

A typical eBPF monitoring program consists of:

```
internal/programs/your_program/
├── your_program.go       # Main program implementation  
├── your_program_test.go  # Unit tests
└── README.md            # Program-specific documentation
```

Plus the eBPF C code:

```
bpf/
├── your_program.c       # eBPF kernel code
└── your_program.o       # Compiled object (auto-generated)
```

## Core Interfaces

### Event Interface

All events must implement the `core.Event` interface:

```go
type Event interface {
    ID() string                           // Unique event identifier
    Type() string                         // Event type (e.g., "connection")
    PID() uint32                         // Process ID
    Command() string                     // Command name
    Timestamp() uint64                   // Kernel timestamp (nanoseconds)
    Time() time.Time                     // Wall clock time
    Metadata() map[string]interface{}    // Event-specific data
    json.Marshaler                       // JSON serialization
}
```

### Program Interface  

All eBPF programs must implement the `core.Program` interface:

```go
type Program interface {
    Name() string                        // Program name
    Description() string                 // Human-readable description
    Load(ctx context.Context) error      // Load program into kernel
    Attach(ctx context.Context) error    // Attach to kernel hooks
    Detach(ctx context.Context) error    // Detach from kernel
    IsLoaded() bool                      // Check if loaded
    IsAttached() bool                    // Check if attached
    EventStream() EventStream            // Get event stream
}
```
## Step-by-Step Implementation

### 1. Create Directory Structure

```bash
mkdir -p internal/programs/your_program
```

### 2. Implement Your Program

Create `internal/programs/your_program/your_program.go`:

```go
package your_program

import (
    "context"
    "fmt"
    
    "github.com/srodi/ebpf-server/internal/core"
    "github.com/srodi/ebpf-server/internal/events"
    "github.com/srodi/ebpf-server/internal/programs"
    "github.com/srodi/ebpf-server/pkg/logger"
)

const (
    // Program configuration
    ProgramName        = "your_program"
    ProgramDescription = "Describe what your program monitors"
    ObjectPath         = "bpf/your_program.o"
    
    // eBPF program and map names (must match your C code)
    TracepointProgram = "your_trace_function"
    EventsMapName     = "events"
    
    // Tracepoint/probe configuration
    TracepointGroup = "syscalls"     // or appropriate subsystem
    TracepointName  = "your_event"   // specific tracepoint
)

// Program implements your custom eBPF monitoring program.
type Program struct {
    *programs.BaseProgram
}

// NewProgram creates a new instance of your monitoring program.
func NewProgram() *Program {
    base := programs.NewBaseProgram(ProgramName, ProgramDescription, ObjectPath)
    return &Program{
        BaseProgram: base,
    }
}

// Attach attaches the program to the appropriate kernel hooks.
func (p *Program) Attach(ctx context.Context) error {
    if !p.IsLoaded() {
        return fmt.Errorf("program not loaded")
    }
    
    logger.Debugf("Attaching %s monitoring program", ProgramName)
    
    // Attach to tracepoint (modify based on your hook type)
    if err := p.AttachTracepoint(TracepointGroup, TracepointName, TracepointProgram); err != nil {
        return fmt.Errorf("failed to attach tracepoint: %w", err)
    }
    
    // Start event processing
    if err := p.StartEventProcessing(ctx, EventsMapName, p.parseEvent); err != nil {
        return fmt.Errorf("failed to start event processing: %w", err)
    }
    
    p.SetAttached(true)
    logger.Debugf("✅ %s program attached successfully", ProgramName)
    return nil
}

// parseEvent converts raw eBPF event data into structured events.
func (p *Program) parseEvent(data []byte) (core.Event, error) {
    // Parse your event structure - this depends on your C struct
    if len(data) < 24 { // Adjust based on your struct size
        return nil, fmt.Errorf("event data too short: %d bytes", len(data))
    }
    
    // Example parsing (adjust to match your C struct):
    pid := binary.LittleEndian.Uint32(data[0:4])
    timestamp := binary.LittleEndian.Uint64(data[4:12])
    // ... parse other fields
    
    // Extract command name
    command := extractNullTerminatedString(data[12:])
    
    // Create metadata with your specific fields
    metadata := map[string]interface{}{
        "your_field1": "your_value1",
        "your_field2": 42,
        // Add your program-specific data
    }
    
    return events.NewBaseEvent(ProgramName, pid, command, timestamp, metadata), nil
}

// Utility function to extract null-terminated strings from binary data
func extractNullTerminatedString(data []byte) string {
    for i, b := range data {
        if b == 0 {
            return string(data[:i])
        }
    }
    return string(data)
}
```

### 3. Create eBPF C Code

Create `bpf/your_program.c`:

```c
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

// Event structure (must match your Go parsing)
struct your_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
    // Add your specific fields
    u32 your_field1;
    u64 your_field2;
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/your_event")
int trace_your_event(struct trace_event_raw_sys_enter* ctx) {
    struct your_event *event;
    struct task_struct *task;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Get current task
    task = (struct task_struct*)bpf_get_current_task();
    
    // Fill event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Add your specific logic here
    event->your_field1 = /* your logic */;
    event->your_field2 = /* your logic */;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 4. Register Your Program

Add your program to the system initialization in `internal/system/system.go`:

```go
// In the Initialize() method:
yourProgram := your_program.NewProgram()
if err := s.manager.RegisterProgram(yourProgram); err != nil {
    return fmt.Errorf("failed to register your program: %w", err)
}
logger.Debugf("✅ Registered your monitoring program")
```

### 5. Update Build System

Add your eBPF program to the Makefile:

```makefile
# Add to BPF_SOURCES
BPF_SOURCES := $(wildcard bpf/*.c)
```

The existing build system will automatically compile your `.c` file to `.o`.
    Timestamp    uint64 `json:"timestamp_ns"`
    Command      string `json:"command"`
    CustomField1 uint32 `json:"custom_field1"`
    CustomField2 string `json:"custom_field2"`
    WallTime     string `json:"wall_time"`
    Note         string `json:"note"`
}

func (e *Event) MarshalJSON() ([]byte, error) {
    return json.Marshal(EventJSON{
        PID:          e.GetPID(),
        Timestamp:    e.GetTimestamp(),
        Command:      e.GetCommand(),
        CustomField1: e.CustomField1,
        CustomField2: e.CustomField2,
        WallTime:     e.GetWallClockTime().Format(time.RFC3339),
        Note:         "timestamp_ns is nanoseconds since boot, wall_time is converted to UTC",
    })
}
```

### 3. Implement Program Interface

Create `internal/bpf/programs/your_program/program.go`:

```go
package your_program

import (
    "context"
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/srodi/ebpf-server/internal/bpf"
    "github.com/srodi/ebpf-server/pkg/logger"
)

type Program struct {
    name        string
    description string
    objectPath  string
    
    // eBPF resources
    collection *ebpf.Collection
    eventsMap  *ebpf.Map
    links      []link.Link
    reader     *ringbuf.Reader
    
    // Event processing
    eventChan chan bpf.BPFEvent
    ctx       context.Context
    cancel    context.CancelFunc
    running   bool
    
    // Storage
    storage bpf.EventStorage
}

func NewProgram(storage bpf.EventStorage) *Program {
    return &Program{
        name:        "your_program",
        description: "Describe what your program monitors",
        objectPath:  "bpf/your_program.o",
        eventChan:   make(chan bpf.BPFEvent, 1000),
        storage:     storage,
    }
}

// Interface implementation
func (p *Program) GetName() string { return p.name }
func (p *Program) GetDescription() string { return p.description }
func (p *Program) GetObjectPath() string { return p.objectPath }

func (p *Program) Load() error {
    spec, err := ebpf.LoadCollectionSpec(p.objectPath)
    if err != nil {
        return fmt.Errorf("failed to load collection spec: %w", err)
    }
    
    collection, err := ebpf.NewCollection(spec)
    if err != nil {
        return fmt.Errorf("failed to create collection: %w", err)
    }
    
    p.collection = collection
    p.eventsMap = collection.Maps["your_events_map"]
    return nil
}

func (p *Program) Attach() error {
    // Attach to appropriate kernel hooks
    // Example for tracepoint:
    l, err := link.Tracepoint(link.TracepointOptions{
        Group:   "your_subsystem",
        Name:    "your_tracepoint",
        Program: p.collection.Programs["your_program_function"],
    })
    if err != nil {
        return fmt.Errorf("failed to attach tracepoint: %w", err)
    }
    p.links = append(p.links, l)
    return nil
}

func (p *Program) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    
    reader, err := ringbuf.NewReader(p.eventsMap)
    if err != nil {
        return fmt.Errorf("failed to create ring buffer reader: %w", err)
    }
    p.reader = reader
    
    p.running = true
    go p.processEvents()
    
    return nil
}

func (p *Program) Stop() error {
    if p.cancel != nil {
        p.cancel()
    }
    
    if p.reader != nil {
        p.reader.Close()
    }
    
    for _, l := range p.links {
        l.Close()
    }
    
    if p.collection != nil {
        p.collection.Close()
    }
    
    p.running = false
    return nil
}

func (p *Program) IsRunning() bool { return p.running }

func (p *Program) GetEventChannel() <-chan bpf.BPFEvent {
    return p.eventChan
}

func (p *Program) GetSummary(pid uint32, command string, durationSeconds int) int {
    // Implement summary logic using storage
    since := bpf.GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
    events, _ := p.storage.Get(pid, command, p.name, since)
    return len(events)
}

func (p *Program) GetAllEvents() map[uint32][]bpf.BPFEvent {
    // Return all events from storage
    allEvents := p.storage.GetAll()
    if events, exists := allEvents[p.name]; exists {
        return events
    }
    return make(map[uint32][]bpf.BPFEvent)
}

// Private methods
func (p *Program) processEvents() {
    logger.Info("Starting your_program event processing...")
    
    for {
        select {
        case <-p.ctx.Done():
            logger.Info("Stopping your_program event processing...")
            return
        default:
            record, err := p.reader.Read()
            if err != nil {
                if p.ctx.Err() != nil {
                    return
                }
                logger.Errorf("Error reading from your_program ring buffer: %v", err)
                continue
            }
            
            if err := p.processEvent(record.RawSample); err != nil {
                logger.Errorf("Error processing your_program event: %v", err)
            }
        }
    }
}

func (p *Program) processEvent(data []byte) error {
    // Parse the raw event data from eBPF
    // This depends on your C struct layout
    
    event := &Event{
        BaseEvent: bpf.BaseEvent{
            // Parse fields from data...
        },
        // Parse custom fields...
    }
    
    // Store event
    p.storage.Store(event)
    
    // Send to channel for real-time processing
    select {
    case p.eventChan <- event:
    default:
        logger.Warn("Event channel full, dropping event")
    }
    
    return nil
}
```

### 4. Write eBPF C Code

Create `bpf/your_program.c`:

```c
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Event structure (must match Go struct layout)
struct your_event_t {
    u32 pid;
    u64 ts;
    char comm[16];
    u32 custom_field1;
    char custom_field2[64];
    u8 padding[8];  // Ensure alignment
} __attribute__((packed));

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} your_events_map SEC(".maps");

// Your eBPF program
SEC("tracepoint/your_subsystem/your_tracepoint")
int your_program_function(void *ctx) {
    struct your_event_t *event;
    u64 pid_tgid;
    u32 pid;
    
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&your_events_map, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    
    // Fill event data
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Add your custom logic here
    event->custom_field1 = /* your logic */;
    // event->custom_field2 = /* your logic */;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### 5. Register Your Program

Add to `internal/bpf/loader.go` in the `registerDefaultPrograms()` function:

```go
// Register your program
yourProgram := your_program.NewProgram(storage)
if err := globalManager.RegisterProgram(yourProgram); err != nil {
    return fmt.Errorf("failed to register your_program: %w", err)
}
```

### 6. Build and Test

```bash
# Compile eBPF code
make build-bpf

# Run tests
go test ./internal/bpf/programs/your_program/...

# Build and test the server
make build
sudo ./bin/ebpf-server
```

## Interface Requirements

### BPFProgram Interface

All programs must implement:

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

### BPFEvent Interface

All events must implement:

```go
type BPFEvent interface {
    GetPID() uint32
    GetTimestamp() uint64
    GetCommand() string
    GetEventType() string
    GetWallClockTime() time.Time
}
```

## Event System

The event system provides a unified way to handle events across all eBPF programs:

### BaseEvent Structure

Use the `events.BaseEvent` for most cases:

```go
// Create an event using the events package
event := events.NewBaseEvent(
    "your_program",    // event type
    pid,              // process ID
    command,          // command name
    timestamp,        // kernel timestamp
    metadata,         // map[string]interface{} with custom data
)
```

### Custom Events

For complex events, you can implement the `core.Event` interface directly:

```go
type CustomEvent struct {
    id        string
    pid       uint32
    timestamp uint64
    // your custom fields
}

func (e *CustomEvent) ID() string { return e.id }
func (e *CustomEvent) Type() string { return "your_program" }
func (e *CustomEvent) PID() uint32 { return e.pid }
// ... implement other required methods
```

### Event Streaming

Events flow through this pipeline:

```
eBPF Program → Ring Buffer → Event Parser → Event Stream → Storage/API
```

1. **eBPF Program**: Writes events to ring buffer
2. **Event Parser**: Converts binary data to Go structs
3. **Event Stream**: Provides channel-based event delivery
4. **Storage**: Persists events for querying
5. **API**: Exposes events via HTTP endpoints

## Manager Integration

The Manager coordinates all programs and provides unified interfaces:

### Program Registration

```go
// Programs are registered during system initialization
manager := programs.NewManager()

// Register your program
program := your_program.NewProgram()
if err := manager.RegisterProgram(program); err != nil {
    return fmt.Errorf("failed to register program: %w", err)
}

// Lifecycle management
ctx := context.Background()
if err := manager.LoadAll(ctx); err != nil {
    return fmt.Errorf("failed to load programs: %w", err)
}

if err := manager.AttachAll(ctx); err != nil {
    return fmt.Errorf("failed to attach programs: %w", err)
}

// Get unified event stream
eventStream := manager.EventStream()
for event := range eventStream.Events() {
    // Process events from all programs
}
```

### Program Status

The manager provides program status information:

```go
type ProgramStatus struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Loaded      bool   `json:"loaded"`
    Attached    bool   `json:"attached"`
    EventCount  int64  `json:"event_count"`
}

// Get status of all programs
statuses := manager.GetProgramStatus()
```

## Event Storage Integration

Events are automatically stored in the unified storage system. The storage interface provides:

### Storage Operations

```go
type EventSink interface {
    // Store saves an event
    Store(ctx context.Context, event Event) error
    
    // Query retrieves events matching the given criteria
    Query(ctx context.Context, query Query) ([]Event, error)
    
    // Count returns the number of events matching the criteria
    Count(ctx context.Context, query Query) (int, error)
}
```

### Query Structure

```go
type Query struct {
    EventType string       // Filter by event type (e.g., "your_program")
    PID       uint32       // Filter by process ID (0 = no filter)
    Command   string       // Filter by command name
    Since     time.Time    // Events after this time
    Until     time.Time    // Events before this time  
    Limit     int          // Maximum number of results (0 = no limit)
}
```

### Usage Examples

```go
// Query all events from your program
query := core.Query{
    EventType: "your_program",
    Since:     time.Now().Add(-1 * time.Hour),
    Limit:     100,
}

events, err := storage.Query(ctx, query)

// Count events for specific PID
query := core.Query{
    EventType: "your_program", 
    PID:       1234,
}

count, err := storage.Count(ctx, query)
```

## API Integration

The HTTP API provides automatic endpoints for all events:

### Built-in Endpoints

All programs automatically get access to:

- `GET /api/events` - Query events with comprehensive filtering
- `GET /api/programs` - List all programs and their status
- `GET /health` - System health and status
- `GET /api/list-connections` - Connection events (from connection program)
- `GET /api/list-packet-drops` - Packet drop events (from packet_drop program)

### Event Query Parameters

The `/api/events` endpoint supports:

```
GET /api/events?type=your_program&pid=1234&command=curl&since=2023-01-01T00:00:00Z&limit=100
```

Parameters:
- `type`: Event type filter
- `pid`: Process ID filter  
- `command`: Command name filter
- `since`: RFC3339 timestamp for start time
- `until`: RFC3339 timestamp for end time
- `limit`: Maximum results (default: 100)

### Program Status API

```
GET /api/programs
```

Returns:
```json
{
  "programs": [
    {
      "name": "your_program",
      "description": "Your program description", 
      "loaded": true,
      "attached": true,
      "event_count": 1234
    }
  ],
  "total_programs": 3,
  "running_programs": 2
}
```

### Custom Endpoints (Optional)

Add custom endpoints in `internal/api/handlers.go`:

```go
// @Summary Get your program statistics
// @Description Returns metrics for your custom monitoring program
// @Tags your_program
// @Accept json
// @Produce json
// @Param pid query int false "Process ID filter"
// @Param duration_seconds query int false "Time window in seconds"
// @Success 200 {object} YourProgramResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/your_program/summary [get]
func HandleYourProgramSummary(w http.ResponseWriter, r *http.Request) {
    if globalSystem == nil {
        http.Error(w, "System not initialized", http.StatusServiceUnavailable)
        return
    }
    
    // Parse query parameters
    var pid uint32
    if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
        if pidVal, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
            pid = uint32(pidVal)
        }
    }
    
    duration := 60 // default
    if durationStr := r.URL.Query().Get("duration_seconds"); durationStr != "" {
        if durationVal, err := strconv.Atoi(durationStr); err == nil {
            duration = durationVal
        }
    }
    
    // Build query for your program
    query := core.Query{
        EventType: "your_program",
        PID:       pid,
        Since:     time.Now().Add(-time.Duration(duration) * time.Second),
    }
    
    // Get event count
    ctx := context.Background()
    count, err := globalSystem.CountEvents(ctx, query)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    // Return response
    response := map[string]interface{}{
        "count":            count,
        "pid":              pid,
        "duration_seconds": duration,
        "query_time":       time.Now().Format(time.RFC3339),
    }
    
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(response); err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
    }
}
```

Register your custom endpoint in `cmd/server/main.go`:

```go
// Add to the HTTP routes setup
mux.HandleFunc("/api/your_program/summary", api.HandleYourProgramSummary)
```

## Testing Your Program

Create comprehensive tests for your program:

### 1. Unit Tests

Create `internal/programs/your_program/your_program_test.go`:

```go
package your_program

import (
    "context"
    "testing"
    
    "github.com/srodi/ebpf-server/internal/events"
)

func TestProgram(t *testing.T) {
    program := NewProgram()
    
    // Test basic properties
    if program.Name() != ProgramName {
        t.Errorf("Expected name %s, got %s", ProgramName, program.Name())
    }
    
    if program.Description() != ProgramDescription {
        t.Errorf("Expected description %s, got %s", ProgramDescription, program.Description())
    }
    
    // Test initial state
    if program.IsLoaded() {
        t.Error("Program should not be loaded initially")
    }
    
    if program.IsAttached() {
        t.Error("Program should not be attached initially")
    }
}

func TestEventParser(t *testing.T) {
    program := NewProgram()
    
    // Create mock event data (adjust based on your C struct)
    eventData := make([]byte, 24)
    // Fill with test data matching your struct
    // pid (4 bytes)
    binary.LittleEndian.PutUint32(eventData[0:4], 1234)
    // timestamp (8 bytes)  
    binary.LittleEndian.PutUint64(eventData[4:12], uint64(time.Now().UnixNano()))
    // command (12 bytes)
    copy(eventData[12:], []byte("test_cmd\x00"))
    
    event, err := program.parseEvent(eventData)
    if err != nil {
        t.Fatalf("Failed to parse event: %v", err)
    }
    
    if event.Type() != ProgramName {
        t.Errorf("Expected event type %s, got %s", ProgramName, event.Type())
    }
    
    if event.PID() != 1234 {
        t.Errorf("Expected PID 1234, got %d", event.PID())
    }
    
    if event.Command() != "test_cmd" {
        t.Errorf("Expected command 'test_cmd', got '%s'", event.Command())
    }
}

func TestParseInvalidData(t *testing.T) {
    program := NewProgram()
    
    // Test with insufficient data
    _, err := program.parseEvent([]byte{1, 2, 3})
    if err == nil {
        t.Error("Expected error for insufficient data")
    }
}
```

### 2. Integration Tests

```go
func TestProgramIntegration(t *testing.T) {
    // Skip integration tests in unit test mode
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }
    
    ctx := context.Background()
    program := NewProgram()
    
    // Test loading (requires eBPF object file)
    if err := program.Load(ctx); err != nil {
        t.Skipf("Cannot load program (missing object file): %v", err)
    }
    
    if !program.IsLoaded() {
        t.Error("Program should be loaded after Load()")
    }
    
    // Cleanup
    if err := program.Detach(ctx); err != nil {
        t.Errorf("Failed to detach program: %v", err)
    }
}
```

### 3. Mock Testing

For testing without eBPF:

```go
type MockProgram struct {
    name     string
    loaded   bool
    attached bool
    stream   *events.ChannelStream
}

func (m *MockProgram) Name() string { return m.name }
func (m *MockProgram) Load(ctx context.Context) error { m.loaded = true; return nil }
func (m *MockProgram) Attach(ctx context.Context) error { m.attached = true; return nil }
// ... implement other methods

func TestWithMock(t *testing.T) {
    mock := &MockProgram{
        name:   "mock_program",
        stream: events.NewChannelStream(10),
    }
    
    // Test program behavior without eBPF
    ctx := context.Background()
    if err := mock.Load(ctx); err != nil {
        t.Fatalf("Mock load failed: %v", err)
    }
    
    if !mock.loaded {
        t.Error("Mock should be loaded")
    }
}
```

### 4. Event Testing

Test event creation and serialization:

```go
func TestEventCreation(t *testing.T) {
    metadata := map[string]interface{}{
        "test_field": "test_value",
        "test_number": 42,
    }
    
    event := events.NewBaseEvent(
        "your_program",
        1234,
        "test_cmd", 
        uint64(time.Now().UnixNano()),
        metadata,
    )
    
    // Test event properties
    if event.Type() != "your_program" {
        t.Errorf("Expected type 'your_program', got %s", event.Type())
    }
    
    if event.PID() != 1234 {
        t.Errorf("Expected PID 1234, got %d", event.PID())
    }
    
    // Test metadata
    eventMetadata := event.Metadata()
    if eventMetadata["test_field"] != "test_value" {
        t.Errorf("Expected test_field 'test_value', got %v", eventMetadata["test_field"])
    }
    
    // Test JSON serialization
    jsonData, err := event.MarshalJSON()
    if err != nil {
        t.Fatalf("JSON marshaling failed: %v", err)
    }
    
    var unmarshaled map[string]interface{}
    if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
        t.Fatalf("JSON unmarshaling failed: %v", err)
    }
    
    if unmarshaled["type"] != "your_program" {
        t.Errorf("Expected JSON type 'your_program', got %v", unmarshaled["type"])
    }
}
```

### 5. Running Tests

```bash
# Run unit tests
go test ./internal/programs/your_program

# Run with verbose output  
go test -v ./internal/programs/your_program

# Run with race detection
go test -race ./internal/programs/your_program

# Run all tests
go test ./...

# Run integration tests (longer)
go test -v ./internal/programs/your_program -tags=integration
```
    }
    
    // Verify JSON contains expected fields
    jsonStr := string(data)
    if !strings.Contains(jsonStr, "\"custom_field1\":42") {
        t.Errorf("JSON should contain custom_field1")
    }
}

func TestYourProgramCreation(t *testing.T) {
    storage := bpf.NewMemoryStorage()
    program := NewProgram(storage)
    
    if program.GetName() != "your_program" {
        t.Errorf("Expected name 'your_program', got '%s'", program.GetName())
    }
    
    if program.IsRunning() {
        t.Error("Program should not be running initially")
    }
}
```

## Best Practices

### eBPF Code

1. **Keep it simple**: eBPF has limitations, avoid complex logic in kernel space
2. **Check bounds**: Always validate array/buffer access to prevent verifier rejection
3. **Handle errors**: Check return values from BPF helpers
4. **Minimize stack usage**: eBPF stack is limited to 512 bytes
5. **Use ring buffers**: Prefer ring buffers over perf buffers for event delivery
6. **Struct alignment**: Ensure consistent memory layout between C and Go

Example of safe eBPF code:

```c
SEC("tracepoint/syscalls/sys_enter_your_syscall")
int trace_your_syscall(struct trace_event_raw_sys_enter* ctx) {
    struct your_event *event;
    
    // Always check ring buffer allocation
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;  // Failed to allocate, but don't crash
    }
    
    // Safe field access
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    
    // Safe string operations
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Always submit or discard
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### Go Code

1. **Error handling**: Always handle errors, especially from eBPF operations
2. **Context awareness**: Respect cancellation contexts for graceful shutdown
3. **Resource cleanup**: Properly clean up eBPF resources
4. **Thread safety**: Use appropriate synchronization for concurrent access
5. **Structured logging**: Use the logger package for consistent debugging
6. **Interface compliance**: Implement all required interface methods

Example of robust Go implementation:

```go
func (p *Program) Attach(ctx context.Context) error {
    if !p.IsLoaded() {
        return fmt.Errorf("program not loaded")
    }
    
    logger.Debugf("Attaching %s program", p.Name())
    
    // Use context for cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // Attach with proper error handling
    if err := p.AttachTracepoint(TracepointGroup, TracepointName, TracepointProgram); err != nil {
        return fmt.Errorf("failed to attach tracepoint: %w", err)
    }
    
    // Start processing with context
    if err := p.StartEventProcessing(ctx, EventsMapName, p.parseEvent); err != nil {
        // Clean up on failure
        p.Detach(ctx)
        return fmt.Errorf("failed to start event processing: %w", err)
    }
    
    p.SetAttached(true)
    logger.Debugf("✅ %s program attached successfully", p.Name())
    return nil
}
```

### Performance

1. **Ring buffer sizing**: Choose appropriate buffer sizes (256KB is often good)
2. **Event filtering**: Filter events in eBPF when possible to reduce overhead
3. **Batch processing**: Process multiple events efficiently  
4. **Memory management**: Avoid excessive allocations in hot paths
5. **Efficient parsing**: Parse only necessary fields from binary data

### Error Handling

1. **Graceful degradation**: Continue operation if non-critical features fail
2. **Meaningful errors**: Provide context in error messages
3. **Proper cleanup**: Always clean up resources on errors
4. **Logging**: Log errors with appropriate levels

## Examples

### Simple Tracepoint Program

See `internal/programs/packet_drop/` for a complete tracepoint-based program that:
- Monitors kernel packet drop events
- Extracts drop reason and packet information
- Provides structured events with metadata

### Syscall Monitoring Program  

See `internal/programs/connection/` for a syscall-based program that:
- Monitors `connect()` system calls
- Extracts network connection details
- Handles IPv4/IPv6 addresses and port information

### Custom Program Structure

Here's a minimal template for a new program:

```bash
# 1. Create program directory
mkdir -p internal/programs/my_monitor

# 2. Create main program file
cat > internal/programs/my_monitor/my_monitor.go << 'EOF'
package my_monitor

import (
    "context"
    "encoding/binary"
    "fmt"
    
    "github.com/srodi/ebpf-server/internal/core"
    "github.com/srodi/ebpf-server/internal/events"
    "github.com/srodi/ebpf-server/internal/programs"
    "github.com/srodi/ebpf-server/pkg/logger"
)

const (
    ProgramName        = "my_monitor"
    ProgramDescription = "Monitors custom kernel events"
    ObjectPath         = "bpf/my_monitor.o"
    TracepointProgram  = "trace_my_event"
    EventsMapName      = "events"
    TracepointGroup    = "custom"
    TracepointName     = "my_event"
)

type Program struct {
    *programs.BaseProgram
}

func NewProgram() *Program {
    base := programs.NewBaseProgram(ProgramName, ProgramDescription, ObjectPath)
    return &Program{BaseProgram: base}
}

func (p *Program) Attach(ctx context.Context) error {
    if !p.IsLoaded() {
        return fmt.Errorf("program not loaded")
    }
    
    logger.Debugf("Attaching %s program", ProgramName)
    
    if err := p.AttachTracepoint(TracepointGroup, TracepointName, TracepointProgram); err != nil {
        return fmt.Errorf("failed to attach: %w", err)
    }
    
    if err := p.StartEventProcessing(ctx, EventsMapName, p.parseEvent); err != nil {
        return fmt.Errorf("failed to start processing: %w", err)
    }
    
    p.SetAttached(true)
    return nil
}

func (p *Program) parseEvent(data []byte) (core.Event, error) {
    if len(data) < 24 {
        return nil, fmt.Errorf("insufficient data: %d bytes", len(data))
    }
    
    pid := binary.LittleEndian.Uint32(data[0:4])
    timestamp := binary.LittleEndian.Uint64(data[4:12])
    command := extractNullTerminatedString(data[12:])
    
    metadata := map[string]interface{}{
        "custom_field": "custom_value",
    }
    
    return events.NewBaseEvent(ProgramName, pid, command, timestamp, metadata), nil
}

func extractNullTerminatedString(data []byte) string {
    for i, b := range data {
        if b == 0 {
            return string(data[:i])
        }
    }
    return string(data)
}
EOF

# 3. Create corresponding eBPF C code
cat > bpf/my_monitor.c << 'EOF'
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct my_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/custom/my_event")
int trace_my_event(void *ctx) {
    struct my_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

# 4. Register in system
# Add to internal/system/system.go Initialize() method:
# myProgram := my_monitor.NewProgram()
# if err := s.manager.RegisterProgram(myProgram); err != nil {
#     return fmt.Errorf("failed to register my_monitor: %w", err)
# }
```

## Troubleshooting

### Common Issues

1. **Program won't load**: 
   - Check eBPF verifier errors: `dmesg | grep bpf`
   - Verify struct sizes and alignment
   - Ensure all code paths are verified by the kernel

2. **No events received**:
   - Verify tracepoint/kprobe exists: `ls /sys/kernel/debug/tracing/events/`
   - Check if events are being generated: `cat /sys/kernel/debug/tracing/trace_pipe`
   - Validate ring buffer setup and reading

3. **Permission errors**:
   - Run with appropriate privileges (usually root)
   - Check if BPF is enabled: `cat /proc/sys/kernel/unprivileged_bpf_disabled`
   - Verify cgroup permissions for containers

4. **Memory access violations**:
   - Check struct alignment between C and Go
   - Validate all memory accesses in eBPF code
   - Use `bpf_core_read()` for safe kernel memory access

### Debugging Tools

1. **eBPF Tools**:
   ```bash
   # List loaded programs
   sudo bpftool prog list
   
   # Show program details
   sudo bpftool prog show id <id>
   
   # List maps
   sudo bpftool map list
   
   # Dump map contents
   sudo bpftool map dump id <id>
   ```

2. **Kernel Tracing**:
   ```bash
   # View trace output
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   
   # Check available tracepoints
   sudo ls /sys/kernel/debug/tracing/events/
   
   # Enable specific tracepoint
   echo 1 | sudo tee /sys/kernel/debug/tracing/events/your_subsystem/your_event/enable
   ```

3. **Application Debugging**:
   ```bash
   # Run with debug logging
   EBPF_DEBUG=1 ./ebpf-server
   
   # Race detection during testing
   go test -race ./internal/programs/your_program
   
   # Memory profiling
   go test -memprofile=mem.prof ./internal/programs/your_program
   ```

### Development Tips

1. **Start incrementally**: Begin with simple event capture, add complexity gradually
2. **Use existing programs**: Study `connection` and `packet_drop` programs as templates  
3. **Test eBPF separately**: Use `bpf_printk()` and trace_pipe for initial debugging
4. **Validate structs**: Ensure C and Go struct layouts match exactly
5. **Handle edge cases**: Test with various input conditions and error scenarios
6. **Document your program**: Add clear comments and documentation
7. **Version compatibility**: Test with different kernel versions if targeting multiple systems

## Summary

This guide covered the complete process of developing eBPF monitoring programs for the eBPF Network Monitor:

1. **Architecture**: Understanding the modular, interface-based design
2. **Implementation**: Creating programs using BaseProgram and core interfaces  
3. **Events**: Using the unified event system with BaseEvent
4. **Integration**: Registering with the Manager and System
5. **API**: Automatic HTTP endpoints and custom endpoint creation
6. **Testing**: Comprehensive testing strategies from unit to integration tests
7. **Best Practices**: Performance, security, and maintainability guidelines

The current architecture provides a solid foundation for adding new monitoring capabilities while maintaining consistency and reliability across all programs.

For additional examples and implementation details, examine the existing programs in `internal/programs/connection/` and `internal/programs/packet_drop/`.
