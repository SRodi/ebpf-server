# Program Development Guide

This guide shows how to create new eBPF monitoring programs for the server.

## Program Structure

Each eBPF program consists of:

1. **eBPF C Code** (`bpf/your_program.c`) - Kernel-space monitoring logic
2. **Event Type** (`internal/bpf/programs/your_program/event.go`) - Event data structure
3. **Program Handler** (`internal/bpf/programs/your_program/program.go`) - User-space event processing
4. **Registration** - Add to manager for automatic loading

## Step-by-Step Guide

### 1. Create eBPF C Program

Create `bpf/your_program.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Event structure (must match Go struct)
struct your_event {
    __u32 pid;
    __u64 ts;
    char comm[16];
    // Your custom fields
    __u32 custom_field;
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hook function
SEC("tracepoint/your_category/your_tracepoint")
int trace_your_event(struct trace_event_raw_your_tracepoint *ctx) {
    struct your_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Your custom logic
    event->custom_field = ctx->some_field;
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 2. Create Event Type

Create `internal/bpf/programs/your_program/event.go`:

```go
package your_program

import (
    "encoding/json"
    "time"
    "github.com/srodi/ebpf-server/internal/bpf"
)

// Event represents your custom event type
type Event struct {
    bpf.BaseEvent         // Embeds PID, TS, Comm
    CustomField uint32    `json:"custom_field"`
}

// GetEventType returns the event type identifier
func (e *Event) GetEventType() string {
    return "your_program"
}

// GetCustomInfo returns program-specific event information
func (e *Event) GetCustomInfo() map[string]interface{} {
    return map[string]interface{}{
        "custom_field": e.CustomField,
        "description": "Your event description",
    }
}

// String returns a human-readable event description
func (e *Event) String() string {
    return fmt.Sprintf("YourEvent: PID=%d, Command=%s, CustomField=%d, Time=%s",
        e.PID, e.GetCommand(), e.CustomField, e.GetWallClockTime().Format(time.RFC3339))
}

// MarshalJSON customizes JSON output
func (e *Event) MarshalJSON() ([]byte, error) {
    return json.Marshal(struct {
        PID         uint32    `json:"pid"`
        Timestamp   uint64    `json:"timestamp"`
        Command     string    `json:"command"`
        WallTime    time.Time `json:"wall_time"`
        EventType   string    `json:"event_type"`
        CustomField uint32    `json:"custom_field"`
    }{
        PID:         e.PID,
        Timestamp:   e.TS,
        Command:     e.GetCommand(),
        WallTime:    e.GetWallClockTime(),
        EventType:   e.GetEventType(),
        CustomField: e.CustomField,
    })
}
```

### 3. Create Program Handler

Create `internal/bpf/programs/your_program/program.go`:

```go
package your_program

import (
    "context"
    "encoding/binary"
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/srodi/ebpf-server/internal/bpf"
    "github.com/srodi/ebpf-server/pkg/logger"
)

// Program implements the BPFProgram interface for your monitoring
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

// NewProgram creates a new instance of your program
func NewProgram(storage bpf.EventStorage) *Program {
    return &Program{
        name:        "your_program",
        description: "Description of what your program monitors",
        objectPath:  "bpf/your_program.o",
        eventChan:   make(chan bpf.BPFEvent, 1000),
        storage:     storage,
    }
}

// Implement required BPFProgram interface methods
func (p *Program) GetName() string        { return p.name }
func (p *Program) GetDescription() string { return p.description }
func (p *Program) GetObjectPath() string  { return p.objectPath }
func (p *Program) IsRunning() bool        { return p.running }
func (p *Program) GetEventChannel() <-chan bpf.BPFEvent { return p.eventChan }

// Load compiles and loads the eBPF program
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
    p.eventsMap = collection.Maps["events"]

    logger.Infof("Your program loaded from %s", p.objectPath)
    return nil
}

// Attach attaches the program to kernel hooks
func (p *Program) Attach() error {
    if p.collection == nil {
        return fmt.Errorf("program not loaded")
    }

    prog := p.collection.Programs["trace_your_event"]
    if prog == nil {
        return fmt.Errorf("trace_your_event program not found")
    }

    // Attach to tracepoint
    tp, err := link.Tracepoint("your_category", "your_tracepoint", prog, nil)
    if err != nil {
        return fmt.Errorf("failed to attach tracepoint: %w", err)
    }

    p.links = append(p.links, tp)

    // Create ring buffer reader
    reader, err := ringbuf.NewReader(p.eventsMap)
    if err != nil {
        tp.Close()
        return fmt.Errorf("failed to create ring buffer reader: %w", err)
    }

    p.reader = reader
    logger.Info("Your program attached to tracepoint")
    return nil
}

// Start begins event processing
func (p *Program) Start(ctx context.Context) error {
    if p.reader == nil {
        return fmt.Errorf("program not attached")
    }

    if p.running {
        return fmt.Errorf("program already running")
    }

    p.ctx, p.cancel = context.WithCancel(ctx)
    p.running = true

    go p.processEvents()

    logger.Info("Your program started")
    return nil
}

// Stop stops event processing and cleans up
func (p *Program) Stop() error {
    if !p.running {
        return nil
    }

    if p.cancel != nil {
        p.cancel()
    }

    if p.reader != nil {
        p.reader.Close()
        p.reader = nil
    }

    for _, l := range p.links {
        if l != nil {
            l.Close()
        }
    }
    p.links = nil

    if p.collection != nil {
        p.collection.Close()
        p.collection = nil
    }

    p.running = false
    close(p.eventChan)

    logger.Info("Your program stopped")
    return nil
}

// GetSummary returns event statistics
func (p *Program) GetSummary(pid uint32, command string, durationSeconds int) int {
    since := bpf.GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
    return p.storage.Count(pid, command, p.name, since)
}

// GetAllEvents returns all events for this program
func (p *Program) GetAllEvents() map[uint32][]bpf.BPFEvent {
    allEvents := p.storage.GetAll()
    if events, exists := allEvents[p.name]; exists {
        return events
    }
    return make(map[uint32][]bpf.BPFEvent)
}

// processEvents handles incoming events from the ring buffer
func (p *Program) processEvents() {
    logger.Info("Starting your program event processing...")

    for {
        select {
        case <-p.ctx.Done():
            logger.Info("Stopping your program event processing...")
            return
        default:
            record, err := p.reader.Read()
            if err != nil {
                if p.ctx.Err() != nil {
                    return
                }
                logger.Errorf("Error reading from ring buffer: %v", err)
                continue
            }

            if err := p.processEvent(record.RawSample); err != nil {
                logger.Errorf("Error processing event: %v", err)
            }
        }
    }
}

// processEvent parses and stores a single event
func (p *Program) processEvent(data []byte) error {
    if len(data) < 28 { // Minimum size for base event + custom fields
        return fmt.Errorf("event data too short: %d bytes", len(data))
    }

    var event Event

    // Parse base fields
    event.PID = binary.LittleEndian.Uint32(data[0:4])
    event.TS = binary.LittleEndian.Uint64(data[4:12])
    copy(event.Comm[:], data[12:28])
    
    // Parse custom fields
    event.CustomField = binary.LittleEndian.Uint32(data[28:32])

    // Store event
    if err := p.storage.Store(&event); err != nil {
        return fmt.Errorf("failed to store event: %w", err)
    }

    // Send to channel for aggregation
    select {
    case p.eventChan <- &event:
    default:
        logger.Infof("Event channel full, dropping event")
    }

    logger.Debugf("Your program event: PID=%d, Command=%s, CustomField=%d",
        event.PID, event.GetCommand(), event.CustomField)

    return nil
}
```

### 4. Register the Program

Add to `internal/bpf/loader.go` in the `registerDefaultPrograms()` function:

```go
func registerDefaultPrograms() error {
    storage := globalManager.GetStorage()

    // Existing programs...
    
    // Register your program
    yourProg := your_program.NewProgram(storage)
    if err := globalManager.RegisterProgram(yourProg); err != nil {
        return fmt.Errorf("failed to register your_program: %w", err)
    }

    logger.Info("Registered your custom eBPF program")
    return nil
}
```

### 5. Add API Endpoint (Optional)

If you want custom API endpoints, add to `internal/api/handlers.go`:

```go
// handleYourProgramSummary handles requests for your program statistics
func handleYourProgramSummary(w http.ResponseWriter, r *http.Request) {
    // @Summary Get your program event statistics
    // @Description Returns the count of events captured by your program within the specified time window
    // @Tags your_program
    // @Produce json
    // @Param pid query int false "Process ID to filter by (0 for all processes)"
    // @Param command query string false "Command name to filter by"
    // @Param duration query int true "Time window in seconds (1-3600)" minimum(1) maximum(3600)
    // @Success 200 {object} SummaryResponse
    // @Failure 400 {object} ErrorResponse
    // @Router /api/your_program/summary [get]
    
    summary := GetYourProgramSummary(pid, command, duration)
    writeJSONResponse(w, SummaryResponse{
        Count:    summary,
        PID:      pid,
        Command:  command,
        Duration: duration,
        Message:  fmt.Sprintf("Found %d your_program events", summary),
    })
}
```

### 6. Build and Test

```bash
# Compile eBPF program
clang -O2 -target bpf -c bpf/your_program.c -o bpf/your_program.o

# Build server
make build

# Test
sudo ./bin/ebpf-server
curl "http://localhost:8080/api/your_program/summary?duration=60"
```

## Best Practices

### Error Handling
- Always check return values in eBPF C code
- Handle ring buffer overflow gracefully
- Validate data sizes before parsing

### Performance
- Use appropriate ring buffer sizes
- Minimize data copying
- Filter events in kernel space when possible

### Security
- Validate all input data
- Use BPF verifier-friendly code
- Avoid unbounded loops

### Testing
- Create unit tests for event parsing
- Test with various kernel versions
- Mock eBPF functionality for CI/CD

## Troubleshooting

### Common Issues

**Program fails to load:**
- Check eBPF C syntax and verifier requirements
- Ensure object file is compiled correctly
- Verify tracepoint names exist on your kernel

**No events received:**
- Check if tracepoints are being triggered
- Verify ring buffer is not overflowing
- Enable debug logging to trace event flow

**Build errors:**
- Ensure all dependencies are installed
- Check Go module imports
- Verify eBPF headers are available
