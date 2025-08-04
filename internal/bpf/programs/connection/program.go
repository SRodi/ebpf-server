package connection

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/srodi/ebpf-server/internal/bpf"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Program implements the connection monitoring eBPF program
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

// NewProgram creates a new connection monitoring program
func NewProgram(storage bpf.EventStorage) *Program {
	return &Program{
		name:        "connection",
		description: "Monitors network connection attempts via sys_enter_connect tracepoint",
		objectPath:  "bpf/connection.o",
		eventChan:   make(chan bpf.BPFEvent, 1000), // Buffered channel
		storage:     storage,
	}
}

// GetName returns the program name
func (p *Program) GetName() string {
	return p.name
}

// GetDescription returns the program description
func (p *Program) GetDescription() string {
	return p.description
}

// GetObjectPath returns the path to the compiled eBPF object
func (p *Program) GetObjectPath() string {
	return p.objectPath
}

// Load compiles and loads the eBPF program into the kernel
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

	logger.Infof("Connection monitoring program loaded from %s", p.objectPath)
	return nil
}

// Attach attaches the loaded program to the appropriate kernel hooks
func (p *Program) Attach() error {
	if p.collection == nil {
		return fmt.Errorf("program not loaded")
	}

	// Attach to sys_enter_connect tracepoint
	prog := p.collection.Programs["trace_connect"]
	if prog == nil {
		return fmt.Errorf("trace_connect program not found in collection")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
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
	logger.Info("Connection monitoring program attached to sys_enter_connect tracepoint")
	return nil
}

// Start begins processing events from this program
func (p *Program) Start(ctx context.Context) error {
	if p.reader == nil {
		return fmt.Errorf("program not attached")
	}

	if p.running {
		return fmt.Errorf("program already running")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true

	// Start event processing goroutine
	go p.processEvents()

	logger.Info("Connection monitoring program started")
	return nil
}

// Stop stops processing events and cleans up resources
func (p *Program) Stop() error {
	if !p.running {
		return nil
	}

	// Cancel context to stop event processing
	if p.cancel != nil {
		p.cancel()
	}

	// Close ring buffer reader
	if p.reader != nil {
		p.reader.Close()
		p.reader = nil
	}

	// Close links
	for _, l := range p.links {
		if l != nil {
			l.Close()
		}
	}
	p.links = nil

	// Close collection
	if p.collection != nil {
		p.collection.Close()
		p.collection = nil
	}

	p.running = false
	close(p.eventChan)

	logger.Info("Connection monitoring program stopped")
	return nil
}

// IsRunning returns true if the program is currently running
func (p *Program) IsRunning() bool {
	return p.running
}

// GetEventChannel returns a channel that receives events from this program
func (p *Program) GetEventChannel() <-chan bpf.BPFEvent {
	return p.eventChan
}

// GetSummary returns aggregated statistics for this program
func (p *Program) GetSummary(pid uint32, command string, durationSeconds int) int {
	// Calculate time window - events from the last durationSeconds
	since := bpf.GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, p.name, since)
}

// GetAllEvents returns all tracked events
func (p *Program) GetAllEvents() map[uint32][]bpf.BPFEvent {
	allEvents := p.storage.GetAll()
	if connectionEvents, exists := allEvents[p.name]; exists {
		return connectionEvents
	}
	return make(map[uint32][]bpf.BPFEvent)
}

// processEvents processes events from the ring buffer
func (p *Program) processEvents() {
	logger.Info("Starting connection event processing...")

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Stopping connection event processing...")
			return
		default:
			record, err := p.reader.Read()
			if err != nil {
				if p.ctx.Err() != nil {
					return // Context cancelled, normal shutdown
				}
				logger.Errorf("Error reading from connection ring buffer: %v", err)
				continue
			}

			if err := p.processEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing connection event: %v", err)
			}
		}
	}
}

// processEvent processes a single event from the ring buffer
func (p *Program) processEvent(data []byte) error {
	if len(data) < 60 {
		return fmt.Errorf("connection event data too short: %d bytes", len(data))
	}

	var event Event

	// Parse the raw data according to the C struct layout
	// Expected structure layout (based on struct event_t):
	// u32 pid (4 bytes)
	// u64 ts (8 bytes)
	// u32 ret (4 bytes)
	// char comm[16] (16 bytes)
	// u32 dest_ip (4 bytes)
	// u8 dest_ip6[16] (16 bytes)
	// u16 dest_port (2 bytes)
	// u16 family (2 bytes)
	// u8 protocol (1 byte)
	// u8 sock_type (1 byte)
	// u16 padding (2 bytes)

	event.BaseEvent.PID = binary.LittleEndian.Uint32(data[0:4])
	event.BaseEvent.TS = binary.LittleEndian.Uint64(data[4:12])
	event.Ret = int32(binary.LittleEndian.Uint32(data[12:16]))
	copy(event.BaseEvent.Comm[:], data[16:32])
	event.DestIPv4 = binary.LittleEndian.Uint32(data[32:36])
	copy(event.DestIPv6[:], data[36:52])
	event.DestPort = binary.LittleEndian.Uint16(data[52:54])
	event.Family = binary.LittleEndian.Uint16(data[54:56])
	event.Protocol = data[56]
	event.SockType = data[57]

	// Handle address data based on family
	const AF_INET = 2
	const AF_INET6 = 10

	if event.Family == AF_INET6 {
		// Clear IPv4 data for IPv6 connections
		event.DestIPv4 = 0
	} else if event.Family == AF_INET {
		// Clear IPv6 data (should already be zero from struct initialization)
		for i := range event.DestIPv6 {
			event.DestIPv6[i] = 0
		}
	}

	// Skip events with no valid destination
	if event.GetDestIP() == "" {
		return nil
	}

	// Store the event
	if err := p.storage.Store(&event); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	// Send to event channel (non-blocking)
	select {
	case p.eventChan <- &event:
	default:
		logger.Infof("Connection event channel full, dropping event")
	}

	logger.Debugf("Connection event: PID=%d, Command=%s, Dest=%s, Protocol=%s",
		event.GetPID(), event.GetCommand(), event.GetDestination(), event.GetProtocol())

	return nil
}
