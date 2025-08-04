package packet_drop

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

// Program implements the packet drop monitoring eBPF program
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

// NewProgram creates a new packet drop monitoring program
func NewProgram(storage bpf.EventStorage) *Program {
	return &Program{
		name:        "packet_drop",
		description: "Monitors packet drops via kfree_skb tracepoint and tcp_drop kprobe",
		objectPath:  "bpf/packet_drop.o",
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
	p.eventsMap = collection.Maps["drop_events"]

	logger.Infof("Packet drop monitoring program loaded from %s", p.objectPath)
	return nil
}

// Attach attaches the loaded program to the appropriate kernel hooks
func (p *Program) Attach() error {
	if p.collection == nil {
		return fmt.Errorf("program not loaded")
	}

	attachedCount := 0

	// Try to attach kfree_skb tracepoint
	if prog, exists := p.collection.Programs["trace_kfree_skb"]; exists {
		tp, err := link.Tracepoint("skb", "kfree_skb", prog, nil)
		if err != nil {
			logger.Infof("Could not attach kfree_skb tracepoint: %v", err)
		} else {
			p.links = append(p.links, tp)
			attachedCount++
			logger.Info("Attached kfree_skb tracepoint for packet drop monitoring")
		}
	}

	// Try to attach tcp_drop kprobe
	if prog, exists := p.collection.Programs["trace_tcp_drop"]; exists {
		kp, err := link.Kprobe("tcp_drop", prog, nil)
		if err != nil {
			logger.Infof("Could not attach tcp_drop kprobe: %v", err)
		} else {
			p.links = append(p.links, kp)
			attachedCount++
			logger.Info("Attached tcp_drop kprobe for packet drop monitoring")
		}
	}

	if attachedCount == 0 {
		return fmt.Errorf("no packet drop attach points available")
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(p.eventsMap)
	if err != nil {
		for _, l := range p.links {
			l.Close()
		}
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	p.reader = reader
	logger.Infof("Packet drop monitoring program attached (%d attach points)", attachedCount)
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

	logger.Info("Packet drop monitoring program started")
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

	logger.Info("Packet drop monitoring program stopped")
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
	if dropEvents, exists := allEvents[p.name]; exists {
		return dropEvents
	}
	return make(map[uint32][]bpf.BPFEvent)
}

// processEvents processes events from the ring buffer
func (p *Program) processEvents() {
	logger.Info("Starting packet drop event processing...")

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Stopping packet drop event processing...")
			return
		default:
			record, err := p.reader.Read()
			if err != nil {
				if p.ctx.Err() != nil {
					return // Context cancelled, normal shutdown
				}
				logger.Errorf("Error reading from packet drop ring buffer: %v", err)
				continue
			}

			if err := p.processEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing packet drop event: %v", err)
			}
		}
	}
}

// processEvent processes a single event from the ring buffer
func (p *Program) processEvent(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("drop event data too short: %d bytes", len(data))
	}

	var event Event

	// Parse the raw data according to the C struct layout
	// Expected structure layout for drop_event_t:
	// u32 pid (4 bytes)
	// u64 ts (8 bytes)
	// char comm[16] (16 bytes)
	// u32 drop_reason (4 bytes)
	// u32 skb_len (4 bytes)
	// u8 padding[8] (8 bytes)
	// Total: 44 bytes

	event.BaseEvent.PID = binary.LittleEndian.Uint32(data[0:4])
	event.BaseEvent.TS = binary.LittleEndian.Uint64(data[4:12])
	copy(event.BaseEvent.Comm[:], data[12:28])
	event.DropReason = binary.LittleEndian.Uint32(data[28:32])
	if len(data) >= 36 {
		event.SkbLen = binary.LittleEndian.Uint32(data[32:36])
	}

	// Store the event
	if err := p.storage.Store(&event); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	// Send to event channel (non-blocking)
	select {
	case p.eventChan <- &event:
	default:
		logger.Infof("Packet drop event channel full, dropping event")
	}

	logger.Debugf("Packet drop event: PID=%d, Command=%s, Reason=%s, WallTime=%s",
		event.GetPID(), event.GetCommand(), event.GetDropReasonString(), 
		event.GetWallClockTime().Format("2006-01-02 15:04:05"))

	return nil
}
