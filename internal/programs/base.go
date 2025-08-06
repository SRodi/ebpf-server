// Package programs provides the base implementation for eBPF programs.
package programs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Constants for backpressure handling
const (
	// AlertThreshold: Alert when drop rate exceeds 1% over a window
	DropRateAlertThreshold = 0.01
	// Alert interval: Don't spam alerts more than once per minute
	AlertCooldownDuration = time.Minute
	// Event window for calculating drop rate
	DropRateWindowSize = 1000
)

// BaseProgram provides common functionality for eBPF programs.
type BaseProgram struct {
	name        string
	description string
	objectPath  string
	collection  *ebpf.Collection
	links       []link.Link
	eventStream *events.ChannelStream
	loaded      bool
	attached    bool
	mu          sync.RWMutex

	// Event processing metrics
	droppedEvents uint64
	totalEvents   uint64
	lastAlertTime time.Time
	logCounter    uint64 // Counter for efficient logging every N events
}

// NewBaseProgram creates a new base program.
func NewBaseProgram(name, description, objectPath string) *BaseProgram {
	return &BaseProgram{
		name:        name,
		description: description,
		objectPath:  objectPath,
		eventStream: events.NewChannelStream(1000),
		links:       make([]link.Link, 0),
	}
}

// Name returns the program name.
func (p *BaseProgram) Name() string {
	return p.name
}

// Description returns the program description.
func (p *BaseProgram) Description() string {
	return p.description
}

// Load compiles and loads the eBPF program.
func (p *BaseProgram) Load(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.loaded {
		return nil
	}

	logger.Debugf("Loading eBPF program %s from %s", p.name, p.objectPath)

	collection, err := ebpf.LoadCollection(p.objectPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF collection: %w", err)
	}

	p.collection = collection
	p.loaded = true

	logger.Debugf("Successfully loaded eBPF program %s", p.name)
	return nil
}

// IsLoaded returns true if the program is loaded.
func (p *BaseProgram) IsLoaded() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loaded
}

// IsAttached returns true if the program is attached.
func (p *BaseProgram) IsAttached() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.attached
}

// EventStream returns the program's event stream.
func (p *BaseProgram) EventStream() core.EventStream {
	return p.eventStream
}

// GetStats returns event processing statistics.
func (p *BaseProgram) GetStats() (totalEvents, droppedEvents uint64, dropRate float64) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	totalEvents = p.totalEvents
	droppedEvents = p.droppedEvents

	if totalEvents > 0 {
		dropRate = float64(droppedEvents) / float64(totalEvents)
	}

	return totalEvents, droppedEvents, dropRate
}

// checkDropRateAndAlert monitors drop rate and triggers alerts when necessary.
func (p *BaseProgram) checkDropRateAndAlert() {
	total, dropped, dropRate := p.GetStats()

	// Only check if we have enough events to make a meaningful assessment
	if total < DropRateWindowSize {
		return
	}

	// Check if drop rate exceeds threshold and we haven't alerted recently
	if dropRate > DropRateAlertThreshold {
		now := time.Now()
		if now.Sub(p.lastAlertTime) > AlertCooldownDuration {
			logger.Errorf("HIGH EVENT DROP RATE DETECTED in %s: %.2f%% (%d/%d events dropped). "+
				"This indicates system overload or insufficient buffer capacity. "+
				"Consider increasing buffer sizes or optimizing event processing.",
				p.name, dropRate*100, dropped, total)

			p.mu.Lock()
			p.lastAlertTime = now
			p.mu.Unlock()
		}
	}
}

// Detach detaches the program from all kernel hooks.
func (p *BaseProgram) Detach(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.attached {
		return nil
	}

	// Close all links
	for _, l := range p.links {
		if err := l.Close(); err != nil {
			logger.Errorf("Error closing link for program %s: %v", p.name, err)
		}
	}

	p.links = p.links[:0]
	p.attached = false

	// Close event stream
	p.eventStream.Close()

	// Reset event statistics
	p.droppedEvents = 0
	p.totalEvents = 0
	p.lastAlertTime = time.Time{}

	logger.Debugf("Detached program %s", p.name)
	return nil
}

// GetCollection returns the eBPF collection (for subclasses).
func (p *BaseProgram) GetCollection() *ebpf.Collection {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.collection
}

// AddLink adds a link to track (for subclasses).
func (p *BaseProgram) AddLink(l link.Link) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.links = append(p.links, l)
	p.attached = true
}

// StartRingBufferReader starts reading from a ring buffer map and parsing events.
func (p *BaseProgram) StartRingBufferReader(mapName string, parser core.EventParser) error {
	collection := p.GetCollection()
	if collection == nil {
		return fmt.Errorf("program not loaded")
	}

	ringbufMap := collection.Maps[mapName]
	if ringbufMap == nil {
		return fmt.Errorf("ring buffer map %s not found", mapName)
	}

	logger.Debugf("Starting ring buffer reader for map %s in program %s", mapName, p.name)

	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	// Start reading in a goroutine
	go func() {
		defer reader.Close()
		defer logger.Debugf("Ring buffer reader stopped for %s", p.name)

		for {
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				logger.Errorf("Error reading from ring buffer in %s: %v", p.name, err)
				continue
			}

			// Parse the event
			event, err := parser.Parse(record.RawSample)
			if err != nil {
				logger.Errorf("Error parsing event in %s: %v", p.name, err)
				continue
			}

			// Track total events
			p.mu.Lock()
			p.totalEvents++
			p.logCounter++
			currentTotal := p.totalEvents
			shouldLog := p.logCounter >= 100 // Log every 100th event to avoid spam
			if shouldLog {
				p.logCounter = 0 // Reset counter
			}
			p.mu.Unlock()

			// Log ring buffer activity (only for debugging)
			if shouldLog {
				logger.Debugf("📡 RING BUFFER: %s processed %d events", p.name, currentTotal)
			}

			// Send to event stream with backpressure handling
			if !p.eventStream.Send(event) {
				// Event dropped due to full buffer - this is a critical issue
				p.mu.Lock()
				p.droppedEvents++
				droppedCount := p.droppedEvents
				p.mu.Unlock()

				// Log error (not just debug) since this represents data loss
				logger.Errorf("Event stream full for %s, DROPPED EVENT (PID: %d, Type: %s). "+
					"Total dropped: %d/%d events. This indicates backpressure - "+
					"consider increasing buffer size or optimizing downstream processing.",
					p.name, event.PID(), event.Type(), droppedCount, currentTotal)

				// Check if we need to trigger high drop rate alerts
				p.checkDropRateAndAlert()
			}
		}
	}()

	return nil
}

// AttachToTracepoint attaches a program to a tracepoint.
func (p *BaseProgram) AttachToTracepoint(progName, group, name string) error {
	collection := p.GetCollection()
	if collection == nil {
		return fmt.Errorf("program not loaded")
	}

	prog := collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("program %s not found in collection", progName)
	}

	logger.Debugf("Attaching program %s to tracepoint %s:%s", progName, group, name)

	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach to tracepoint %s:%s: %w", group, name, err)
	}

	p.AddLink(l)
	logger.Debugf("Successfully attached program %s to tracepoint %s:%s", progName, group, name)

	return nil
}
