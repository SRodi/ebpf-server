// Package events provides event implementations and utilities for the eBPF monitoring system.
package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/kubernetes"
	"github.com/srodi/ebpf-server/pkg/logger"
)

var (
	// Cached boot time to avoid recalculating it for every event
	systemBootTime     time.Time
	bootTimeCalculated bool
	bootTimeMutex      sync.Mutex
	
	// Global Kubernetes metadata provider
	k8sProvider *kubernetes.Provider
	k8sOnce     sync.Once
)

// calculateSystemBootTime calculates the system boot time.
// On Linux, it reads /proc/stat to get the 'btime' field.
// On other platforms, it uses a fallback method.
func calculateSystemBootTime() time.Time {
	bootTimeMutex.Lock()
	defer bootTimeMutex.Unlock()

	if bootTimeCalculated {
		return systemBootTime
	}

	// Try Linux-specific method first
	if bootTime, err := getBootTimeLinux(); err == nil {
		systemBootTime = bootTime
		bootTimeCalculated = true
		logger.Debugf("System boot time calculated (Linux): %v", systemBootTime)
		return systemBootTime
	}

	// Fallback for non-Linux systems or when /proc/stat is unavailable
	// This provides a reasonable approximation for development/testing
	systemBootTime = time.Now().Add(-time.Hour * 24) // Assume system has been up for less than 24 hours
	bootTimeCalculated = true
	logger.Debugf("System boot time calculated (fallback): %v", systemBootTime)
	return systemBootTime
}

// getBootTimeLinux reads boot time from /proc/stat (Linux-specific).
func getBootTimeLinux() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}

	// Parse /proc/stat to find the btime line
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				bootTimeSeconds, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return time.Time{}, err
				}
				return time.Unix(bootTimeSeconds, 0), nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}

// convertEBPFTimestamp converts an eBPF timestamp (nanoseconds since boot) to wall-clock time.
// eBPF timestamps are typically obtained using bpf_ktime_get_ns() which returns nanoseconds
// since system boot. To convert to wall-clock time, we add this to the system boot time.
func convertEBPFTimestamp(ebpfTimestampNs uint64) time.Time {
	bootTime := calculateSystemBootTime()

	// Add the eBPF timestamp (nanoseconds since boot) to the boot time
	return bootTime.Add(time.Duration(ebpfTimestampNs) * time.Nanosecond)
}

// ResetBootTimeCache resets the cached boot time calculation.
// This is useful for testing or if the system time changes significantly.
func ResetBootTimeCache() {
	bootTimeMutex.Lock()
	defer bootTimeMutex.Unlock()
	bootTimeCalculated = false
	systemBootTime = time.Time{}
}

// BaseEvent provides common functionality for all eBPF events.
type BaseEvent struct {
	id        string
	eventType string
	pid       uint32
	command   string
	timestamp uint64
	time      time.Time
	metadata  map[string]interface{}
}

// getKubernetesProvider returns the global Kubernetes metadata provider.
func getKubernetesProvider() *kubernetes.Provider {
	k8sOnce.Do(func() {
		k8sProvider = kubernetes.NewProvider()
	})
	return k8sProvider
}

// NewBaseEvent creates a new base event.
func NewBaseEvent(eventType string, pid uint32, command string, timestamp uint64, metadata map[string]interface{}) *BaseEvent {
	// Generate a unique ID
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		// If crypto/rand fails, use a simple fallback
		for i := range idBytes {
			idBytes[i] = byte(i)
		}
	}
	id := hex.EncodeToString(idBytes)

	// Convert eBPF timestamp to wall clock time using proper boot time calculation
	// eBPF timestamps are nanoseconds since boot (from bpf_ktime_get_ns())
	eventTime := convertEBPFTimestamp(timestamp)

	// Ensure metadata map exists
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add Kubernetes metadata if available
	k8sProvider := getKubernetesProvider()
	if k8sProvider.IsEnabled() {
		k8sProvider.AddToMap(metadata)
	}

	return &BaseEvent{
		id:        id,
		eventType: eventType,
		pid:       pid,
		command:   command,
		timestamp: timestamp,
		time:      eventTime,
		metadata:  metadata,
	}
}

// ID returns the unique event identifier.
func (e *BaseEvent) ID() string {
	return e.id
}

// Type returns the event type.
func (e *BaseEvent) Type() string {
	return e.eventType
}

// PID returns the process ID.
func (e *BaseEvent) PID() uint32 {
	return e.pid
}

// Command returns the command name.
func (e *BaseEvent) Command() string {
	return e.command
}

// Timestamp returns the kernel timestamp.
func (e *BaseEvent) Timestamp() uint64 {
	return e.timestamp
}

// Time returns the wall clock time.
func (e *BaseEvent) Time() time.Time {
	return e.time
}

// Metadata returns the event metadata.
func (e *BaseEvent) Metadata() map[string]interface{} {
	return e.metadata
}

// MarshalJSON implements json.Marshaler.
func (e *BaseEvent) MarshalJSON() ([]byte, error) {
	data := map[string]interface{}{
		"id":        e.id,
		"type":      e.eventType,
		"pid":       e.pid,
		"command":   e.command,
		"timestamp": e.timestamp,
		"time":      e.time.Format(time.RFC3339Nano),
	}

	// Add metadata fields
	for k, v := range e.metadata {
		data[k] = v
	}

	return json.Marshal(data)
}

// ChannelStream implements EventStream using a channel.
type ChannelStream struct {
	events chan core.Event
	closed bool
	mu     sync.RWMutex
}

// NewChannelStream creates a new channel-based event stream.
func NewChannelStream(bufferSize int) *ChannelStream {
	return &ChannelStream{
		events: make(chan core.Event, bufferSize),
	}
}

// Events returns the event channel.
func (s *ChannelStream) Events() <-chan core.Event {
	return s.events
}

// Send adds an event to the stream (non-blocking).
func (s *ChannelStream) Send(event core.Event) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return false
	}

	select {
	case s.events <- event:
		return true
	default:
		// Channel is full, drop the event
		return false
	}
}

// Close stops the event stream.
func (s *ChannelStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed {
		s.closed = true
		close(s.events)
	}

	return nil
}

// MergedStream merges events from multiple EventStreams.
type MergedStream struct {
	streams []core.EventStream
	events  chan core.Event
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closed  bool
	mu      sync.Mutex
}

// NewMergedStream creates a stream that merges events from multiple sources.
func NewMergedStream(streams []core.EventStream) *MergedStream {
	ctx, cancel := context.WithCancel(context.Background())
	merged := &MergedStream{
		streams: streams,
		events:  make(chan core.Event, 1000),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start goroutines to read from each stream
	for _, stream := range streams {
		merged.wg.Add(1)
		go merged.readFromStream(stream)
	}

	return merged
}

// Events returns the merged event channel.
func (m *MergedStream) Events() <-chan core.Event {
	return m.events
}

// Close stops the merged stream.
func (m *MergedStream) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	// Cancel context to signal all goroutines to stop
	m.cancel()

	// Close all source streams
	for _, stream := range m.streams {
		stream.Close()
	}

	// Wait for all goroutines to finish before closing the events channel
	m.wg.Wait()
	close(m.events)

	return nil
}

// readFromStream reads events from a source stream and forwards them.
func (m *MergedStream) readFromStream(stream core.EventStream) {
	defer m.wg.Done()

	for {
		select {
		case event, ok := <-stream.Events():
			if !ok {
				return
			}

			// Try to send the event, but respect context cancellation
			select {
			case m.events <- event:
			case <-m.ctx.Done():
				return
			}

		case <-m.ctx.Done():
			return
		}
	}
}
