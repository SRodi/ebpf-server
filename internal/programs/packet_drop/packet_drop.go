// Package packet_drop implements eBPF monitoring for packet drops.
package packet_drop

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
	// Program configuration
	ProgramName        = "packet_drop"
	ProgramDescription = "Monitors packet drops via kfree_skb tracepoint"
	ObjectPath         = "bpf/packet_drop.o"
	
	// eBPF program and map names
	TracepointProgram = "trace_kfree_skb"
	EventsMapName     = "drop_events"
	
	// Tracepoint configuration
	TracepointGroup = "skb"
	TracepointName  = "kfree_skb"
)

// Program implements the packet drop monitoring eBPF program.
type Program struct {
	*programs.BaseProgram
}

// NewProgram creates a new packet drop monitoring program.
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
	
	logger.Debugf("Attaching packet drop monitoring program")
	
	// Attach to kfree_skb tracepoint
	if err := p.AttachToTracepoint(TracepointProgram, TracepointGroup, TracepointName); err != nil {
		return fmt.Errorf("failed to attach to tracepoint: %w", err)
	}
	
	// Start ring buffer reader
	parser := NewEventParser()
	if err := p.StartRingBufferReader(EventsMapName, parser); err != nil {
		return fmt.Errorf("failed to start ring buffer reader: %w", err)
	}
	
	logger.Info("Packet drop monitoring program attached and active")
	return nil
}

// EventParser parses packet drop events from binary data.
type EventParser struct{}

// NewEventParser creates a new packet drop event parser.
func NewEventParser() *EventParser {
	return &EventParser{}
}

// EventType returns the type of events this parser handles.
func (p *EventParser) EventType() string {
	return "packet_drop"
}

// Parse converts raw bytes from eBPF into a packet drop event.
func (p *EventParser) Parse(data []byte) (core.Event, error) {
	if len(data) != 44 {
		return nil, fmt.Errorf("invalid packet drop event size: expected 44 bytes, got %d", len(data))
	}
	
	// Parse binary data based on C struct layout:
	// struct drop_event_t {
	//     u32 pid;          // 0-3
	//     u64 ts;           // 4-11  
	//     char comm[16];    // 12-27
	//     u32 drop_reason;  // 28-31
	//     u32 skb_len;      // 32-35
	//     u8 padding[8];    // 36-43
	// }
	
	pid := binary.LittleEndian.Uint32(data[0:4])
	timestamp := binary.LittleEndian.Uint64(data[4:12])
	
	// Extract command (null-terminated string)
	command := extractNullTerminatedString(data[12:28])
	
	dropReason := binary.LittleEndian.Uint32(data[28:32])
	skbLen := binary.LittleEndian.Uint32(data[32:36])
	
	// Build metadata with parsed fields and derived information
	metadata := map[string]interface{}{
		"drop_reason_code":   dropReason,
		"drop_reason":        formatDropReason(dropReason),
		"skb_length":         skbLen,
		"packet_size_bytes":  skbLen,
	}
	
	event := events.NewBaseEvent("packet_drop", pid, command, timestamp, metadata)
	
	// Debug log the parsed packet drop event
	logger.Debugf("📦 PACKET DROP EVENT: PID=%d cmd=%s reason=%s (%d) size=%d bytes", 
		pid, command, formatDropReason(dropReason), dropReason, skbLen)
	
	return event, nil
}

// extractNullTerminatedString extracts a null-terminated string from a byte slice.
func extractNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// formatDropReason converts drop reason code to human-readable string.
func formatDropReason(reason uint32) string {
	switch reason {
	case 1:
		return "SKB_FREE"
	case 2:
		return "TCP_DROP"
	case 3:
		return "UDP_DROP"
	case 4:
		return "ICMP_DROP"
	case 5:
		return "NETFILTER_DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", reason)
	}
}
