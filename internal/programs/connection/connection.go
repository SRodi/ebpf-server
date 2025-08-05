// Package connection implements eBPF monitoring for network connections.
package connection

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/pkg/logger"
)

const (
	// Program configuration
	ProgramName        = "connection"
	ProgramDescription = "Monitors network connection attempts via sys_enter_connect tracepoint"
	ObjectPath         = "bpf/connection.o"
	
	// eBPF program and map names
	TracepointProgram = "trace_connect"
	EventsMapName     = "events"
	
	// Tracepoint configuration
	TracepointGroup = "syscalls"
	TracepointName  = "sys_enter_connect"
)

// Program implements the connection monitoring eBPF program.
type Program struct {
	*programs.BaseProgram
}

// NewProgram creates a new connection monitoring program.
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
	
	logger.Debugf("Attaching connection monitoring program")
	
	// Attach to sys_enter_connect tracepoint
	if err := p.AttachToTracepoint(TracepointProgram, TracepointGroup, TracepointName); err != nil {
		return fmt.Errorf("failed to attach to tracepoint: %w", err)
	}
	
	// Start ring buffer reader
	parser := NewEventParser()
	if err := p.StartRingBufferReader(EventsMapName, parser); err != nil {
		return fmt.Errorf("failed to start ring buffer reader: %w", err)
	}
	
	logger.Info("Connection monitoring program attached and active")
	return nil
}

// EventParser parses connection events from binary data.
type EventParser struct{}

// NewEventParser creates a new connection event parser.
func NewEventParser() *EventParser {
	return &EventParser{}
}

// EventType returns the type of events this parser handles.
func (p *EventParser) EventType() string {
	return "connection"
}

// Parse converts raw bytes from eBPF into a connection event.
func (p *EventParser) Parse(data []byte) (core.Event, error) {
	if len(data) != 60 {
		return nil, fmt.Errorf("invalid connection event size: expected 60 bytes, got %d", len(data))
	}
	
	// Parse binary data based on C struct layout:
	// struct event_t {
	//     u32 pid;         // 0-3
	//     u64 ts;          // 4-11
	//     u32 ret;         // 12-15
	//     char comm[16];   // 16-31
	//     u32 dest_ip;     // 32-35
	//     u8 dest_ip6[16]; // 36-51
	//     u16 dest_port;   // 52-53
	//     u16 family;      // 54-55
	//     u8 protocol;     // 56
	//     u8 sock_type;    // 57
	//     u16 padding;     // 58-59
	// }
	
	pid := binary.LittleEndian.Uint32(data[0:4])
	timestamp := binary.LittleEndian.Uint64(data[4:12])
	ret := int32(binary.LittleEndian.Uint32(data[12:16]))
	
	// Extract command (null-terminated string)
	command := extractNullTerminatedString(data[16:32])
	
	destIPv4 := binary.LittleEndian.Uint32(data[32:36])
	var destIPv6 [16]byte
	copy(destIPv6[:], data[36:52])
	
	destPort := binary.LittleEndian.Uint16(data[52:54])
	family := binary.LittleEndian.Uint16(data[54:56])
	protocol := data[56]
	sockType := data[57]
	
	// Build metadata with parsed fields and derived information
	metadata := map[string]interface{}{
		"return_code":      ret,
		"destination_ip":   formatIP(family, destIPv4, destIPv6),
		"destination_port": destPort,
		"destination":      formatDestination(family, destIPv4, destIPv6, destPort),
		"address_family":   family,
		"protocol":         formatProtocol(protocol),
		"socket_type":      formatSocketType(sockType),
		
		// Raw values for further processing if needed
		"raw_ipv4":      destIPv4,
		"raw_ipv6":      destIPv6,
		"raw_protocol":  protocol,
		"raw_socktype":  sockType,
	}
	
	event := events.NewBaseEvent("connection", pid, command, timestamp, metadata)
	
	// Debug log the parsed connection event
	destination := formatDestination(family, destIPv4, destIPv6, destPort)
	if destination != "" {
		logger.Debugf("🔗 CONNECTION EVENT: PID=%d cmd=%s dest=%s proto=%s ret=%d", 
			pid, command, destination, formatProtocol(protocol), ret)
	} else {
		logger.Debugf("🔗 CONNECTION EVENT: PID=%d cmd=%s family=%d (local socket) ret=%d", 
			pid, command, family, ret)
	}
	
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

// formatIP converts the IP address to a string representation.
func formatIP(family uint16, ipv4 uint32, ipv6 [16]byte) string {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)
	
	switch family {
	case AF_INET:
		if ipv4 == 0 {
			return ""
		}
		// Convert from little-endian uint32 to IP address
		ip := net.IPv4(byte(ipv4), byte(ipv4>>8), byte(ipv4>>16), byte(ipv4>>24))
		return ip.String()
		
	case AF_INET6:
		// Check if IPv6 address is all zeros
		allZero := true
		for _, b := range ipv6 {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return ""
		}
		ip := net.IP(ipv6[:])
		return ip.String()
		
	default:
		return ""
	}
}

// formatDestination formats the destination as "IP:port".
func formatDestination(family uint16, ipv4 uint32, ipv6 [16]byte, port uint16) string {
	const AF_INET6 = 10
	
	ip := formatIP(family, ipv4, ipv6)
	if ip == "" {
		return ""
	}
	
	// IPv6 addresses need to be wrapped in brackets
	if family == AF_INET6 {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	
	return fmt.Sprintf("%s:%d", ip, port)
}

// formatProtocol converts protocol number to string.
func formatProtocol(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", protocol)
	}
}

// formatSocketType converts socket type to string.
func formatSocketType(sockType uint8) string {
	switch sockType {
	case 1:
		return "STREAM"
	case 2:
		return "DGRAM"
	default:
		return fmt.Sprintf("Unknown(%d)", sockType)
	}
}
