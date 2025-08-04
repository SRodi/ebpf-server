package bpf

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Connection event structure (existing)
type Event struct {
	PID      uint32   `json:"pid"`
	TS       uint64   `json:"timestamp_ns"`
	Ret      int32    `json:"return_code"`
	Comm     [16]byte `json:"-"`
	DestIPv4 uint32   `json:"dest_ip"`  // IPv4 address (0 if IPv6)
	DestIPv6 [16]byte `json:"dest_ip6"` // IPv6 address (all zeros if IPv4)
	DestPort uint16   `json:"dest_port"`
	Family   uint16   `json:"address_family"`
	Protocol uint8    `json:"protocol"`
	SockType uint8    `json:"socket_type"`
	Padding  uint16   `json:"-"`
}

// Packet drop event structure (new)
// Must match the C struct layout which is __attribute__((packed))
type DropEvent struct {
	PID        uint32   `json:"pid"`
	TS         uint64   `json:"timestamp_ns"`
	Comm       [16]byte `json:"-"`
	DropReason uint32   `json:"drop_reason"`
	SkbLen     uint32   `json:"skb_length"`
	Padding    [8]byte  `json:"-"`
}

// GetCommand returns the command name as a string
func (e *Event) GetCommand() string {
	// Convert the byte array to a null-terminated string
	cmd := make([]byte, 0, 16)
	for i := 0; i < len(e.Comm) && e.Comm[i] != 0; i++ {
		cmd = append(cmd, e.Comm[i])
	}
	return string(cmd)
}

// GetDestIP returns the destination IP as a string
func (e *Event) GetDestIP() string {
	const AF_INET = 2
	const AF_INET6 = 10

	switch e.Family {
	case AF_INET:
		if e.DestIPv4 == 0 {
			return ""
		}
		// Convert from little-endian uint32 to IP address
		ip := net.IPv4(byte(e.DestIPv4), byte(e.DestIPv4>>8), byte(e.DestIPv4>>16), byte(e.DestIPv4>>24))
		return ip.String()
	case AF_INET6:
		// Check if IPv6 address is all zeros
		allZero := true
		for _, b := range e.DestIPv6 {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return ""
		}
		ip := net.IP(e.DestIPv6[:])
		return ip.String()
	default:
		return ""
	}
}

// GetDestination returns the destination as "IP:port" format
func (e *Event) GetDestination() string {
	const AF_INET6 = 10

	ip := e.GetDestIP()
	if ip == "" {
		return ""
	}

	// IPv6 addresses need to be wrapped in brackets
	if e.Family == AF_INET6 {
		return fmt.Sprintf("[%s]:%d", ip, e.DestPort)
	}

	return fmt.Sprintf("%s:%d", ip, e.DestPort)
}

// GetProtocol returns the protocol as a string
func (e *Event) GetProtocol() string {
	switch e.Protocol {
	case 6: // IPPROTO_TCP
		return "TCP"
	case 17: // IPPROTO_UDP
		return "UDP"
	default:
		return "Unknown"
	}
}

// GetSocketType returns the socket type as a string
func (e *Event) GetSocketType() string {
	switch e.SockType {
	case 1: // SOCK_STREAM
		return "STREAM"
	case 2: // SOCK_DGRAM
		return "DGRAM"
	default:
		return "Unknown"
	}
}

// GetTime returns a placeholder since eBPF timestamps are boot-relative, not wall-clock time
func (e *Event) GetTime() time.Time {
	// eBPF uses ktime_get_ns() which is nanoseconds since boot, not Unix epoch
	// Converting to wall-clock time requires additional boot time calculation
	// For now, return a zero time to avoid misleading 1970 dates
	return time.Time{}
}

// GetWallClockTime converts eBPF timestamp to wall clock time using system boot time
func (e *Event) GetWallClockTime() time.Time {
	// eBPF timestamp is nanoseconds since boot, convert to wall clock time
	bootTime := GetSystemBootTime()
	eventTime := bootTime.Add(time.Duration(e.TS))
	return eventTime
}

// EventJSON is used for JSON serialization with human-readable fields
type EventJSON struct {
	PID         uint32 `json:"pid"`
	Timestamp   uint64 `json:"timestamp_ns"`
	RetCode     int32  `json:"return_code"`
	Command     string `json:"command"`
	DestIP      string `json:"destination_ip"`
	DestPort    uint16 `json:"destination_port"`
	Destination string `json:"destination"`
	Family      uint16 `json:"address_family"`
	Protocol    string `json:"protocol"`
	SocketType  string `json:"socket_type"`
	WallTime    string `json:"wall_time"`
	Note        string `json:"note"`
}

// MarshalJSON implements custom JSON marshaling
func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(EventJSON{
		PID:         e.PID,
		Timestamp:   e.TS,
		RetCode:     e.Ret,
		Command:     e.GetCommand(),
		DestIP:      e.GetDestIP(),
		DestPort:    e.DestPort,
		Destination: e.GetDestination(),
		Family:      e.Family,
		Protocol:    e.GetProtocol(),
		SocketType:  e.GetSocketType(),
		WallTime:    e.GetWallClockTime().Format(time.RFC3339),
		Note:        "timestamp_ns is nanoseconds since boot, wall_time is converted to UTC",
	})
}

// DropEvent getter methods

// GetCommand returns the command name as a string
func (e *DropEvent) GetCommand() string {
	// Convert the byte array to a null-terminated string
	cmd := make([]byte, 0, 16)
	for i := 0; i < len(e.Comm) && e.Comm[i] != 0; i++ {
		cmd = append(cmd, e.Comm[i])
	}
	return string(cmd)
}

// GetWallClockTime converts eBPF timestamp to wall clock time using system boot time
func (e *DropEvent) GetWallClockTime() time.Time {
	// eBPF timestamp is nanoseconds since boot, convert to wall clock time
	bootTime := GetSystemBootTime()
	eventTime := bootTime.Add(time.Duration(e.TS))
	return eventTime
}

// GetDropReasonString returns a human-readable drop reason
func (e *DropEvent) GetDropReasonString() string {
	switch e.DropReason {
	case 1:
		return "SKB_FREE"
	case 2:
		return "TCP_DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", e.DropReason)
	}
}

// DropEventJSON is used for JSON serialization with human-readable fields
type DropEventJSON struct {
	PID           uint32 `json:"pid"`
	Timestamp     uint64 `json:"timestamp_ns"`
	Command       string `json:"command"`
	DropReason    uint32 `json:"drop_reason_code"`
	DropReasonStr string `json:"drop_reason"`
	SkbLength     uint32 `json:"skb_length"`
	WallTime      string `json:"wall_time"`
	Note          string `json:"note"`
}

// MarshalJSON implements custom JSON marshaling for DropEvent
func (e *DropEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(DropEventJSON{
		PID:           e.PID,
		Timestamp:     e.TS,
		Command:       e.GetCommand(),
		DropReason:    e.DropReason,
		DropReasonStr: e.GetDropReasonString(),
		SkbLength:     e.SkbLen,
		WallTime:      e.GetWallClockTime().Format(time.RFC3339),
		Note:          "timestamp_ns is nanoseconds since boot, wall_time is converted to UTC",
	})
}
