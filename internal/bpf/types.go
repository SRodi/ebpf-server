package bpf

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
	"unsafe"
)

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

// GetCommand returns the command name as a string
func (e *Event) GetCommand() string {
	return string((*(*[16]byte)(unsafe.Pointer(&e.Comm[0])))[:clen(e.Comm[:])])
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
	// Convert eBPF timestamp (nanoseconds since boot) to wall clock time
	// This requires access to the systemBootTime from loader.go
	return GetSystemBootTime().Add(time.Duration(e.TS) * time.Nanosecond)
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

// clen finds the length of a null-terminated C string
func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b)
}
