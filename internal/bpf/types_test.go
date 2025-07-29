package bpf

import (
	"testing"
	"time"
)

func TestEventGetters(t *testing.T) {
	// Create a test event
	event := Event{
		PID:      1234,
		TS:       1000000000000, // 1 second since boot in nanoseconds
		Ret:      0,
		Comm:     [16]byte{'t', 'e', 's', 't', 0}, // null-terminated string
		DestIP:   0x08080808,                       // 8.8.8.8 in network byte order (little endian)
		DestPort: 53,
		Family:   2, // AF_INET
		Protocol: 17, // UDP
		SockType: 2,  // SOCK_DGRAM
	}

	// Test GetCommand
	if cmd := event.GetCommand(); cmd != "test" {
		t.Errorf("GetCommand() = %q, want %q", cmd, "test")
	}

	// Test GetDestIP
	if ip := event.GetDestIP(); ip != "8.8.8.8" {
		t.Errorf("GetDestIP() = %q, want %q", ip, "8.8.8.8")
	}

	// Test GetDestination
	if dest := event.GetDestination(); dest != "8.8.8.8:53" {
		t.Errorf("GetDestination() = %q, want %q", dest, "8.8.8.8:53")
	}

	// Test GetProtocol
	if proto := event.GetProtocol(); proto != "UDP" {
		t.Errorf("GetProtocol() = %q, want %q", proto, "UDP")
	}

	// Test GetSocketType
	if sockType := event.GetSocketType(); sockType != "DGRAM" {
		t.Errorf("GetSocketType() = %q, want %q", sockType, "DGRAM")
	}
}

func TestEventGettersUnknown(t *testing.T) {
	// Test unknown values
	event := Event{
		Protocol: 255, // Unknown protocol
		SockType: 255, // Unknown socket type
		DestIP:   0,   // Invalid IP
	}

	if proto := event.GetProtocol(); proto != "Unknown" {
		t.Errorf("GetProtocol() = %q, want %q", proto, "Unknown")
	}

	if sockType := event.GetSocketType(); sockType != "Unknown" {
		t.Errorf("GetSocketType() = %q, want %q", sockType, "Unknown")
	}

	if ip := event.GetDestIP(); ip != "" {
		t.Errorf("GetDestIP() = %q, want empty string for zero IP", ip)
	}

	if dest := event.GetDestination(); dest != "" {
		t.Errorf("GetDestination() = %q, want empty string for zero IP", dest)
	}
}

func TestEventTimeConversion(t *testing.T) {
	// Set a mock boot time for testing
	originalBootTime := systemBootTime
	systemBootTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	defer func() {
		systemBootTime = originalBootTime
	}()

	event := Event{
		TS: 5000000000, // 5 seconds since boot in nanoseconds
	}

	wallTime := event.GetWallClockTime() // Use GetWallClockTime instead of GetTime
	expectedTime := systemBootTime.Add(5 * time.Second)

	if !wallTime.Equal(expectedTime) {
		t.Errorf("GetWallClockTime() = %v, want %v", wallTime, expectedTime)
	}
	
	// Test that GetTime returns zero time (as documented)
	zeroTime := event.GetTime()
	if !zeroTime.IsZero() {
		t.Errorf("GetTime() should return zero time, got %v", zeroTime)
	}
}

func TestTcpProtocolDetection(t *testing.T) {
	tests := []struct {
		protocol uint8
		sockType uint8
		expected string
	}{
		{6, 1, "TCP"},        // IPPROTO_TCP with SOCK_STREAM
		{17, 2, "UDP"},       // IPPROTO_UDP with SOCK_DGRAM  
		{1, 1, "Unknown"},    // IPPROTO_ICMP
		{255, 1, "Unknown"},  // Unknown protocol
	}

	for _, tt := range tests {
		event := Event{
			Protocol: tt.protocol,
			SockType: tt.sockType,
		}

		if proto := event.GetProtocol(); proto != tt.expected {
			t.Errorf("Protocol %d: GetProtocol() = %q, want %q", tt.protocol, proto, tt.expected)
		}
	}
}

func TestSocketTypeDetection(t *testing.T) {
	tests := []struct {
		sockType uint8
		expected string
	}{
		{1, "STREAM"},   // SOCK_STREAM
		{2, "DGRAM"},    // SOCK_DGRAM
		{3, "Unknown"},  // SOCK_RAW
		{255, "Unknown"}, // Unknown socket type
	}

	for _, tt := range tests {
		event := Event{
			SockType: tt.sockType,
		}

		if sockType := event.GetSocketType(); sockType != tt.expected {
			t.Errorf("SockType %d: GetSocketType() = %q, want %q", tt.sockType, sockType, tt.expected)
		}
	}
}
