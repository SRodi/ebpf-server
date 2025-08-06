package connection

import (
	"encoding/binary"
	"testing"
)

// TestProgram tests the Program struct
func TestProgram(t *testing.T) {
	program := NewProgram()

	// Test basic properties
	if program.Name() != "connection" {
		t.Errorf("expected name 'connection', got %s", program.Name())
	}

	if program.Description() != "Monitors network connection attempts via sys_enter_connect tracepoint" {
		t.Errorf("unexpected description: %s", program.Description())
	}

	// Test initial state
	if program.IsLoaded() {
		t.Error("program should not be loaded initially")
	}

	if program.IsAttached() {
		t.Error("program should not be attached initially")
	}

	// Test event stream
	stream := program.EventStream()
	if stream == nil {
		t.Error("expected non-nil event stream")
	}
}

// TestEventParser tests the EventParser struct
func TestEventParser(t *testing.T) {
	parser := NewEventParser()

	// Test event type
	if parser.EventType() != "connection" {
		t.Errorf("expected event type 'connection', got %s", parser.EventType())
	}
}

// TestParseValidConnectionEvent tests parsing of valid binary event data
func TestParseValidConnectionEvent(t *testing.T) {
	parser := NewEventParser()

	// Create test binary data (60 bytes total as per the C struct)
	testData := make([]byte, 60)

	// Set test values based on C struct layout:
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

	// pid (offset 0, 4 bytes)
	binary.LittleEndian.PutUint32(testData[0:4], 1234)

	// timestamp (offset 4, 8 bytes)
	binary.LittleEndian.PutUint64(testData[4:12], 1000000)

	// ret (offset 12, 4 bytes)
	binary.LittleEndian.PutUint32(testData[12:16], 0) // Success

	// command (offset 16, 16 bytes)
	copy(testData[16:32], []byte("curl\x00"))

	// dest_ip (offset 32, 4 bytes) - 127.0.0.1
	// Need to store as little-endian but the IP extraction expects different byte order
	binary.LittleEndian.PutUint32(testData[32:36], 0x0100007f)

	// dest_ip6 (offset 36, 16 bytes) - leave as zeros for IPv4

	// dest_port (offset 52, 2 bytes)
	binary.LittleEndian.PutUint16(testData[52:54], 80)

	// family (offset 54, 2 bytes) - AF_INET = 2
	binary.LittleEndian.PutUint16(testData[54:56], 2)

	// protocol (offset 56, 1 byte) - TCP = 6
	testData[56] = 6

	// sock_type (offset 57, 1 byte) - STREAM = 1
	testData[57] = 1

	// Test parsing
	event, err := parser.Parse(testData)
	if err != nil {
		t.Fatalf("failed to parse binary data: %v", err)
	}

	// Verify parsed event
	if event.Type() != "connection" {
		t.Errorf("expected type 'connection', got %s", event.Type())
	}

	if event.PID() != 1234 {
		t.Errorf("expected PID 1234, got %d", event.PID())
	}

	if event.Command() != "curl" {
		t.Errorf("expected command 'curl', got %s", event.Command())
	}

	if event.Timestamp() != 1000000 {
		t.Errorf("expected timestamp 1000000, got %d", event.Timestamp())
	}

	// Check metadata
	metadata := event.Metadata()

	if metadata["protocol"] != "TCP" {
		t.Errorf("expected protocol 'TCP', got %v", metadata["protocol"])
	}

	if metadata["destination_ip"] != "127.0.0.1" {
		t.Errorf("expected destination_ip '127.0.0.1', got %v", metadata["destination_ip"])
	}

	if metadata["destination_port"] != uint16(80) {
		t.Errorf("expected destination_port 80, got %v", metadata["destination_port"])
	}

	if metadata["destination"] != "127.0.0.1:80" {
		t.Errorf("expected destination '127.0.0.1:80', got %v", metadata["destination"])
	}

	if metadata["return_code"] != int32(0) {
		t.Errorf("expected return_code 0, got %v", metadata["return_code"])
	}

	if metadata["address_family"] != uint16(2) {
		t.Errorf("expected address_family 2 (AF_INET), got %v", metadata["address_family"])
	}

	if metadata["socket_type"] != "STREAM" {
		t.Errorf("expected socket_type 'STREAM', got %v", metadata["socket_type"])
	}
}

// TestParseIPv6ConnectionEvent tests parsing of IPv6 connection events
func TestParseIPv6ConnectionEvent(t *testing.T) {
	parser := NewEventParser()
	testData := make([]byte, 60)

	// Set basic fields
	binary.LittleEndian.PutUint32(testData[0:4], 5678)     // pid
	binary.LittleEndian.PutUint64(testData[4:12], 2000000) // timestamp
	binary.LittleEndian.PutUint32(testData[12:16], 0)      // ret
	copy(testData[16:32], []byte("wget\x00"))              // command

	// IPv4 dest_ip = 0 (not used for IPv6)
	binary.LittleEndian.PutUint32(testData[32:36], 0)

	// IPv6 address: ::1 (localhost)
	ipv6 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	copy(testData[36:52], ipv6[:])

	binary.LittleEndian.PutUint16(testData[52:54], 443) // dest_port (HTTPS)
	binary.LittleEndian.PutUint16(testData[54:56], 10)  // family (AF_INET6 = 10)
	testData[56] = 6                                    // protocol (TCP)
	testData[57] = 1                                    // sock_type (STREAM)

	event, err := parser.Parse(testData)
	if err != nil {
		t.Fatalf("failed to parse IPv6 binary data: %v", err)
	}

	metadata := event.Metadata()

	if metadata["destination_ip"] != "::1" {
		t.Errorf("expected destination_ip '::1', got %v", metadata["destination_ip"])
	}

	if metadata["destination"] != "[::1]:443" {
		t.Errorf("expected destination '[::1]:443', got %v", metadata["destination"])
	}

	if metadata["address_family"] != uint16(10) {
		t.Errorf("expected address_family 10 (AF_INET6), got %v", metadata["address_family"])
	}
}

// TestParseLocalSocketEvent tests parsing of local socket events (no IP)
func TestParseLocalSocketEvent(t *testing.T) {
	parser := NewEventParser()
	testData := make([]byte, 60)

	// Set basic fields
	binary.LittleEndian.PutUint32(testData[0:4], 9999)         // pid
	binary.LittleEndian.PutUint64(testData[4:12], 3000000)     // timestamp
	binary.LittleEndian.PutUint32(testData[12:16], 0xFFFFFFFF) // ret (error -1)
	copy(testData[16:32], []byte("test\x00"))                  // command

	// No IP addresses (all zeros)
	// family = 1 (AF_UNIX), no destination info
	binary.LittleEndian.PutUint16(testData[54:56], 1) // family (AF_UNIX)
	testData[56] = 0                                  // protocol
	testData[57] = 1                                  // sock_type (STREAM)

	event, err := parser.Parse(testData)
	if err != nil {
		t.Fatalf("failed to parse local socket data: %v", err)
	}

	metadata := event.Metadata()

	// For local sockets, IP should be empty
	if metadata["destination_ip"] != "" {
		t.Errorf("expected empty destination_ip for local socket, got %v", metadata["destination_ip"])
	}

	if metadata["destination"] != "" {
		t.Errorf("expected empty destination for local socket, got %v", metadata["destination"])
	}

	if metadata["return_code"] != int32(-1) {
		t.Errorf("expected return_code -1, got %v", metadata["return_code"])
	}
}

// TestParseInvalidData tests parsing with invalid data
func TestParseInvalidData(t *testing.T) {
	parser := NewEventParser()

	// Test with data that's too short
	shortData := make([]byte, 10)
	_, err := parser.Parse(shortData)
	if err == nil {
		t.Error("expected error when parsing data that's too short")
	}

	// Test with data that's too long
	longData := make([]byte, 100)
	_, err = parser.Parse(longData)
	if err == nil {
		t.Error("expected error when parsing data that's too long")
	}

	// Test with nil data
	_, err = parser.Parse(nil)
	if err == nil {
		t.Error("expected error when parsing nil data")
	}

	// Test with empty data
	_, err = parser.Parse([]byte{})
	if err == nil {
		t.Error("expected error when parsing empty data")
	}
}

// TestFormatProtocol tests protocol formatting
func TestFormatProtocol(t *testing.T) {
	testCases := []struct {
		protocol uint8
		expected string
	}{
		{6, "TCP"},
		{17, "UDP"},
		{255, "Unknown(255)"},
	}

	for _, tc := range testCases {
		result := formatProtocol(tc.protocol)
		if result != tc.expected {
			t.Errorf("protocol %d: expected '%s', got '%s'", tc.protocol, tc.expected, result)
		}
	}
}

// TestFormatSocketType tests socket type formatting
func TestFormatSocketType(t *testing.T) {
	testCases := []struct {
		sockType uint8
		expected string
	}{
		{1, "STREAM"},
		{2, "DGRAM"},
		{255, "Unknown(255)"},
	}

	for _, tc := range testCases {
		result := formatSocketType(tc.sockType)
		if result != tc.expected {
			t.Errorf("socket type %d: expected '%s', got '%s'", tc.sockType, tc.expected, result)
		}
	}
}

// TestExtractNullTerminatedString tests string extraction
func TestExtractNullTerminatedString(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "normal string",
			input:    []byte("hello\x00world"),
			expected: "hello",
		},
		{
			name:     "no null terminator",
			input:    []byte("hello"),
			expected: "hello",
		},
		{
			name:     "empty string",
			input:    []byte("\x00abc"),
			expected: "",
		},
		{
			name:     "all zeros",
			input:    []byte{0, 0, 0, 0},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractNullTerminatedString(tc.input)
			if result != tc.expected {
				t.Errorf("expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}
