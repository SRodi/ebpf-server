package packet_drop

import (
	"encoding/binary"
	"testing"
)

// TestProgram tests the Program struct
func TestProgram(t *testing.T) {
	program := NewProgram()

	// Test basic properties
	if program.Name() != "packet_drop" {
		t.Errorf("expected name 'packet_drop', got %s", program.Name())
	}

	if program.Description() != "Monitors packet drops via kfree_skb tracepoint" {
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
	if parser.EventType() != "packet_drop" {
		t.Errorf("expected event type 'packet_drop', got %s", parser.EventType())
	}
}

// TestParseValidPacketDropEvent tests parsing of valid binary event data
func TestParseValidPacketDropEvent(t *testing.T) {
	parser := NewEventParser()

	// Create test binary data (44 bytes total as per the C struct)
	testData := make([]byte, 44)

	// Set test values based on C struct layout:
	// struct drop_event_t {
	//     u32 pid;          // 0-3
	//     u64 ts;           // 4-11  
	//     char comm[16];    // 12-27
	//     u32 drop_reason;  // 28-31
	//     u32 skb_len;      // 32-35
	//     u8 padding[8];    // 36-43
	// }

	// pid (offset 0, 4 bytes)
	binary.LittleEndian.PutUint32(testData[0:4], 5678)
	
	// timestamp (offset 4, 8 bytes)  
	binary.LittleEndian.PutUint64(testData[4:12], 2000000)
	
	// command (offset 12, 16 bytes)
	copy(testData[12:28], []byte("iptables\x00"))
	
	// drop_reason (offset 28, 4 bytes)
	binary.LittleEndian.PutUint32(testData[28:32], 2) // TCP_DROP
	
	// skb_len (offset 32, 4 bytes)
	binary.LittleEndian.PutUint32(testData[32:36], 1500)

	// Test parsing
	event, err := parser.Parse(testData)
	if err != nil {
		t.Fatalf("failed to parse binary data: %v", err)
	}

	// Verify parsed event
	if event.Type() != "packet_drop" {
		t.Errorf("expected type 'packet_drop', got %s", event.Type())
	}

	if event.PID() != 5678 {
		t.Errorf("expected PID 5678, got %d", event.PID())
	}

	if event.Command() != "iptables" {
		t.Errorf("expected command 'iptables', got %s", event.Command())
	}

	if event.Timestamp() != 2000000 {
		t.Errorf("expected timestamp 2000000, got %d", event.Timestamp())
	}

	// Check metadata
	metadata := event.Metadata()
	
	if metadata["drop_reason_code"] != uint32(2) {
		t.Errorf("expected drop_reason_code 2, got %v", metadata["drop_reason_code"])
	}

	if metadata["drop_reason"] != "TCP_DROP" {
		t.Errorf("expected drop_reason 'TCP_DROP', got %v", metadata["drop_reason"])
	}

	if metadata["skb_length"] != uint32(1500) {
		t.Errorf("expected skb_length 1500, got %v", metadata["skb_length"])
	}

	if metadata["packet_size_bytes"] != uint32(1500) {
		t.Errorf("expected packet_size_bytes 1500, got %v", metadata["packet_size_bytes"])
	}
}

// TestParsePacketDropWithDifferentReasons tests parsing with various drop reasons
func TestParsePacketDropWithDifferentReasons(t *testing.T) {
	parser := NewEventParser()

	testCases := []struct {
		name         string
		reasonCode   uint32
		expectedName string
	}{
		{"SKB_FREE", 1, "SKB_FREE"},
		{"TCP_DROP", 2, "TCP_DROP"},
		{"UDP_DROP", 3, "UDP_DROP"},
		{"ICMP_DROP", 4, "ICMP_DROP"},
		{"NETFILTER_DROP", 5, "NETFILTER_DROP"},
		{"Unknown reason", 99, "UNKNOWN(99)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testData := make([]byte, 44)
			
			// Set basic fields
			binary.LittleEndian.PutUint32(testData[0:4], 1234)    // pid
			binary.LittleEndian.PutUint64(testData[4:12], 1000000) // timestamp
			copy(testData[12:28], []byte("test\x00"))              // command
			binary.LittleEndian.PutUint32(testData[28:32], tc.reasonCode) // drop_reason
			binary.LittleEndian.PutUint32(testData[32:36], 500)   // skb_len

			event, err := parser.Parse(testData)
			if err != nil {
				t.Fatalf("failed to parse data for %s: %v", tc.name, err)
			}

			metadata := event.Metadata()
			if metadata["drop_reason"] != tc.expectedName {
				t.Errorf("expected drop_reason '%s', got %v", tc.expectedName, metadata["drop_reason"])
			}

			if metadata["drop_reason_code"] != tc.reasonCode {
				t.Errorf("expected drop_reason_code %d, got %v", tc.reasonCode, metadata["drop_reason_code"])
			}
		})
	}
}

// TestParsePacketDropWithDifferentSizes tests parsing with various packet sizes
func TestParsePacketDropWithDifferentSizes(t *testing.T) {
	parser := NewEventParser()

	testCases := []struct {
		name string
		size uint32
	}{
		{"Small packet", 64},
		{"Medium packet", 1024},
		{"Large packet", 1500},
		{"Jumbo frame", 9000},
		{"Zero size", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testData := make([]byte, 44)
			
			// Set basic fields
			binary.LittleEndian.PutUint32(testData[0:4], 1234)    // pid
			binary.LittleEndian.PutUint64(testData[4:12], 1000000) // timestamp
			copy(testData[12:28], []byte("test\x00"))              // command
			binary.LittleEndian.PutUint32(testData[28:32], 1)     // drop_reason (SKB_FREE)
			binary.LittleEndian.PutUint32(testData[32:36], tc.size) // skb_len

			event, err := parser.Parse(testData)
			if err != nil {
				t.Fatalf("failed to parse data for %s: %v", tc.name, err)
			}

			metadata := event.Metadata()
			if metadata["skb_length"] != tc.size {
				t.Errorf("expected skb_length %d, got %v", tc.size, metadata["skb_length"])
			}

			if metadata["packet_size_bytes"] != tc.size {
				t.Errorf("expected packet_size_bytes %d, got %v", tc.size, metadata["packet_size_bytes"])
			}
		})
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

// TestFormatDropReason tests drop reason formatting
func TestFormatDropReason(t *testing.T) {
	testCases := []struct {
		reason   uint32
		expected string
	}{
		{1, "SKB_FREE"},
		{2, "TCP_DROP"},
		{3, "UDP_DROP"},
		{4, "ICMP_DROP"},
		{5, "NETFILTER_DROP"},
		{0, "UNKNOWN(0)"},
		{999, "UNKNOWN(999)"},
	}

	for _, tc := range testCases {
		result := formatDropReason(tc.reason)
		if result != tc.expected {
			t.Errorf("reason %d: expected '%s', got '%s'", tc.reason, tc.expected, result)
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
			input:    []byte("iptables\x00world"),
			expected: "iptables",
		},
		{
			name:     "no null terminator",
			input:    []byte("firewall"),
			expected: "firewall",
		},
		{
			name:     "empty string",
			input:    []byte("\x00abc"),
			expected: "",
		},
		{
			name:     "kernel command",
			input:    []byte("kworker/0:1\x00"),
			expected: "kworker/0:1",
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

// TestPacketDropEventCompleteScenarios tests complete realistic scenarios
func TestPacketDropEventCompleteScenarios(t *testing.T) {
	parser := NewEventParser()

	scenarios := []struct {
		name        string
		pid         uint32
		command     string
		reason      uint32
		size        uint32
		expectedMsg string
	}{
		{
			name:        "Firewall dropped large packet",
			pid:         1234,
			command:     "iptables",
			reason:      5, // NETFILTER_DROP
			size:        1500,
			expectedMsg: "NETFILTER_DROP",
		},
		{
			name:        "TCP connection dropped",
			pid:         5678,
			command:     "nginx",
			reason:      2, // TCP_DROP
			size:        1024,
			expectedMsg: "TCP_DROP",
		},
		{
			name:        "UDP packet dropped",
			pid:         9999,
			command:     "systemd-resolve",
			reason:      3, // UDP_DROP
			size:        512,
			expectedMsg: "UDP_DROP",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			testData := make([]byte, 44)
			
			binary.LittleEndian.PutUint32(testData[0:4], scenario.pid)
			binary.LittleEndian.PutUint64(testData[4:12], 3000000)
			copy(testData[12:28], []byte(scenario.command+"\x00"))
			binary.LittleEndian.PutUint32(testData[28:32], scenario.reason)
			binary.LittleEndian.PutUint32(testData[32:36], scenario.size)

			event, err := parser.Parse(testData)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", scenario.name, err)
			}

			// Verify all expected fields
			if event.PID() != scenario.pid {
				t.Errorf("expected PID %d, got %d", scenario.pid, event.PID())
			}

			if event.Command() != scenario.command {
				t.Errorf("expected command '%s', got '%s'", scenario.command, event.Command())
			}

			metadata := event.Metadata()
			if metadata["drop_reason"] != scenario.expectedMsg {
				t.Errorf("expected drop_reason '%s', got %v", scenario.expectedMsg, metadata["drop_reason"])
			}

			if metadata["packet_size_bytes"] != scenario.size {
				t.Errorf("expected packet_size_bytes %d, got %v", scenario.size, metadata["packet_size_bytes"])
			}
		})
	}
}
