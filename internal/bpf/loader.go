package bpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/srodi/ebpf-server/pkg/logger"
)

var (
	// Program objects for multiple eBPF programs
	connectionObjs struct {
		Events *ebpf.Map
	}
	dropObjs struct {
		DropEvents *ebpf.Map
	}

	// Links for all programs
	connectionLinks []link.Link
	dropLinks       []link.Link

	// Connection tracking
	connectionsMu sync.RWMutex
	connections   = make(map[uint32][]Event) // PID -> []Event

	// Packet drop tracking
	dropsMu sync.RWMutex
	drops   = make(map[uint32][]DropEvent) // PID -> []DropEvent

	// Ring buffer readers
	connectionReader *ringbuf.Reader
	dropReader       *ringbuf.Reader

	// Boot time for converting eBPF timestamps to wall clock time
	systemBootTime time.Time

	// Context for graceful shutdown of event processing
	eventCtx    context.Context
	eventCancel context.CancelFunc
	eventDone   chan struct{}
)

// IsAvailable checks if eBPF is available on the current system
func IsAvailable() bool {
	// On macOS, eBPF is not available
	if strings.Contains(strings.ToLower(os.Getenv("GOOS")), "darwin") {
		logger.Info("eBPF is not available on macOS - running in mock mode")
		return false
	}

	// Try to remove memory limit for eBPF - this will fail if not supported
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Infof("Failed to remove memory limit for eBPF: %v", err)
		return false
	}

	// Check if we can access /sys/fs/bpf (BPF filesystem)
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		logger.Info("BPF filesystem not available")
		return false
	}

	return true
}

// calculateBootTimeOffset calculates the system boot time for timestamp conversion
func calculateBootTimeOffset() {
	// Read system uptime from /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		logger.Infof("Could not read /proc/uptime: %v, using current time", err)
		systemBootTime = time.Now()
		return
	}

	// Parse uptime (first number is seconds since boot)
	uptimeStr := strings.Fields(string(data))[0]
	uptime, err := strconv.ParseFloat(uptimeStr, 64)
	if err != nil {
		logger.Infof("Could not parse uptime: %v, using current time", err)
		systemBootTime = time.Now()
		return
	}

	// Calculate boot time
	systemBootTime = time.Now().Add(-time.Duration(uptime * float64(time.Second)))

	logger.Infof("System boot time calculated: %s", systemBootTime.Format("2006-01-02 15:04:05"))
}

// GetSystemBootTime returns the calculated system boot time
func GetSystemBootTime() time.Time {
	return systemBootTime
}

func LoadAndAttach() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Calculate boot time offset for timestamp conversion
	calculateBootTimeOffset()

	// Initialize context for graceful shutdown
	eventCtx, eventCancel = context.WithCancel(context.Background())
	eventDone = make(chan struct{})

	// Load connection monitoring program
	if err := loadConnectionProgram(); err != nil {
		return fmt.Errorf("failed to load connection program: %w", err)
	}

	// Load packet drop monitoring program (optional)
	if err := loadPacketDropProgram(); err != nil {
		logger.Infof("Failed to load packet drop program: %v (continuing without it)", err)
	}

	// Start event processing goroutines
	go processConnectionEvents()

	// Start packet drop processing if available
	if dropReader != nil {
		go processPacketDropEvents()
	}

	logger.Info("eBPF programs attached successfully")
	return nil
}

// loadConnectionProgram loads the connection monitoring eBPF program
func loadConnectionProgram() error {
	spec, err := ebpf.LoadCollectionSpec("bpf/connection.o")
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	connectionObjs.Events = coll.Maps["events"]

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", coll.Programs["trace_connect"], nil)
	if err != nil {
		coll.Close()
		return err
	}

	connectionLinks = append(connectionLinks, tp)

	// Start reading from ring buffer
	connectionReader, err = ringbuf.NewReader(connectionObjs.Events)
	if err != nil {
		tp.Close()
		coll.Close()
		return err
	}

	logger.Info("Connection monitoring eBPF program attached to sys_enter_connect")
	return nil
}

// loadPacketDropProgram loads the packet drop monitoring eBPF program
func loadPacketDropProgram() error {
	spec, err := ebpf.LoadCollectionSpec("bpf/packet_drop.o")
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	dropObjs.DropEvents = coll.Maps["drop_events"]

	// Try to attach kfree_skb tracepoint
	if prog, exists := coll.Programs["trace_kfree_skb"]; exists {
		tp, err := link.Tracepoint("skb", "kfree_skb", prog, nil)
		if err != nil {
			logger.Infof("Could not attach kfree_skb tracepoint: %v", err)
		} else {
			dropLinks = append(dropLinks, tp)
			logger.Info("Attached kfree_skb tracepoint for packet drop monitoring")
		}
	}

	// Try to attach tcp_drop kprobe
	if prog, exists := coll.Programs["trace_tcp_drop"]; exists {
		kp, err := link.Kprobe("tcp_drop", prog, nil)
		if err != nil {
			logger.Infof("Could not attach tcp_drop kprobe: %v", err)
		} else {
			dropLinks = append(dropLinks, kp)
			logger.Info("Attached tcp_drop kprobe for packet drop monitoring")
		}
	}

	if len(dropLinks) == 0 {
		coll.Close()
		return fmt.Errorf("no packet drop attach points available")
	}

	// Start reading from ring buffer
	dropReader, err = ringbuf.NewReader(dropObjs.DropEvents)
	if err != nil {
		for _, l := range dropLinks {
			l.Close()
		}
		coll.Close()
		return err
	}

	logger.Info("Packet drop monitoring eBPF program loaded successfully")
	return nil
}

// processConnectionEvents reads events from the connection ring buffer and stores them
func processConnectionEvents() {
	defer close(eventDone)
	logger.Info("Starting connection ring buffer event processing...")

	for {
		select {
		case <-eventCtx.Done():
			logger.Info("Stopping connection event processing...")
			return
		default:
			record, err := connectionReader.Read()
			if err != nil {
				if eventCtx.Err() != nil {
					return // Context cancelled, normal shutdown
				}
				logger.Errorf("Error reading from connection ring buffer: %v", err)
				continue
			}

			if err := processConnectionEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing connection event: %v", err)
			}
		}
	}
}

// processPacketDropEvents reads events from the packet drop ring buffer and stores them
func processPacketDropEvents() {
	logger.Info("Starting packet drop ring buffer event processing...")

	for {
		select {
		case <-eventCtx.Done():
			logger.Info("Stopping packet drop event processing...")
			return
		default:
			record, err := dropReader.Read()
			if err != nil {
				if eventCtx.Err() != nil {
					return // Context cancelled, normal shutdown
				}
				logger.Errorf("Error reading from drop ring buffer: %v", err)
				continue
			}

			if err := processPacketDropEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing packet drop event: %v", err)
			}
		}
	}
}

// processConnectionEvent processes a single connection event
func processConnectionEvent(data []byte) error {
	if len(data) < 60 {
		return fmt.Errorf("connection event data too short: %d bytes", len(data))
	}

	var event Event

	// Expected structure layout (based on struct event_t):
	// u32 pid (4 bytes)
	// u64 ts (8 bytes)
	// u32 ret (4 bytes)
	// char comm[16] (16 bytes)
	// u32 dest_ip (4 bytes)
	// u8 dest_ip6[16] (16 bytes)
	// u16 dest_port (2 bytes)
	// u16 family (2 bytes)
	// u8 protocol (1 byte)
	// u8 sock_type (1 byte)
	// u16 padding (2 bytes)
	// Total: 60 bytes

	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.TS = binary.LittleEndian.Uint64(data[4:12])
	event.Ret = int32(binary.LittleEndian.Uint32(data[12:16]))
	copy(event.Comm[:], data[16:32])
	event.DestIPv4 = binary.LittleEndian.Uint32(data[32:36])
	copy(event.DestIPv6[:], data[36:52])
	event.DestPort = binary.LittleEndian.Uint16(data[52:54])
	event.Family = binary.LittleEndian.Uint16(data[54:56])
	event.Protocol = data[56]
	event.SockType = data[57]

	// Handle address data based on family
	const AF_INET = 2
	const AF_INET6 = 10

	if event.Family == AF_INET6 {
		// Clear IPv4 data for IPv6 connections
		event.DestIPv4 = 0
	} else if event.Family == AF_INET {
		// Clear IPv6 data (should already be zero from struct initialization)
		for i := range event.DestIPv6 {
			event.DestIPv6[i] = 0
		}
	}

	// Skip events with no valid destination (common with IPv6 connections that fail address extraction)
	if event.GetDestIP() == "" {
		return nil
	}

	// Store the event
	connectionsMu.Lock()
	connections[event.PID] = append(connections[event.PID], event)
	connectionsMu.Unlock()

	logger.Debugf("Connection event: PID=%d, Command=%s, Dest=%s, Protocol=%s",
		event.PID, event.GetCommand(), event.GetDestination(), event.GetProtocol())

	return nil
}

// processPacketDropEvent processes a single packet drop event
func processPacketDropEvent(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("drop event data too short: %d bytes", len(data))
	}

	var event DropEvent

	// Expected structure layout for drop_event_t:
	// u32 pid (4 bytes)
	// u64 ts (8 bytes)
	// char comm[16] (16 bytes)
	// u32 drop_reason (4 bytes)
	// u32 skb_len (4 bytes)
	// u8 padding[8] (8 bytes)
	// Total: 44 bytes

	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.TS = binary.LittleEndian.Uint64(data[4:12])
	copy(event.Comm[:], data[12:28])
	event.DropReason = binary.LittleEndian.Uint32(data[28:32])
	if len(data) >= 36 {
		event.SkbLen = binary.LittleEndian.Uint32(data[32:36])
	}

	// Debug: Log raw data to understand what we're getting
	logger.Debugf("Raw packet drop data (%d bytes): %v", len(data), data)
	logger.Debugf("Parsed drop event: PID=%d, TS=%d, Comm=%v, DropReason=%d, SkbLen=%d",
		event.PID, event.TS, event.Comm, event.DropReason, event.SkbLen)

	// Store the event
	dropsMu.Lock()
	drops[event.PID] = append(drops[event.PID], event)
	dropsMu.Unlock()

	logger.Debugf("Packet drop event: PID=%d, Command=%s, Reason=%s, WallTime=%s",
		event.PID, event.GetCommand(), event.GetDropReasonString(), event.GetWallClockTime().Format("2006-01-02 15:04:05"))

	return nil
}

// GetConnectionSummary returns connection statistics for a given PID or command and duration
func GetConnectionSummary(pid uint32, command string, durationSeconds int) int {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()

	logger.Debugf("GetConnectionSummary called: pid=%d, command='%s', duration=%d", pid, command, durationSeconds)
	logger.Debugf("Total PIDs in connections map: %d", len(connections))

	// Debug: show all stored connections
	for storedPid, events := range connections {
		logger.Debugf("Stored PID %d has %d events", storedPid, len(events))
		for i, event := range events {
			if i >= 3 {
				logger.Debugf("  ... and %d more events", len(events)-3)
				break
			}
			logger.Debugf("  Event %d: Command=%s, Dest=%s, TS=%d", i+1, event.GetCommand(), event.GetDestination(), event.TS)
		}
	}

	// Get current eBPF time for comparison
	currentEBPFTime := time.Since(systemBootTime).Nanoseconds()
	logger.Debugf("Current eBPF time (ns since boot): %d", currentEBPFTime)

	// Check if we have any events at all
	totalEvents := 0
	for _, events := range connections {
		totalEvents += len(events)
	}
	if totalEvents == 0 {
		logger.Debug("No connection events stored yet")
		return 0
	}

	// Instead of using newest timestamp, use current time for cutoff calculation
	// This matches the eBPF time format (nanoseconds since boot)
	cutoffTime := currentEBPFTime - int64(durationSeconds)*int64(time.Second) // Convert seconds to nanoseconds

	// If command is specified, search by command name across all PIDs
	if command != "" {
		count := 0
		for _, events := range connections {
			for _, event := range events {
				if strings.Contains(strings.ToLower(event.GetCommand()), strings.ToLower(command)) &&
					int64(event.TS) >= cutoffTime {
					count++
				}
			}
		}
		logger.Debugf("Found %d connection attempts for command '%s' in last %d seconds", count, command, durationSeconds)
		return count
	}

	// If PID is specified, search by specific PID
	if pid != 0 {
		count := 0
		if events, exists := connections[pid]; exists {
			for _, event := range events {
				if int64(event.TS) >= cutoffTime {
					count++
				}
			}
		}
		logger.Debugf("Found %d connection attempts for PID %d in last %d seconds", count, pid, durationSeconds)
		return count
	}

	// Return the count of connection attempts in the time window
	return 0
}

// GetAllConnections returns all tracked connections (for debugging)
func GetAllConnections() map[uint32][]Event {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[uint32][]Event)
	for pid, events := range connections {
		eventsCopy := make([]Event, len(events))
		copy(eventsCopy, events)
		result[pid] = eventsCopy
	}

	return result
}

// GetPacketDropSummary returns packet drop statistics for a given PID or command and duration
func GetPacketDropSummary(pid uint32, command string, durationSeconds int) int {
	dropsMu.RLock()
	defer dropsMu.RUnlock()

	logger.Debugf("GetPacketDropSummary called: pid=%d, command='%s', duration=%d", pid, command, durationSeconds)

	// Get current eBPF time for comparison
	currentEBPFTime := time.Since(systemBootTime).Nanoseconds()
	cutoffTime := currentEBPFTime - int64(durationSeconds)*int64(time.Second)

	count := 0

	if command != "" {
		// Search by command name across all PIDs
		for _, events := range drops {
			for _, event := range events {
				if strings.Contains(strings.ToLower(event.GetCommand()), strings.ToLower(command)) &&
					int64(event.TS) >= cutoffTime {
					count++
				}
			}
		}
	} else if pid != 0 {
		// Search by specific PID
		if events, exists := drops[pid]; exists {
			for _, event := range events {
				if int64(event.TS) >= cutoffTime {
					count++
				}
			}
		}
	}

	return count
}

// GetAllPacketDrops returns all tracked packet drops
func GetAllPacketDrops() map[uint32][]DropEvent {
	dropsMu.RLock()
	defer dropsMu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[uint32][]DropEvent)
	for pid, events := range drops {
		eventsCopy := make([]DropEvent, len(events))
		copy(eventsCopy, events)
		result[pid] = eventsCopy
	}

	return result
}

// Cleanup closes the ring buffer reader and detaches programs
func Cleanup() {
	logger.Info("Starting eBPF cleanup...")

	// Signal the event processing goroutine to stop
	if eventCancel != nil {
		eventCancel()
	}

	// Wait for the event processing goroutine to finish (with timeout)
	if eventDone != nil {
		select {
		case <-eventDone:
		case <-time.After(5 * time.Second):
			logger.Info("Timeout waiting for event processing to stop")
		}
	}

	// Close connection ring buffer reader
	if connectionReader != nil {
		logger.Info("Closing connection ring buffer reader...")
		connectionReader.Close()
		connectionReader = nil
	}

	// Close packet drop ring buffer reader
	if dropReader != nil {
		logger.Info("Closing drop ring buffer reader...")
		dropReader.Close()
		dropReader = nil
	}

	// Close connection links
	for _, l := range connectionLinks {
		if l != nil {
			l.Close()
		}
	}
	connectionLinks = nil

	// Close packet drop links
	for _, l := range dropLinks {
		if l != nil {
			l.Close()
		}
	}
	dropLinks = nil

	// Close connection maps
	if connectionObjs.Events != nil {
		logger.Info("Closing connection maps...")
		connectionObjs.Events.Close()
		connectionObjs.Events = nil
	}

	// Close packet drop maps
	if dropObjs.DropEvents != nil {
		logger.Info("Closing drop maps...")
		dropObjs.DropEvents.Close()
		dropObjs.DropEvents = nil
	}

	logger.Info("eBPF cleanup complete")
}
