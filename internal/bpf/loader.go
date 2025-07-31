package bpf

import (
	"context"
	"encoding/binary"
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
	objs struct {
		Events *ebpf.Map
	}
	links []link.Link

	// Connection tracking
	connectionsMu sync.RWMutex
	connections   = make(map[uint32][]Event) // PID -> []Event

	// Ring buffer reader
	reader *ringbuf.Reader

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
		return false
	}

	// Try to remove memory limit for eBPF - this will fail if not supported
	if err := rlimit.RemoveMemlock(); err != nil {
		return false
	}

	// Check if we can access /sys/fs/bpf (BPF filesystem)
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return false
	}

	return true
}

// calculateBootTimeOffset calculates the system boot time for timestamp conversion
func calculateBootTimeOffset() {
	// Read system uptime from /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		logger.Debugf("Could not read /proc/uptime: %v", err)
		systemBootTime = time.Now() // Fallback to current time
		return
	}

	// Parse uptime (first number is seconds since boot)
	uptimeStr := strings.Fields(string(data))[0]
	uptime, err := strconv.ParseFloat(uptimeStr, 64)
	if err != nil {
		logger.Debugf("Could not parse uptime: %v", err)
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

	spec, err := ebpf.LoadCollectionSpec("bpf/connection.o")
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	objs.Events = coll.Maps["events"]

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", coll.Programs["trace_connect"], nil)
	if err != nil {
		return err
	}

	links = append(links, tp)

	// Start reading from ring buffer
	reader, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		return err
	}

	// Start event processing goroutine
	go processEvents()

	logger.Info("eBPF program attached to sys_enter_connect")
	return nil
}

// processEvents reads events from the ring buffer and stores them
func processEvents() {
	defer close(eventDone)
	logger.Info("Starting ring buffer event processing...")

	for {
		select {
		case <-eventCtx.Done():
			logger.Info("Event processing stopped by context cancellation")
			return
		default:
			// Continue with event processing
		}

		record, err := reader.Read()
		if err != nil {
			// Check if we're shutting down before logging the error
			select {
			case <-eventCtx.Done():
				logger.Debug("Ring buffer read error during shutdown (expected)")
				return
			default:
				logger.Debugf("Error reading from ring buffer: %v", err)
				continue
			}
		}

		logger.Debugf("Received ring buffer event: %d bytes", len(record.RawSample))
		logger.Debugf("Raw bytes: %x", record.RawSample)

		if len(record.RawSample) < 60 { // sizeof(event_t) packed = 4+8+4+16+4+16+2+2+1+1+2 = 60
			logger.Debugf("Event too small: %d bytes, expected at least 60", len(record.RawSample))
			continue
		}

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

		event := Event{
			PID:      binary.LittleEndian.Uint32(record.RawSample[0:4]),
			TS:       binary.LittleEndian.Uint64(record.RawSample[4:12]),
			Ret:      int32(binary.LittleEndian.Uint32(record.RawSample[12:16])),
			DestIPv4: binary.LittleEndian.Uint32(record.RawSample[32:36]),
			DestPort: binary.LittleEndian.Uint16(record.RawSample[52:54]),
			Family:   binary.LittleEndian.Uint16(record.RawSample[54:56]),
			Protocol: record.RawSample[56],
			SockType: record.RawSample[57],
			Padding:  binary.LittleEndian.Uint16(record.RawSample[58:60]),
		}
		copy(event.Comm[:], record.RawSample[16:32])

		// Handle address data based on family
		family := event.Family
		if family == 2 { // AF_INET - IPv4 data is at offset 32
			event.DestIPv4 = binary.LittleEndian.Uint32(record.RawSample[32:36])
			// Clear IPv6 data (should already be zero from struct initialization)
		} else if family == 10 { // AF_INET6 - IPv6 data is at offset 36
			copy(event.DestIPv6[:], record.RawSample[36:52])
			// IPv4 field should remain 0
		}

		logger.Debugf("Parsed: PID=%d, TS=%d, Ret=%d, DestIP=%s, DestPort=%d, Protocol=%s",
			event.PID, event.TS, event.Ret, event.GetDestIP(), event.DestPort, event.GetProtocol())
		logger.Debugf("Command bytes: %x", event.Comm[:])
		logger.Debugf("Command string: '%s'", event.GetCommand())

		logger.Debugf("Processed event: PID=%d, Command='%s', Destination='%s', Protocol='%s', TS=%d",
			event.PID, event.GetCommand(), event.GetDestination(), event.GetProtocol(), event.TS)

		// Skip events with no valid destination (common with IPv6 connections that fail address extraction)
		if event.GetDestination() == "" || event.GetDestination() == ":0" {
			logger.Debugf("Skipping event with invalid destination: '%s'", event.GetDestination())
			continue
		}

		// Store the event
		connectionsMu.Lock()
		connections[event.PID] = append(connections[event.PID], event)
		logger.Debugf("Stored event for PID %d, total events for this PID: %d",
			event.PID, len(connections[event.PID]))
		connectionsMu.Unlock()
	}
}

// GetConnectionSummary returns connection statistics for a given PID or command and duration
// Returns count of connection attempts in the specified time window
func GetConnectionSummary(pid uint32, command string, durationSeconds int) int {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()

	logger.Debugf("GetConnectionSummary called: pid=%d, command='%s', duration=%d", pid, command, durationSeconds)
	logger.Debugf("Total PIDs in connections map: %d", len(connections))

	// Debug: show all stored connections
	for storedPid, events := range connections {
		logger.Debugf("  PID %d has %d events, newest: %d", storedPid, len(events),
			func() uint64 {
				if len(events) > 0 {
					return events[len(events)-1].TS
				}
				return 0
			}())
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
		logger.Debugf("No events found, returning 0")
		return 0
	}

	// Instead of using newest timestamp, use current time for cutoff calculation
	// This matches the eBPF time format (nanoseconds since boot)
	cutoff := uint64(currentEBPFTime) - uint64(durationSeconds)*1e9 // Convert seconds to nanoseconds
	logger.Debugf("Cutoff timestamp: %d (duration: %d seconds)", cutoff, durationSeconds)

	var recentEvents []Event

	// If command is specified, search by command name across all PIDs
	if command != "" {
		logger.Debugf("Searching for command '%s' in the last %d seconds", command, durationSeconds)
		for pid, events := range connections {
			for _, event := range events {
				eventCommand := event.GetCommand()
				logger.Debugf("Checking PID %d: command='%s', timestamp=%d, cutoff=%d, match=%t",
					pid, eventCommand, event.TS, cutoff, event.TS >= cutoff && eventCommand == command)
				if event.TS >= cutoff && eventCommand == command {
					recentEvents = append(recentEvents, event)
					logger.Debugf("  -> Match found! Total matches so far: %d", len(recentEvents))
				}
			}
		}
		logger.Debugf("Found %d matching events for command '%s'", len(recentEvents), command)
	} else {
		// Search by PID (original behavior)
		events, exists := connections[pid]
		if !exists {
			logger.Debugf("PID %d not found in connections", pid)
			return 0
		}

		logger.Debugf("Searching PID %d events (total: %d)", pid, len(events))
		for _, event := range events {
			logger.Debugf("  Event TS: %d, cutoff: %d, include: %t", event.TS, cutoff, event.TS >= cutoff)
			if event.TS >= cutoff {
				recentEvents = append(recentEvents, event)
			}
		}
		logger.Debugf("Found %d recent events for PID %d", len(recentEvents), pid)
	}

	if len(recentEvents) == 0 {
		logger.Debugf("No recent events found, returning 0")
		return 0
	}

	logger.Debugf("Returning count: %d", len(recentEvents))
	// Return the count of connection attempts in the time window
	return len(recentEvents)
}

// GetAllConnections returns all tracked connections (for debugging)
func GetAllConnections() map[uint32][]Event {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()

	result := make(map[uint32][]Event)
	for pid, events := range connections {
		result[pid] = make([]Event, len(events))
		copy(result[pid], events)
	}
	return result
}

// Cleanup closes the ring buffer reader and detaches programs
func Cleanup() {
	logger.Info("Starting eBPF cleanup...")

	// Signal the event processing goroutine to stop
	if eventCancel != nil {
		logger.Debug("Cancelling event processing context...")
		eventCancel()
	}

	// Wait for the event processing goroutine to finish (with timeout)
	if eventDone != nil {
		logger.Debug("Waiting for event processing to complete...")
		select {
		case <-eventDone:
			logger.Debug("Event processing goroutine finished")
		case <-time.After(5 * time.Second):
			logger.Error("Timeout waiting for event processing to finish")
		}
	}

	// Close ring buffer reader
	if reader != nil {
		logger.Debug("Closing ring buffer reader...")
		reader.Close()
		reader = nil
	}

	// Close links
	logger.Debug("Closing eBPF links...")
	for _, l := range links {
		l.Close()
	}
	links = nil

	// Close maps
	if objs.Events != nil {
		logger.Debug("Closing eBPF maps...")
		objs.Events.Close()
		objs.Events = nil
	}

	logger.Info("eBPF cleanup complete")
}
