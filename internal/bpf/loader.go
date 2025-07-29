package bpf

import (
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
    "github.com/srodi/mcp-ebpf/pkg/logger"
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
)

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
    logger.Info("Starting ring buffer event processing...")
    
    for {
        record, err := reader.Read()
        if err != nil {
            logger.Debugf("Error reading from ring buffer: %v", err)
            continue
        }

        logger.Debugf("Received ring buffer event: %d bytes", len(record.RawSample))
        logger.Debugf("Raw bytes: %x", record.RawSample)

        if len(record.RawSample) < 44 { // sizeof(event_t) packed = 4+8+4+16+4+2+2+1+1+2 = 44
            logger.Debugf("Event too small: %d bytes, expected at least 44", len(record.RawSample))
            continue
        }

        // Packed struct layout (no padding):
        // u32 pid (4 bytes)
        // u64 ts (8 bytes)  
        // u32 ret (4 bytes)
        // char comm[16] (16 bytes)
        // u32 dest_ip (4 bytes)
        // u16 dest_port (2 bytes)
        // u16 family (2 bytes)
        // u8 protocol (1 byte)
        // u8 sock_type (1 byte)
        // u16 padding (2 bytes)
        // Total: 44 bytes
        
        event := Event{
            PID:      binary.LittleEndian.Uint32(record.RawSample[0:4]),
            TS:       binary.LittleEndian.Uint64(record.RawSample[4:12]),
            Ret:      int32(binary.LittleEndian.Uint32(record.RawSample[12:16])),
            DestIP:   binary.LittleEndian.Uint32(record.RawSample[32:36]),
            DestPort: binary.LittleEndian.Uint16(record.RawSample[36:38]),
            Family:   binary.LittleEndian.Uint16(record.RawSample[38:40]),
            Protocol: record.RawSample[40],
            SockType: record.RawSample[41],
            Padding:  binary.LittleEndian.Uint16(record.RawSample[42:44]),
        }
        copy(event.Comm[:], record.RawSample[16:32])
        
        logger.Debugf("Parsed: PID=%d, TS=%d, Ret=%d, DestIP=%s, DestPort=%d, Protocol=%s", 
                  event.PID, event.TS, event.Ret, event.GetDestIP(), event.DestPort, event.GetProtocol())
        logger.Debugf("Command bytes: %x", event.Comm[:])
        logger.Debugf("Command string: '%s'", event.GetCommand())

        logger.Debugf("Processed event: PID=%d, Command='%s', Destination='%s', Protocol='%s', TS=%d", 
                  event.PID, event.GetCommand(), event.GetDestination(), event.GetProtocol(), event.TS)

        // Store the event
        connectionsMu.Lock()
        connections[event.PID] = append(connections[event.PID], event)
        logger.Debugf("Stored event for PID %d, total events for this PID: %d", 
                  event.PID, len(connections[event.PID]))
        connectionsMu.Unlock()
    }
}

// GetConnectionSummary returns connection statistics for a given PID or command and duration
func GetConnectionSummary(pid uint32, command string, durationSeconds int) (int, float64) {
    connectionsMu.RLock()
    defer connectionsMu.RUnlock()

    // Get current time and convert to the same timestamp format as eBPF events
    // eBPF uses ktime_get_ns() which is nanoseconds since boot
    // We need to filter based on the most recent events, not absolute time
    var newestTimestamp uint64
    for _, events := range connections {
        for _, event := range events {
            if event.TS > newestTimestamp {
                newestTimestamp = event.TS
            }
        }
    }
    
    // If no events exist, return empty
    if newestTimestamp == 0 {
        return 0, 0.0
    }
    
    // Calculate cutoff based on duration from the newest event
    cutoff := newestTimestamp - uint64(durationSeconds)*1e9 // Convert seconds to nanoseconds

    var recentEvents []Event
    
    // If command is specified, search by command name across all PIDs
    if command != "" {
        logger.Debugf("Searching for command '%s' in the last %d seconds", command, durationSeconds)
        for pid, events := range connections {
            for _, event := range events {
                eventCommand := event.GetCommand()
                logger.Debugf("Checking PID %d: command='%s', timestamp=%d, cutoff=%d", 
                          pid, eventCommand, event.TS, cutoff)
                if event.TS >= cutoff && eventCommand == command {
                    recentEvents = append(recentEvents, event)
                    logger.Debugf("  -> Match found!")
                }
            }
        }
        logger.Debugf("Found %d matching events for command '%s'", len(recentEvents), command)
    } else {
        // Search by PID (original behavior)
        events, exists := connections[pid]
        if !exists {
            return 0, 0.0
        }

        for _, event := range events {
            if event.TS >= cutoff {
                recentEvents = append(recentEvents, event)
            }
        }
    }

    if len(recentEvents) == 0 {
        return 0, 0.0
    }

    // Calculate average latency as the average time between connection attempts within the same PID
    // This gives a more meaningful metric than comparing across different processes
    var totalLatency float64
    var latencyCount int
    
    // Group events by PID
    pidEvents := make(map[uint32][]Event)
    for _, event := range recentEvents {
        pidEvents[event.PID] = append(pidEvents[event.PID], event)
    }
    
    // Calculate latency within each PID's events
    for _, events := range pidEvents {
        if len(events) > 1 {
            // Sort events by timestamp (they should already be in order)
            for i := 1; i < len(events); i++ {
                latency := float64(events[i].TS-events[i-1].TS) / 1e6 // Convert to milliseconds
                totalLatency += latency
                latencyCount++
            }
        }
    }

    avgLatency := 0.0
    if latencyCount > 0 {
        avgLatency = totalLatency / float64(latencyCount)
    }

    return len(recentEvents), avgLatency
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
    if reader != nil {
        reader.Close()
    }
    
    for _, l := range links {
        l.Close()
    }
    
    if objs.Events != nil {
        objs.Events.Close()
    }
}
