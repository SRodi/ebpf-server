package bpf

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

var (
	// Boot time for converting eBPF timestamps to wall clock time
	bootTime     time.Time
	bootTimeOnce sync.Once
)

// BaseEvent provides common functionality for all eBPF events
type BaseEvent struct {
	PID  uint32
	TS   uint64
	Comm [16]byte
}

// GetPID returns the process ID
func (e *BaseEvent) GetPID() uint32 {
	return e.PID
}

// GetTimestamp returns the eBPF timestamp (nanoseconds since boot)
func (e *BaseEvent) GetTimestamp() uint64 {
	return e.TS
}

// GetCommand returns the command name as a string
func (e *BaseEvent) GetCommand() string {
	// Convert the byte array to a null-terminated string
	cmd := make([]byte, 0, 16)
	for i := 0; i < len(e.Comm) && e.Comm[i] != 0; i++ {
		cmd = append(cmd, e.Comm[i])
	}
	return string(cmd)
}

// GetWallClockTime converts eBPF timestamp to wall clock time
func (e *BaseEvent) GetWallClockTime() time.Time {
	bootTimeOnce.Do(func() {
		calculateBootTime()
	})
	return bootTime.Add(time.Duration(e.TS))
}

// GetSystemBootTime returns the calculated system boot time
func GetSystemBootTime() time.Time {
	bootTimeOnce.Do(func() {
		calculateBootTime()
	})
	return bootTime
}

// calculateBootTime calculates the system boot time for timestamp conversion
func calculateBootTime() {
	// Read system uptime from /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		logger.Infof("Could not read /proc/uptime: %v, using current time", err)
		bootTime = time.Now()
		return
	}

	// Parse uptime (first number is seconds since boot)
	uptimeStr := strings.Fields(string(data))[0]
	uptime, err := strconv.ParseFloat(uptimeStr, 64)
	if err != nil {
		logger.Infof("Could not parse uptime: %v, using current time", err)
		bootTime = time.Now()
		return
	}

	// Calculate boot time
	bootTime = time.Now().Add(-time.Duration(uptime * float64(time.Second)))

	logger.Infof("System boot time calculated: %s", bootTime.Format("2006-01-02 15:04:05"))
}
