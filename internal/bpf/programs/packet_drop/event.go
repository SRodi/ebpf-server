package packet_drop

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/srodi/ebpf-server/internal/bpf"
)

// Event represents a packet drop event
type Event struct {
	bpf.BaseEvent
	DropReason uint32  `json:"drop_reason"`
	SkbLen     uint32  `json:"skb_length"`
	Padding    [8]byte `json:"-"`
}

// GetEventType returns the event type identifier
func (e *Event) GetEventType() string {
	return "packet_drop"
}

// GetDropReasonString returns a human-readable drop reason
func (e *Event) GetDropReasonString() string {
	switch e.DropReason {
	case 1:
		return "SKB_FREE"
	case 2:
		return "TCP_DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", e.DropReason)
	}
}

// EventJSON is used for JSON serialization with human-readable fields
type EventJSON struct {
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
func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(EventJSON{
		PID:           e.GetPID(),
		Timestamp:     e.GetTimestamp(),
		Command:       e.GetCommand(),
		DropReason:    e.DropReason,
		DropReasonStr: e.GetDropReasonString(),
		SkbLength:     e.SkbLen,
		WallTime:      e.GetWallClockTime().Format(time.RFC3339),
		Note:          "timestamp_ns is nanoseconds since boot, wall_time is converted to UTC",
	})
}
