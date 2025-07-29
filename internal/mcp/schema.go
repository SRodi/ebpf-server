package mcp

import "github.com/srodi/mcp-ebpf/internal/bpf"

type GetConnectionSummaryRequest struct {
    PID     int    `json:"pid,omitempty"`
    Command string `json:"command,omitempty"`
    Seconds int    `json:"duration"`
}

type GetConnectionSummaryResponse struct {
    Total   int     `json:"total_attempts"`
    Average float64 `json:"avg_latency_ms"`
}

type ListConnectionsResponse struct {
    Connections map[uint32][]bpf.Event `json:"connections"`
}
