package mcp

import "github.com/srodi/mcp-ebpf/internal/bpf"

type GetConnectionSummaryParams struct {
    PID     int    `json:"pid,omitempty"`
    Command string `json:"command,omitempty"`
    Seconds int    `json:"duration"`
}

type GetConnectionSummaryResponse struct {
    Total int `json:"total_attempts"`
}

type ListConnectionsResponse struct {
    Connections map[uint32][]bpf.Event `json:"connections"`
}
