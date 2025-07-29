package server

import (
	"net/http"

	"github.com/srodi/mcp-ebpf/internal/mcp"
	"github.com/srodi/mcp-ebpf/pkg/logger"
)

func Start() {
	http.HandleFunc("/mcp", mcp.HandleMCP)
	logger.Info("Starting MCP server on :8080")
	logger.Fatal(http.ListenAndServe(":8080", nil))
}
