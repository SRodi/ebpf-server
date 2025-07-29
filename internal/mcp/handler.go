package mcp

import (
    "encoding/json"
    "net/http"
    
    "github.com/srodi/mcp-ebpf/internal/bpf"
    "github.com/srodi/mcp-ebpf/pkg/logger"
)

func HandleMCP(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Method string          `json:"method"`
        Params json.RawMessage `json:"params"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid JSON", http.StatusBadRequest)
        return
    }

    switch req.Method {
    case "get_connection_summary":
        var p GetConnectionSummaryParams
        if err := json.Unmarshal(req.Params, &p); err != nil {
            http.Error(w, "invalid params", http.StatusBadRequest)
            return
        }
        
        var total int
        if p.Command != "" {
            total = bpf.GetConnectionSummary(0, p.Command, p.Seconds)
            logger.Debugf("Connection summary for command '%s': %d attempts in %d seconds", 
                      p.Command, total, p.Seconds)
        } else {
            total = bpf.GetConnectionSummary(uint32(p.PID), "", p.Seconds)
            logger.Debugf("Connection summary for PID %d: %d attempts in %d seconds", 
                      p.PID, total, p.Seconds)
        }
        
        resp := GetConnectionSummaryResponse{
            Total: total,
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "result": resp,
        })
        
    case "list_connections":
        // Additional method to list all tracked connections (for debugging)
        allConnections := bpf.GetAllConnections()
        
        logger.Debugf("Total PIDs being tracked: %d", len(allConnections))
        for pid, events := range allConnections {
            logger.Debugf("PID %d: %d events", pid, len(events))
            for i, event := range events {
                if i < 3 { // Log first 3 events for each PID
                    logger.Debugf("  Event %d: PID=%d, Command='%s', Time=%s", 
                              i, event.PID, event.GetCommand(), event.GetTime().Format("15:04:05"))
                }
            }
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "result": allConnections,
        })
        
    default:
        http.Error(w, "unknown method", http.StatusBadRequest)
    }
}
