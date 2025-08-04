#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Packet drop event structure
struct drop_event_t {
    u32 pid;            // Process ID
    u64 ts;             // Timestamp (nanoseconds since boot)
    char comm[16];      // Command name
    u32 drop_reason;    // Drop reason code
    u32 skb_len;        // Socket buffer length (when available)
    u8 padding[8];      // Padding for alignment
} __attribute__((packed)); // Force no padding

// Ring buffer for packet drop events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} drop_events SEC(".maps");

// Tracepoint for kfree_skb (packet drops)
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(void *ctx) {
    struct drop_event_t *event;
    u64 pid_tgid;
    u32 pid;
    
    // Get current task info
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    // Skip kernel threads (PID 0)
    if (pid == 0)
        return 0;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Initialize event structure
    __builtin_memset(event, 0, sizeof(*event));
    
    // Fill basic event information
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->drop_reason = 1; // Generic drop reason
    event->skb_len = 1; // Mark as valid drop event
    
    // Get command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Alternative: Monitor failed socket operations
SEC("kprobe/tcp_drop")
int trace_tcp_drop(struct pt_regs *ctx) {
    struct drop_event_t *event;
    u64 pid_tgid;
    u32 pid;
    
    // Get current task info
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    // Skip kernel threads
    if (pid == 0)
        return 0;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Initialize event structure
    __builtin_memset(event, 0, sizeof(*event));
    
    // Fill basic event information
    event->pid = pid;
    event->ts = bpf_ktime_get_ns();
    event->drop_reason = 2; // TCP drop
    event->skb_len = 1; // Mark as valid drop event
    
    // Get command name
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}
