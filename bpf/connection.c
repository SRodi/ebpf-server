#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Network constants (since they might not be in vmlinux.h)
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Network structures (define if not available in vmlinux.h)
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct {
        unsigned int s_addr;
    } sin_addr;
    char sin_zero[8];
};

struct event_t {
    u32 pid;
    u64 ts;
    u32 ret;  // Changed from int to u32 for better alignment
    char comm[16];
    u32 dest_ip;   // Destination IP address (IPv4)
    u16 dest_port; // Destination port
    u16 family;    // Address family (AF_INET, AF_INET6)
    u8 protocol;   // Protocol (IPPROTO_TCP, IPPROTO_UDP)
    u8 sock_type;  // Socket type (SOCK_STREAM, SOCK_DGRAM)
    u16 padding;   // Explicit padding for alignment
} __attribute__((packed)); // Force no padding

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ts = bpf_ktime_get_ns();
    e->ret = 0; // Initialize ret field
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Extract destination IP and port from connect() syscall arguments
    // ctx->args[0] = socket fd
    // ctx->args[1] = struct sockaddr *addr
    // ctx->args[2] = socklen_t addrlen
    
    // Initialize protocol fields
    e->protocol = 0;
    e->sock_type = 0;
    e->padding = 0;
    
    // Try to determine protocol from socket - this is tricky in eBPF
    // We'll use a heuristic based on the destination port for common protocols
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (addr) {
        u16 family;
        if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) == 0) {
            e->family = family;
            
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                if (bpf_probe_read_user(&e->dest_ip, sizeof(e->dest_ip), &addr_in->sin_addr.s_addr) != 0) {
                    e->dest_ip = 0;
                }
                if (bpf_probe_read_user(&e->dest_port, sizeof(e->dest_port), &addr_in->sin_port) != 0) {
                    e->dest_port = 0;
                } else {
                    e->dest_port = __builtin_bswap16(e->dest_port); // Convert from network to host byte order
                    
                    // Heuristic protocol detection based on common ports
                    // Most connect() calls on these ports are TCP
                    if (e->dest_port == 80 || e->dest_port == 443 || e->dest_port == 22 || 
                        e->dest_port == 21 || e->dest_port == 25 || e->dest_port == 993 || 
                        e->dest_port == 995 || e->dest_port == 587 || e->dest_port == 143 ||
                        e->dest_port == 110 || e->dest_port == 3306 || e->dest_port == 5432) {
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    } else if (e->dest_port == 53 || e->dest_port == 67 || e->dest_port == 68 ||
                               e->dest_port == 123 || e->dest_port == 161 || e->dest_port == 162) {
                        e->protocol = IPPROTO_UDP;
                        e->sock_type = SOCK_DGRAM;
                    } else {
                        // Default assumption: most connect() calls are TCP
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    }
                }
            } else {
                e->dest_ip = 0;
                e->dest_port = 0;
            }
        } else {
            e->family = 0;
            e->dest_ip = 0;
            e->dest_port = 0;
        }
    } else {
        e->family = 0;
        e->dest_ip = 0;
        e->dest_port = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
