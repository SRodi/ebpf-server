#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifdef __TARGET_ARCH_x86
#define bpf_target_x86
#define bpf_target_defined
#elif defined(__TARGET_ARCH_arm64)
#define bpf_target_arm64
#define bpf_target_defined
#endif

/* Basic type definitions for eBPF programs */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

/* Process/task related structures */
struct trace_event_raw_sys_enter {
    u16 common_type;
    u8 common_flags;
    u8 common_preempt_count;
    s32 common_pid;
    s32 id;
    unsigned long args[6];
};

/* Basic kernel structures needed for eBPF */
struct task_struct {
    int pid;
    int tgid;
    char comm[16];
};

/* Socket and network structures (simplified) */
struct sock {
    u16 sk_family;
    u16 sk_type;
    u32 sk_rcvbuf;
    u32 sk_sndbuf;
};

struct sk_buff {
    u32 len;
    u32 data_len;
    u16 mac_len;
    u16 hdr_len;
    u32 priority;
    u32 mark;
};

/* Time structures */
typedef u64 ktime_t;

#endif /* __VMLINUX_H__ */
