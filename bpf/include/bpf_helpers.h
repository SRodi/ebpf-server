#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* BPF helper functions - these are provided by the kernel */

/* Map operations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

/* Ringbuf operations */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, unsigned long long flags) = (void *) 133;

/* Process/task helpers */
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static int (*bpf_get_current_comm)(void *buf, unsigned int size_of_buf) = (void *) 16;

/* Time helpers */
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *) 5;

/* Tracing helpers */
static int (*bpf_probe_read)(void *dst, unsigned int size, const void *src) = (void *) 4;
static int (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *src) = (void *) 113;
static int (*bpf_probe_read_user)(void *dst, unsigned int size, const void *src) = (void *) 112;

/* Debug helpers */
static int (*bpf_trace_printk)(const char *fmt, unsigned int fmt_size, ...) = (void *) 6;

/* Map type definitions */
#define BPF_MAP_TYPE_HASH           1
#define BPF_MAP_TYPE_ARRAY          2
#define BPF_MAP_TYPE_PROG_ARRAY     3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_HASH    5
#define BPF_MAP_TYPE_PERCPU_ARRAY   6
#define BPF_MAP_TYPE_STACK_TRACE    7
#define BPF_MAP_TYPE_CGROUP_ARRAY   8
#define BPF_MAP_TYPE_LRU_HASH       9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE       11
#define BPF_MAP_TYPE_ARRAY_OF_MAPS  12
#define BPF_MAP_TYPE_HASH_OF_MAPS   13
#define BPF_MAP_TYPE_DEVMAP         14
#define BPF_MAP_TYPE_SOCKMAP        15
#define BPF_MAP_TYPE_CPUMAP         16
#define BPF_MAP_TYPE_XSKMAP         17
#define BPF_MAP_TYPE_SOCKHASH       18
#define BPF_MAP_TYPE_CGROUP_STORAGE 19
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#define BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 21
#define BPF_MAP_TYPE_QUEUE          22
#define BPF_MAP_TYPE_STACK          23
#define BPF_MAP_TYPE_SK_STORAGE     24
#define BPF_MAP_TYPE_DEVMAP_HASH    25
#define BPF_MAP_TYPE_STRUCT_OPS     26
#define BPF_MAP_TYPE_RINGBUF        27

/* Section and map helper macros */
#define SEC(name) __attribute__((section(name), used))

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#endif /* __BPF_HELPERS_H */
