#ifndef __BPF_CORE_READ_H
#define __BPF_CORE_READ_H

#include "bpf_helpers.h"

/* BPF CO-RE (Compile Once - Run Everywhere) read helpers */

/* Core read macro - safely read kernel memory */
#define bpf_core_read(dst, sz, src) \
    bpf_probe_read_kernel(dst, sz, (const void *)(src))

/* Type-safe core read */
#define bpf_core_read_into(dst, src) \
    bpf_core_read(dst, sizeof(*(dst)), src)

/* Read a field from a kernel structure */
#define BPF_CORE_READ_INTO(dst, src, a, ...) \
    BPF_CORE_READ_INTO_IMPL(dst, src, a, ##__VA_ARGS__)

#define BPF_CORE_READ_INTO_IMPL(dst, src, a, ...) \
    ({ \
        bpf_core_read((dst), sizeof(*(dst)), &((src)->a)); \
    })

/* String operations */
#define BPF_CORE_READ_STR_INTO(dst, src, a, ...) \
    ({ \
        bpf_probe_read_kernel_str((dst), sizeof(dst), &((src)->a)); \
    })

/* Helper to read user space memory */
#define bpf_core_read_user(dst, sz, src) \
    bpf_probe_read_user(dst, sz, (const void *)(src))

#define bpf_core_read_user_into(dst, src) \
    bpf_core_read_user(dst, sizeof(*(dst)), src)

/* String read helper */
static int (*bpf_probe_read_kernel_str)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *) 115;
static int (*bpf_probe_read_user_str)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *) 114;

#endif /* __BPF_CORE_READ_H */
