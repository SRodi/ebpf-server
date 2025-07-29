#ifndef __BPF_TRACING_H
#define __BPF_TRACING_H

#include "bpf_helpers.h"

/* Tracing program types */
#define BPF_PROG_TYPE_KPROBE        1
#define BPF_PROG_TYPE_TRACEPOINT    2
#define BPF_PROG_TYPE_PERF_EVENT    3

/* Platform register structure (simplified for x86_64) */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

/* Common tracing helpers and macros */

/* BPF CO-RE (Compile Once - Run Everywhere) helpers */
#define BPF_CORE_READ(dst, src) bpf_probe_read_kernel(dst, sizeof(*dst), src)

/* Tracepoint context access helpers */
static inline unsigned long PT_REGS_PARM1(const struct pt_regs *ctx) {
    return ctx->di;
}

static inline unsigned long PT_REGS_PARM2(const struct pt_regs *ctx) {
    return ctx->si;
}

static inline unsigned long PT_REGS_PARM3(const struct pt_regs *ctx) {
    return ctx->dx;
}

static inline unsigned long PT_REGS_PARM4(const struct pt_regs *ctx) {
    return ctx->cx;
}

static inline unsigned long PT_REGS_PARM5(const struct pt_regs *ctx) {
    return ctx->r8;
}

static inline unsigned long PT_REGS_RET(const struct pt_regs *ctx) {
    return ctx->sp;
}

static inline unsigned long PT_REGS_FP(const struct pt_regs *ctx) {
    return ctx->bp;
}

static inline unsigned long PT_REGS_RC(const struct pt_regs *ctx) {
    return ctx->ax;
}

static inline unsigned long PT_REGS_SP(const struct pt_regs *ctx) {
    return ctx->sp;
}

static inline unsigned long PT_REGS_IP(const struct pt_regs *ctx) {
    return ctx->ip;
}

#endif /* __BPF_TRACING_H */
