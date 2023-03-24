#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    int size;
    u32 pid;
};

struct bpf_map_def SEC("maps") events = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 24,
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/kmem/kmalloc")
int trace_kmalloc(struct trace_event_raw_kmem_alloc *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    //int r_pid = ctx->ptr;
    struct event e = {
            .size=ctx->bytes_alloc,
            .pid=pid,
    };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}