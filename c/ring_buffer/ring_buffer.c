#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u32 sig;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracing/syscalls/sys_enter_kill")
int ringbuffer_execve(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int tpid = ctx->args[0];
    int sig = ctx->args[1];
    struct event e = {
            .pid=pid,
            .sig = sig,
    };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}