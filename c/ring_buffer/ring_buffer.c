#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u32 sig;
};

struct bpf_map_def SEC("maps") events = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 24,
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_kill")
int ringbuffer_execve(struct trace_event_raw_sys_enter *trace) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    char text[] = "You are hacked!";
    long result = bpf_probe_write_user((u64 *) 0, text, sizeof(text));
    if (result != 0) {
        bpf_printk("some thing wrong!\n");
    }

    int tpid = trace->args[0];
    int sig = trace->args[1];
    struct event e = {
            .pid=tpid,
            .sig=sig,
    };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}