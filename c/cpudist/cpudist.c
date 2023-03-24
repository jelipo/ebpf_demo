#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u64 ts;
    u64 pid_tgid;
    u32 tgid;
    u32 pid;
    u32 cpu;
    u32 prev_pid;
    u32 next_pid;
};

struct bpf_map_def SEC("maps") events = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 24,
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct pt_regs *ctx, struct trace_event_raw_sched_switch *trace) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    //u32 cpu = bpf_get_smp_processor_id();

//    u32 prev_pid = trace->prev_pid;
//    u32 next_pid = trace->next_pid;


    struct event e = {
            .ts=ts,
            .pid_tgid=pid_tgid,
            .tgid=tgid,
            .pid=pid,
            .cpu=0,
            .prev_pid=0,
            .next_pid=0,
    };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);

    return 0;
}

