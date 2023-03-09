#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

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
int ringbuffer_execve(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int tpid = ctx->args[0];
    int sig = ctx->args[1];
    struct event e = {
            .pid=tpid,
            .sig=sig,
    };
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}


#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[16];
};

struct bpf_map_def SEC("maps") start = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(key_t),
        .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") counts = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(u32),
        .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") stack_traces = {
        .type = BPF_MAP_TYPE_STACK_TRACE,
        .key_size=sizeof(u32), // TODO size大小未知
        .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") stack_map = {
        .type           = BPF_MAP_TYPE_STACK_TRACE,
        .key_size       = sizeof(uint32_t),
        .value_size     = sizeof(struct bpf_stacktrace),
        .max_entries    = 10240
};

struct bpf_map_def SEC("maps") _name = {
        .type = _type,
        .key_size = sizeof(u32),
        .value_size = sizeof(struct bpf_stacktrace_info),
        .max_entries = 10240
};

struct warn_event_t {
    u32 pid;
    u32 tgid;
    u32 t_start;
    u32 t_end;
};

struct bpf_map_def SEC("maps") warn_events = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size=sizeof(u32), // TODO size大小未知
        .max_entries = 1 << 24,
};


BPF_PERF_OUTPUT(warn_events);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;

    // record previous thread sleep time
    if ((THREAD_FILTER) && (STATE_FILTER)) {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time 计算当前线程的增量时间
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&start, &pid)
    if (t_start > t_end) {
        struct warn_event_t event = {
                .pid = pid,
                .tgid = tgid,
                .t_start = t_start,
                .t_end = t_end,
        };
        warn_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    u64 delta = t_end - t_start;
    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;

    bpf_get_stack(ctx,)

    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&key.name, sizeof(key.name));
    counts.increment(key, delta);
    return 0;
}