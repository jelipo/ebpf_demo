#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";


struct key_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    u8 name[16];
};

// Force emitting struct event into the ELF.
const struct key_t *unused __attribute__((unused));

struct bpf_map_def SEC("maps") events = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") stack_pids_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(u32),
        .value_size=0,
        .max_entries = 1024,
};

#define PERF_MAX_STACK_DEPTH        127

struct bpf_map_def SEC("maps") stack_traces = {
        .type = BPF_MAP_TYPE_STACK_TRACE,
        .key_size = sizeof(u32),
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
        .max_entries = 10000,
};

SEC("kprobe/finish_task_switch")
int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    // 判断是否是需要监控的PID
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&stack_pids_map, &pid) == NULL) {
        return 0;
    }
    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;

    // create map key
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;

    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&key.name, sizeof(key.name));


    // 发送到ring
    bpf_ringbuf_output(&events, &key, sizeof(key), 0);
    return 0;
}

struct ksym {
    long addr;
    char *name;
};

#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
static int sym_cnt;
struct ksym *ksym_search(long key){
    int start = 0, end = sym_cnt;
    int result;

    while (start < end) {
        size_t mid = start + (end - start) / 2;

        result = key - syms[mid].addr;
        if (result < 0)
            end = mid;
        else if (result > 0)
            start = mid + 1;
        else
            return &syms[mid];
    }

    if (start >= 1 && syms[start - 1].addr < key &&
        key < syms[start].addr)
        /* valid ksym */
        return &syms[start - 1];

    /* out of range. return _stext */
    return &syms[0];
}