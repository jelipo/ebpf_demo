#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";


struct key_t {
    u32 pid;
    u32 tgid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u8 name[16];
};

int test() {
    return 0;
}

int main() {}

// Force emitting struct event into the ELF.
const struct key_t *unused __attribute__((unused));

struct bpf_map_def SEC("maps") events = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 24,
};

struct bpf_map_def SEC("maps") stack_pids_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(u32),
        .value_size=sizeof(int),
        .max_entries = 1024,
};

#define PERF_MAX_STACK_DEPTH        127

struct bpf_map_def SEC("maps") stack_traces = {
        .type = BPF_MAP_TYPE_STACK_TRACE,
        .key_size = sizeof(u32),
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
        .max_entries = 10000,
};

void print_trace(struct trace_event_raw_sched_switch *ctx) {
    u8 name[16];
    bpf_get_current_comm(&name, sizeof(name));
    bpf_printk("curr:%d   %s    ", bpf_get_current_pid_tgid(), &name);
    bpf_printk("prev:%d   %s    ", ctx->prev_pid, ctx->prev_comm);
    bpf_printk("next:%d   %s    \n", ctx->next_pid, ctx->next_comm);
}

SEC("tracepoint/sched/sched_switch")
int oncpu(struct trace_event_raw_sched_switch *ctx) {
    // 判断是否是需要监控的PID
    char listen_pid_key[4] = "key1";
    u32 *listen_pid = bpf_map_lookup_elem(&stack_pids_map, &listen_pid_key);

    if (listen_pid == NULL) {
        //bpf_printk("NULL");
        return 0;
    }
    u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    u8 name[16];
    bpf_get_current_comm(&name, sizeof(name));
    //bpf_printk("curr %d %s", curr_pid, name);
    if (curr_pid == *listen_pid || ctx->prev_pid == *listen_pid ||
        ctx->next_pid == *listen_pid) {
        print_trace(ctx);
    } else {
        return 0;
    }
    // create map key
    struct key_t key = {};

    key.pid = curr_pid;
    key.tgid = tgid;

    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&key.name, sizeof(key.name));

    bpf_printk("user_stack_id:%d     user_stack_id:%d\n", key.user_stack_id, key.kernel_stack_id);
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

struct ksym *ksym_search(long key) {
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