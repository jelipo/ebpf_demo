#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 tgid;
    u32 pid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u8 comm[16];
};

// 用于暂存到map的struck
struct temp_key_t {
    u32 tgid;
    u32 pid;
};

struct temp_value_t {
    u64 start_time;
};

int main() {}

// Force emitting struct event into the ELF.
const struct key_t *unused __attribute__((unused));

struct bpf_map_def SEC("maps") listen_pids_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(u32),
        .value_size=sizeof(int32),
        .max_entries = 1024,
};

struct bpf_map_def SEC("maps") temp_pid_status = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(struct temp_key_t),
        .value_size=sizeof(struct temp_value_t),
        .max_entries = 1024,
};

#define PERF_MAX_STACK_DEPTH        127

struct bpf_map_def SEC("maps") stack_traces = {
        .type = BPF_MAP_TYPE_STACK_TRACE,
        .key_size = sizeof(u32),
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
        .max_entries = 10000,
};

struct bpf_map_def SEC("maps") pid_stack_counter = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size=sizeof(struct key_t),
        .value_size=sizeof(u64),
        .max_entries = 1024 * 10,
};

void increment_ns(void *ctx, u32 pid, u32 tgid, u64 usage_us) {
    struct key_t key = {};
    key.tgid = tgid;
    key.pid = pid;
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 *total_usage_us = bpf_map_lookup_elem(&pid_stack_counter, &key);
    u64 result = 0;
    if (total_usage_us == NULL) {
        result = usage_us;
    } else {
        result = usage_us + *total_usage_us;
    }
    bpf_map_update_elem(&pid_stack_counter, &key, &result, BPF_ANY);
}

// 尝试记录offcputime开始时间
inline void try_record_start(u32 prev_pid, u32 prev_tgid) {
    if (prev_tgid == 0) {
        return;
    }
    if (bpf_map_lookup_elem(&listen_pids_map, &prev_tgid) == NULL) {
        return;
    }
    struct temp_value_t value = {};
    value.start_time = bpf_ktime_get_ns();
    struct temp_key_t key = {
            .pid = prev_pid,
            .tgid = prev_tgid
    };
    bpf_map_update_elem(&temp_pid_status, &key, &value, BPF_ANY);
}

// 尝试记录offcputime结束并计算时间
inline void try_record_end(void *ctx, u32 next_pid, u32 next_tgid) {
    if (next_tgid == 0 || next_pid == 0) {
        return;
    }
    if (bpf_map_lookup_elem(&listen_pids_map, &next_tgid) == NULL) {
        return;
    }
    struct temp_key_t key = {
            .pid = next_pid,
            .tgid = next_tgid
    };
    struct temp_value_t *value = NULL;
    value = bpf_map_lookup_elem(&temp_pid_status, &key);
    if (value == NULL) {
        // 找不到直接return
        return;
    }
    u64 end_time = bpf_ktime_get_ns();
    // 计算出使用的时间，微秒
    u64 usage_us = (end_time - value->start_time) / 1000;
    increment_ns(ctx, next_pid, next_tgid, usage_us);
}

SEC("kprobe/finish_task_switch.isra.0")
int sched_switch(struct pt_regs *ctx) {
    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    u32 prev_pid = BPF_CORE_READ(prev, pid);
    u32 prev_tgid = BPF_CORE_READ(prev, tgid);

    u32 next_tgid = bpf_get_current_pid_tgid() >> 32;
    u32 next_pid = bpf_get_current_pid_tgid();


    try_record_start(prev_pid, prev_tgid);
    try_record_end(ctx, next_pid, next_tgid);
    return 0;
}