#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";


struct key_t {
    u32 pid;
    u64 user_stack_id;
    u64 kernel_stack_id;
};

// 用于暂存到map的struck
struct temp_key_t {
    u32 pid;
};

struct temp_value_t {
    u32 user_stack_id;
    u32 kernel_stack_id;
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

void start(u32 pid, struct trace_event_raw_sched_switch *ctx) {
    struct temp_value_t value = {};
    value.start_time = bpf_ktime_get_ns();
    value.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    value.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    struct temp_key_t key = {.pid = pid};
    bpf_map_update_elem(&temp_pid_status, &key, &value, BPF_ANY);
}

void increment_ns(u32 pid, struct temp_value_t *start_value, u64 usage_us) {
//    struct key_t key = {
//            .pid = pid,
//            .user_stack_id = start_value->user_stack_id,
//            .kernel_stack_id = start_value->kernel_stack_id,
//    };

    struct key_t key = {};
    key.pid = pid;
    key.user_stack_id = start_value->user_stack_id;
    key.kernel_stack_id = start_value->kernel_stack_id;


    u64 *total_usage_us = bpf_map_lookup_elem(&pid_stack_counter, &key);
    u64 result = 0;
    if (total_usage_us == NULL) {
        result = usage_us;
    } else {
        result = usage_us + *total_usage_us;
    }
    bpf_map_update_elem(&pid_stack_counter, &key, &result, BPF_ANY);
}

void end(u32 pid, struct trace_event_raw_sched_switch *ctx) {
    struct temp_key_t key = {.pid = pid};
    struct temp_value_t *value = NULL;
    value = bpf_map_lookup_elem(&temp_pid_status, &key);
    if (value == NULL) {
        // 找不到直接return
        return;
    }
    u64 end_time = bpf_ktime_get_ns();
    // 计算出使用的时间，微秒
    u64 usage_us = (end_time - value->start_time) / 1000;
    increment_ns(pid, value, usage_us);
}

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    if (prev_pid == 0) {
        // 恢复，查找之前保存的信息，并发送到用户空间
        if (bpf_map_lookup_elem(&listen_pids_map, &next_pid) == NULL) {
            return 0;
        }
        end(next_pid, ctx);
    } else if (next_pid == 0) {
        // 调度出,记录开始的时间戳和其他信息
        if (bpf_map_lookup_elem(&listen_pids_map, &prev_pid) == NULL) {
            return 0;
        }
        start(prev_pid, ctx);
    } else {
        if (bpf_map_lookup_elem(&listen_pids_map, &next_pid) != NULL) {
            end(next_pid, ctx);
        } else if (bpf_map_lookup_elem(&listen_pids_map, &prev_pid) != NULL) {
            start(prev_pid, ctx);
        }
        return 0;
    }
    return 0;
}