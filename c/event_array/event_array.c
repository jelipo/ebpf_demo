#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") my_event = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY
};

struct pro_data {
    u32 pid;
    u8 program_name[16];
};

struct pro_data *unused __attribute__((unused));

SEC("tp/syscalls/sys_enter_execve")
int bpf_prog(struct pt_regs *ctx) {
    bpf_printk("hello world");
    struct pro_data data;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.program_name, sizeof(data.program_name));
    bpf_perf_event_output(ctx, &my_event, 0, &data, sizeof(data));
    return 0;
}
