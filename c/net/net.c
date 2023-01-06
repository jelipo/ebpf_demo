#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct trace_entry {
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_inet_sock_set_state {
    struct trace_entry ent;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};


struct bpf_map_def SEC("maps") my_event = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY
};

struct pro_data {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
};

struct pro_data *unused __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int bpf_prog(struct pt_regs *ctx, struct trace_event_raw_inet_sock_set_state *state) {
    struct pro_data data;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), (void *) state->daddr);
    bpf_perf_event_output(ctx, &my_event, 0, &data, sizeof(data));
    return 0;
}
