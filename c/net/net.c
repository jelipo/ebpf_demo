#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


char __license[] SEC("license") = "Dual MIT/GPL";


struct bpf_map_def SEC("maps") my_event = {
        .type = BPF_MAP_TYPE_RINGBUF,
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
int bpf_prog(struct trace_event_raw_inet_sock_set_state *ctx) {
    struct pro_data data;
    ctx->saddr
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), (void *) &sk->sk_ack_backlog);
    bpf_perf_event_output(ctx, &my_event, 0, &data, sizeof(data));
    return 0;
}
