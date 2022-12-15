#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/common.h"
//#include "vmlinux.h"

typedef char stringkey[64];

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8 line[80];
};

//struct bpf_map_def SEC("maps") event_demo = {
//        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//        .max_entries = 128,
//        .key_size = sizeof(int),
//        .value_size = 4,
//        .map_flags = BPF_F_NO_PREALLOC,
//};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct data_t {
    u32 pid;
    char program_name[16];
};

SEC("kprobe/sys_exec")
int bpf_capture_exec(struct pt_regs *ctx) {
    bpf_printk("hello world");
    return 0;
}