#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef __u32 u32;
typedef char stringkey[64];

struct bpf_map_def SEC("maps") event = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .max_entries = 128,
        .key_size = sizeof(int),
        .value_size = 4,
        .map_flags = BPF_F_NO_PREALLOC,
};

struct data_t {
    u32 pid;
    char program_name[16];
};



//struct {
//    __uint(type, BPF_MAP_TYPE_HASH);
//    __uint(max_entries, 128);
//    //__type(key, stringkey);
//    stringkey *key;
//    __type(value, u64);
//} execve_counter SEC(".maps");


SEC("kprobe/sys_exec")
int bpf_capture_exec(struct pt_regs *ctx) {
    struct data_t data;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.program_name, sizeof(data.program_name));
    bpf_perf_event_output(ctx, &event, 0, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";