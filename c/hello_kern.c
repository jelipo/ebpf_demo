#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef char stringkey[64];

struct bpf_map_def SEC("maps") my_map = {
        .type = BPF_MAP_TYPE_HASH,
        .max_entries = 128,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .map_flags = BPF_F_NO_PREALLOC,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    //__type(key, stringkey);
    stringkey *key;
    __type(value, u64);
} execve_counter SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    int key = 1;
    int value = 1111;
    long a = bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";