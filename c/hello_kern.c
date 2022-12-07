#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef char stringkey[64];

struct bpf_map_def SEC("maps") my_map = {
        .type = BPF_MAP_TYPE_HASH,
        .max_entries = 128,
        .key_size = 64,
        .value_size = 8,
        .map_flags = BPF_F_NO_PREALLOC,
};

//struct {
//    __uint(type, BPF_MAP_TYPE_HASH);
//    __uint(max_entries, 128);
//    //__type(key, stringkey);
//    stringkey *key;
//    __type(value, u64);
//} execve_counter SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    char key[64] = "key";
    int *value = NULL;
    value = bpf_map_lookup_elem(&my_map, &key);
    if (value != NULL) {
        *value += 1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";