#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(u64),
        .max_entries = 1,
};

SEC("kprobe/finish_task_switch.isra.0")
int kprobe_execve(struct pt_regs *ctx) {
    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    u32 pid = BPF_CORE_READ(prev, pid);
    u32 tgid = BPF_CORE_READ(prev, tgid);
    char comm[16];
    bpf_core_read(&comm, sizeof(comm), &prev->comm);

    if (pid == 1040 || tgid == 1040) {
        bpf_printk("pid:%d  tgid:%d  comm:%s", pid, tgid, comm);
    }
//    u32 key = 0;
//    u64 initval = 1, *valp;
//
//    valp = bpf_map_lookup_elem(&kprobe_map, &key);
//    if (!valp) {
//        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
//        return 0;
//    }
//    __sync_fetch_and_add(valp, 1);

    return 0;
}