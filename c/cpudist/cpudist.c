#include "../include/vmlinux.h"
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

#define ONCPU
typedef struct entry_key {
    u32 pid;
    u32 cpu;
} entry_key_t;

typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;

typedef struct ext_val {
    u64 total;
    u64 count;
} ext_val_t;

static inline void update_hist(u32 tgid, u32 pid, u32 cpu, u64 ts) {
    entry_key_t entry_key = {.pid = pid, .cpu = cpu};
    u64 *tsp = start.lookup(&entry_key);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
}

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    u32 cpu = bpf_get_smp_processor_id();

    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;

#ifdef ONCPU
    update_hist(prev_tgid, prev_pid, cpu, ts);
#else
    store_start(prev_tgid, prev_pid, cpu, ts);
#endif

    BAIL:
#ifdef ONCPU
    store_start(tgid, pid, cpu, ts);
#else
    update_hist(tgid, pid, cpu, ts);
#endif

    return 0;
}

