#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256

struct user_proc_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct user_proc_event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->pid  = pid_tgid >> 32;
    e->uid  = uid_gid & 0xffffffff;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->ts_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (ctx->filename)
        bpf_probe_read_str(e->filename, sizeof(e->filename), ctx->filename);
    else
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}
