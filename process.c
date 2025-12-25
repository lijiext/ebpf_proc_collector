#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* 必须与 process.bpf.c 中的结构体完全一致 */
struct user_proc_event {
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    char comm[16];
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int signo)
{
    exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct user_proc_event *e = data;
    struct passwd *pw;

    pw = getpwuid(e->uid);

    printf("PID=%-6u PPID=%-6u USER=%-10s COMM=%s\n",
           e->pid,
           e->ppid,
           pw ? pw->pw_name : "unknown",
           e->comm);
}

static void handle_lost(void *ctx, int cpu, __u64 cnt)
{
    fprintf(stderr, "lost %llu events on CPU %d\n",
            (unsigned long long)cnt, cpu);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--btf /path/to/vmlinux.btf]\n", prog);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct perf_buffer *pb = NULL;
    struct bpf_object_open_opts opts = {};
    struct perf_buffer_opts pb_opts = {};
    int err;
    const char *btf_path = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--btf") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            btf_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 打开 BPF 对象 */
    opts.sz = sizeof(opts);
    if (btf_path)
        opts.btf_custom_path = btf_path;

    obj = bpf_object__open_file("process.bpf.o", &opts);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    /* 加载到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* attach 所有 program（Ubuntu 20.04 需要这样） */
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            fprintf(stderr, "failed to attach BPF program\n");
            goto cleanup;
        }
    }

    /* 找到 perf event map */
    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "failed to find events map\n");
        goto cleanup;
    }

    /* 创建 perf buffer */
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost;
    pb_opts.ctx = NULL;

    pb = perf_buffer__new(bpf_map__fd(map), 8, &pb_opts);
    if (!pb) {
        fprintf(stderr, "failed to create perf buffer\n");
        goto cleanup;
    }

    printf("开始监听进程 exec 事件（Ctrl+C 退出）\n");

    /* 主循环 */
    while (!exiting) {
        err = perf_buffer__poll(pb, 200);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "perf_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}
