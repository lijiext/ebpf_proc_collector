#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>

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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct user_proc_event *e = data;
    struct passwd *pw;

    pw = getpwuid(e->uid);

    printf("PID=%-6u PPID=%-6u USER=%-10s COMM=%s\n",
           e->pid,
           e->ppid,
           pw ? pw->pw_name : "unknown",
           e->comm);

    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 打开 BPF 对象 */
    obj = bpf_object__open_file("process.bpf.o", NULL);
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

    /* 找到 ringbuf map */
    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "failed to find events map\n");
        goto cleanup;
    }

    /* 创建 ring buffer */
    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }

    printf("开始监听进程 exec 事件（Ctrl+C 退出）\n");

    /* 主循环 */
    while (!exiting) {
        err = ring_buffer__poll(rb, 200);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}

