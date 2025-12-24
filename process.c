#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif

#define NANOSEC_PER_SEC 1000000000ULL

#define DEFAULT_TEXTFILE_PATH \
    "/var/lib/node_exporter/textfile_collector/ebpf_process.prom"
#define DEFAULT_WINDOW_SECONDS 300ULL
#define DEFAULT_FLUSH_SECONDS 30ULL

#define HASH_BUCKETS (1u << 15)
#define FNV1A_OFFSET 2166136261u
#define FNV1A_PRIME 16777619u

#define METRIC_NAME "ebpf_user_process_execs"

struct user_proc_event {
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned long long ts_ns;
    char comm[16];
    char filename[256];
};

struct proc_key {
    unsigned int uid;
    char comm[16];
    char filename[256];
};

struct proc_entry {
    struct proc_entry *next;
    struct proc_key key;
    unsigned long long latest_ts_ns;
};

static const char *textfile_path = DEFAULT_TEXTFILE_PATH;
static unsigned long long window_ns = DEFAULT_WINDOW_SECONDS * NANOSEC_PER_SEC;
static unsigned long long flush_interval_ns = DEFAULT_FLUSH_SECONDS * NANOSEC_PER_SEC;

static struct proc_entry *hash_table[HASH_BUCKETS];
static size_t entry_count;

static volatile sig_atomic_t exiting;

static unsigned long long last_flush_ns;

static char hostname_buf[HOST_NAME_MAX + 1] = "unknown";

static char *pw_buf;
static size_t pw_buf_len;

static inline unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (unsigned long long)ts.tv_sec * NANOSEC_PER_SEC + ts.tv_nsec;
}

static void sig_handler(int signo)
{
    (void)signo;
    exiting = 1;
}

static uint32_t fnv1a_hash(uint32_t hash, const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (!c)
            break;
        hash ^= c;
        hash *= FNV1A_PRIME;
    }
    return hash;
}

static inline uint32_t bucket_index(const struct proc_key *key)
{
    uint32_t hash = FNV1A_OFFSET;

    hash ^= key->uid;
    hash *= FNV1A_PRIME;
    hash = fnv1a_hash(hash, key->comm, sizeof(key->comm));
    hash = fnv1a_hash(hash, key->filename, sizeof(key->filename));

    return hash & (HASH_BUCKETS - 1);
}

static void fill_key_from_event(struct proc_key *key, const struct user_proc_event *e)
{
    key->uid = e->uid;
    strncpy(key->comm, e->comm, sizeof(key->comm));
    key->comm[sizeof(key->comm) - 1] = '\0';
    strncpy(key->filename, e->filename, sizeof(key->filename));
    key->filename[sizeof(key->filename) - 1] = '\0';
}

static bool keys_equal(const struct proc_key *a, const struct user_proc_event *b)
{
    return a->uid == b->uid &&
           strncmp(a->comm, b->comm, sizeof(a->comm)) == 0 &&
           strncmp(a->filename, b->filename, sizeof(a->filename)) == 0;
}

static void expire_stale_entries(unsigned long long cutoff_ns)
{
    for (size_t i = 0; i < HASH_BUCKETS; i++) {
        struct proc_entry **pp = &hash_table[i];
        while (*pp) {
            if ((*pp)->latest_ts_ns < cutoff_ns) {
                struct proc_entry *old = *pp;
                *pp = old->next;
                free(old);
                if (entry_count)
                    entry_count--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}

static int upsert_event(const struct user_proc_event *e)
{
    struct proc_key key;
    fill_key_from_event(&key, e);
    uint32_t bucket = bucket_index(&key);

    struct proc_entry *entry = hash_table[bucket];
    while (entry) {
        if (keys_equal(&entry->key, e)) {
            entry->latest_ts_ns = e->ts_ns;
            return 0;
        }
        entry = entry->next;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -ENOMEM;

    entry->key = key;
    entry->latest_ts_ns = e->ts_ns;
    entry->next = hash_table[bucket];
    hash_table[bucket] = entry;
    entry_count++;

    return 0;
}

static void destroy_entries(void)
{
    for (size_t i = 0; i < HASH_BUCKETS; i++) {
        struct proc_entry *entry = hash_table[i];
        while (entry) {
            struct proc_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        hash_table[i] = NULL;
    }
    entry_count = 0;
}

static const char *username_from_uid(uid_t uid, char *buf, size_t buf_len)
{
    if (!pw_buf_len) {
        long sz = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (sz < 0)
            sz = 16384;
        pw_buf_len = (size_t)sz;
        pw_buf = malloc(pw_buf_len);
    }

    if (pw_buf) {
        struct passwd pwd;
        struct passwd *result = NULL;
        if (getpwuid_r(uid, &pwd, pw_buf, pw_buf_len, &result) == 0 && result) {
            strncpy(buf, pwd.pw_name, buf_len);
            buf[buf_len - 1] = '\0';
            return buf;
        }
    }

    snprintf(buf, buf_len, "%u", uid);
    return buf;
}

static void escape_label(FILE *f, const char *value)
{
    for (const char *p = value; *p; p++) {
        if (*p == '\\' || *p == '"') {
            fputc('\\', f);
            fputc(*p, f);
        } else if (*p == '\n' || *p == '\r') {
            fputc('_', f);
        } else {
            fputc(*p, f);
        }
    }
}

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof(tmp) - 1);

    if (len == 0)
        return 0;

    memcpy(tmp, path, len);
    tmp[len] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }

    if (mkdir(tmp, 0755) && errno != EEXIST)
        return -1;

    return 0;
}

static int ensure_textfile_dir(const char *path)
{
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path)
        return 0;

    size_t len = (size_t)(slash - path);
    if (len >= PATH_MAX)
        return -1;

    char dir[PATH_MAX];
    memcpy(dir, path, len);
    dir[len] = '\0';
    return mkdir_p(dir);
}

static void write_metrics_file(void)
{
    if (!textfile_path || !*textfile_path)
        return;

    if (ensure_textfile_dir(textfile_path) != 0) {
        fprintf(stderr, "failed to create directory for %s: %s\n",
                textfile_path, strerror(errno));
        return;
    }

    unsigned long long cutoff = now_ns() - window_ns;
    expire_stale_entries(cutoff);

    char tmp_path[PATH_MAX];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", textfile_path, getpid()) >= (int)sizeof(tmp_path)) {
        fprintf(stderr, "textfile path too long\n");
        return;
    }

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        fprintf(stderr, "failed to open %s: %s\n", tmp_path, strerror(errno));
        return;
    }

    fprintf(f, "# HELP %s Unique process executions per user over the sliding window\n", METRIC_NAME);
    fprintf(f, "# TYPE %s gauge\n", METRIC_NAME);

    for (size_t i = 0; i < HASH_BUCKETS; i++) {
        for (struct proc_entry *entry = hash_table[i]; entry; entry = entry->next) {
            if (entry->latest_ts_ns < cutoff)
                continue;

            const char *exec_path = entry->key.filename[0] ? entry->key.filename : "unknown";
            char user_buf[64];
            const char *user = username_from_uid(entry->key.uid, user_buf, sizeof(user_buf));

            fprintf(f, "%s{hostname=\"", METRIC_NAME);
            escape_label(f, hostname_buf);
            fprintf(f, "\",user=\"");
            escape_label(f, user);
            fprintf(f, "\",command=\"");
            escape_label(f, entry->key.comm);
            fprintf(f, "\",exec=\"");
            escape_label(f, exec_path);
            fprintf(f, "\"} 1\n");
        }
    }

    fclose(f);

    if (rename(tmp_path, textfile_path) != 0) {
        fprintf(stderr, "failed to rename %s to %s: %s\n",
                tmp_path, textfile_path, strerror(errno));
        unlink(tmp_path);
    }
}

static void maybe_flush_metrics(void)
{
    unsigned long long now = now_ns();
    if (now - last_flush_ns >= flush_interval_ns) {
        write_metrics_file();
        last_flush_ns = now;
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;

    const struct user_proc_event *e = data;

    if (upsert_event(e) != 0)
        fprintf(stderr, "failed to record event for uid %u\n", e->uid);

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-o textfile_path] [-w window_seconds] [-f flush_seconds]\n",
            prog);
}

static void init_hostname(void)
{
    if (gethostname(hostname_buf, sizeof(hostname_buf)) != 0)
        strncpy(hostname_buf, "unknown", sizeof(hostname_buf));
    hostname_buf[sizeof(hostname_buf) - 1] = '\0';
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct ring_buffer *rb = NULL;
    struct bpf_link **links = NULL;
    size_t link_count = 0;
    int err = 0;
    int opt;

    while ((opt = getopt(argc, argv, "o:w:f:h")) != -1) {
        switch (opt) {
        case 'o':
            textfile_path = optarg;
            break;
        case 'w': {
            unsigned long long seconds = strtoull(optarg, NULL, 10);
            if (seconds > 0)
                window_ns = seconds * NANOSEC_PER_SEC;
            break;
        }
        case 'f': {
            unsigned long long seconds = strtoull(optarg, NULL, 10);
            if (seconds > 0)
                flush_interval_ns = seconds * NANOSEC_PER_SEC;
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
            return 1;
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    init_hostname();
    last_flush_ns = now_ns();

    obj = bpf_object__open_file("process.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        err = 1;
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        err = libbpf_get_error(link);
        if (err) {
            fprintf(stderr, "failed to attach BPF program: %d\n", err);
            link = NULL;
            goto cleanup;
        }

        struct bpf_link **tmp = realloc(links, (link_count + 1) * sizeof(*links));
        if (!tmp) {
            fprintf(stderr, "failed to allocate link array\n");
            err = -ENOMEM;
            bpf_link__destroy(link);
            goto cleanup;
        }

        links = tmp;
        links[link_count++] = link;
    }

    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "failed to find events map\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Collecting exec events (window %llu s, flush interval %llu s) -> %s\n",
           window_ns / NANOSEC_PER_SEC,
           flush_interval_ns / NANOSEC_PER_SEC,
           textfile_path);

    while (!exiting) {
        err = ring_buffer__poll(rb, 200);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
        maybe_flush_metrics();
    }

    write_metrics_file();

cleanup:
    if (rb)
        ring_buffer__free(rb);

    for (size_t i = 0; i < link_count; i++)
        bpf_link__destroy(links[i]);
    free(links);

    if (obj)
        bpf_object__close(obj);

    if (pw_buf)
        free(pw_buf);

    destroy_entries();

    return err ? 1 : 0;
}
