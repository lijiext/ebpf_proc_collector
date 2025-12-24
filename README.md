# eBPF 进程采集器

## 环境准备
```bash
sudo apt install -y \
  linux-tools-common \
  linux-tools-$(uname -r) \
   clang \
   llvm \
   libelf-dev \
   libbpf-dev \
   fuse3
```

## 编译
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c process.bpf.c -o process.bpf.o
gcc -O2 -g process.c -o process -lbpf -lelf -lz
```

## 参数
```text
-o <path>  node-exporter textfile 输出路径，默认 /var/lib/node_exporter/textfile_collector/ebpf_process.prom
-w <sec>   统计窗口大小，单位秒，默认 300 秒（5 分钟）
-f <sec>   刷新 textfile 的时间间隔，单位秒，默认 30 秒
```

## 运行
Collector 会持续消费 BPF ring buffer 中的 exec 事件，并按 `hostname/user/command/exec` 维度在指定的时间窗口内去重，写到 node-exporter textfile。

1. 确保 node-exporter 启用了 `textfile` collector，并且 `process` 程序有写入路径的权限：
   ```bash
   sudo mkdir -p /var/lib/node_exporter/textfile_collector
   sudo chown root:root /var/lib/node_exporter/textfile_collector
   ```
2. 运行 collector：
   ```bash
   sudo ./process -o /var/lib/node_exporter/textfile_collector/ebpf_process.prom
   ```
3. node-exporter 的 `textfile` collector 将在下一次 scrape 时暴露如下指标：
   ```
   ebpf_user_process_execs{hostname="hostA",user="root",command="sshd",exec="/usr/sbin/sshd"} 1
   ```

被动场景下（没有新 exec 事件）也会按照 `-f` 间隔刷新 textfile，保证指标按窗口滑动；程序退出时会做最后一次刷新。
