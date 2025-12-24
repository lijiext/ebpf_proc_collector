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
gcc -O2 -g process.c -o process     -lbpf -lelf -lz
```

## 运行
```bash
sudo ./process
```