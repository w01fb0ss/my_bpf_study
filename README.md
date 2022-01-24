# libbpf-rs + BPF CO-RE
bpf部分参考[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools)

### example
```bash
cd bashreadline/
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo libbpf build
cargo libbpf gen
cargo build
sudo ./target/debug/bashreadline
```
