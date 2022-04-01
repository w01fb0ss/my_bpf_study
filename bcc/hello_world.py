#! /usr/bin/env python3
from bcc import BPF

BPF(
    text='''int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!"); return 0; }''').trace_print()
