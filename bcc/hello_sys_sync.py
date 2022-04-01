#!/usr/bin/env python3
from bcc import BPF

print("Tracing sys_sync()... Ctrl-C to end.")
BPF(text="""
int kprobe__sys_sync(void *ctx)
{
    bpf_trace_printk("sys_sync() called"); 
    return 0;
}
""").trace_print()
