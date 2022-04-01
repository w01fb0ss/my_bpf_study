#!/usr/bin/env python3
from bcc import BPF

prog = """
int hello(void *ctx)
{
    bpf_trace_printk("sys_sync() called"); 
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="hello")
print("Tracing sys_sync()... Ctrl-C to end.")
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue

    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
