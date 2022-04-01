#!/usr/bin/env python
from bcc import BPF

b = BPF(src_file="sync_count.c")
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    (task, pid, cpu, flags, ts, count) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    # print(ms)
    # print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    print("sync count: %s" % count)
