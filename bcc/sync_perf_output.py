#!/usr/bin/env python3
from bcc import BPF

b = BPF(src_file="sync_perf_output.c")
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="hello")

print("Tracing for quick sync's... Ctrl-C to end")

start = 0


def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)

    if start == 0:
        start = int(event.time)
    start_time = (int(event.time) - start) / 1000000

    print("[PID:%6s] At time %d ms: multiple syncs detected, last %s ms ago" % (
        event.pid, start_time, event.delta))


b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
