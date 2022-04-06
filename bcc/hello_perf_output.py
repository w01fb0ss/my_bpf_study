#!/usr/bin/env python3
from bcc import BPF
from bcc.utils import printb

b = BPF(src_file="hello_perf_output.c")
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    data_t = b["events"].event(data)
    if start == 0:
        start = data_t.ts
    time_s = (float(data_t.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %s" % (time_s, data_t.comm, data_t.pid,
                                       b"Hello, perf_output!"))


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
