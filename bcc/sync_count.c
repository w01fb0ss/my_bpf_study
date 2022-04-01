#include <uapi/linux/ptrace.h>

BPF_HASH(last);
BPF_HASH(count);

int do_trace(struct pt_regs *ctx)
{
    u64 ts, *tsp, *oc, nc, delta, key = 0, ckey = 1;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL)
    {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000)
        {
            // output if time is less than 1 second
            bpf_trace_printk("%d", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);

    oc = last.lookup(&ckey);
    if (oc != 0)
    {
        nc = (*oc) + 1;
        last.delete(&ckey); // required due to a bug in kernel: https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02
        last.update(&ckey, &nc);
        bpf_trace_printk("%d", nc);
    }
    else
    {
        nc = 1;
        last.update(&ckey, &nc);
        bpf_trace_printk("%d", nc);
    }
    return 0;
}