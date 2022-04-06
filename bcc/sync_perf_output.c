#include <uapi/linux/ptrace.h>

struct data_t
{
    u32 pid;
    u64 delta;
    u64 time;
};
BPF_HASH(last);
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx)
{
    u64 ts, *tsp, delta, key = 0;
    struct data_t data = {};

    tsp = last.lookup(&key);
    if (tsp != 0)
    {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000)
        {
            // output if time is less than 1 second
            data.pid = bpf_get_current_pid_tgid();
            data.delta = delta / 1000000;
            data.time = bpf_ktime_get_ns();
            events.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
    }
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}