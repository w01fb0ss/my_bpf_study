#![no_std]
#![no_main]
use cty::*;
use probes::openmonitor::*;
use redbpf_probes::kprobe::prelude::*;

// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
// use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;
// use redbpf_probes::tc::prelude::*;
// use redbpf_probes::uprobe::prelude::*;
// use redbpf_probes::sockmap::prelude::*;
// use redbpf_probes::bpf_iter::prelude::*;

// Use the types you're going to share with userspace, eg:
// use probes::openmonitor::SomeEvent;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);

#[kprobe]
fn do_sys_open(regs: Registers) {
    let mut path = OpenPath::default();
    unsafe {
        let filename = regs.parm2() as *const u8;
        if bpf_probe_read_user_str(
            path.filename.as_mut_ptr() as *mut _,
            path.filename.len() as u32,
            filename as *const _,
        ) <= 0
        {
            bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
            return;
        }
        OPEN_PATHS.insert(regs.ctx, &path);
    }
}

// The maps and probe functions go here, eg:
//
// #[map]
// static mut syscall_events: PerfMap<SomeEvent> = PerfMap::with_max_entries(1024);
//
// #[kprobe("__x64_sys_open")]
// fn syscall_enter(regs: Registers) {
//   let pid_tgid = bpf_get_current_pid_tgid();
//   ...
//
//   let event = SomeEvent {
//     pid: pid_tgid >> 32,
//     ...
//   };
//   unsafe { syscall_events.insert(regs.ctx, &event) };
// }
