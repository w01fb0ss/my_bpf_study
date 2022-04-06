#![no_std]
#![no_main]
use cty::*;
use probes::readline::ReadLineEvent;
use redbpf_probes::uprobe::prelude::*;

// use one of the preludes
// use redbpf_probes::kprobe::prelude::*;
// use redbpf_probes::xdp::prelude::*;
// use redbpf_probes::socket_filter::prelude::*;
// use redbpf_probes::tc::prelude::*;
// use redbpf_probes::uprobe::prelude::*;
// use redbpf_probes::sockmap::prelude::*;
// use redbpf_probes::bpf_iter::prelude::*;

// Use the types you're going to share with userspace, eg:
// use probes::readline::SomeEvent;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut ReadLines: PerfMap<ReadLineEvent> = PerfMap::with_max_entries(1024);

#[uretprobe]
fn readline(regs: Registers) {
    let event = ReadLineEvent {
        pid: bpf_get_current_pid_tgid() >> 32,
        uid: bpf_get_current_uid_gid() >> 32,
        str: unsafe { bpf_probe_read(regs.rc() as *const [u8; 80]).ok().unwrap() },
    };

    unsafe {
        ReadLines.insert(regs.ctx, &event);
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
