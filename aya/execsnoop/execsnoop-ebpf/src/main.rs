#![no_std]
#![no_main]
mod vmlinux;
use aya_bpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read,
        bpf_probe_read_kernel_buf,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    BpfContext,
};
use execsnoop_common::Event;
use memoffset::offset_of;
use vmlinux::task_struct;

const ARGSIZE: u32 = 128;

#[map]
static mut EXECS: HashMap<i32, Event> = HashMap::with_max_entries(10240, 0);

#[inline(always)]
fn set_execs(pid: i32, event: &Event) {
    let _ = unsafe { EXECS.insert(&pid, event, 0) };
}

#[inline(always)]
fn get_execs(pid: i32) -> Event {
    match unsafe { EXECS.get(&pid) } {
        Some(event) => *event,
        None => Event {
            comm: [0u8; 16],
            pid: 0,
            tgid: 0,
            ppid: 0,
            uid: 0,
            retval: 0,
            args_count: 0,
            args_size: 0,
            args: [0u8; 128 * 60],
        },
    }
}

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(10240, 0);

#[tracepoint(name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
    let uid = bpf_get_current_uid_gid() as i32;
    let pid = bpf_get_current_pid_tgid() as i32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let mut event = get_execs(pid);
    if event.pid == 0 {
        return Ok(0);
    }
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    let real_parent = bpf_probe_read(
        ctx.as_ptr()
            .offset(offset_of!(task_struct, real_parent) as isize) as *const task_struct,
    )
    .map_err(|_| 0u32)?;
    event.ppid = real_parent.tgid;
    event.args_count = 0;
    event.args_size = 0;
    // TODO: todo
    Ok(0)
}

#[tracepoint(name = "sys_exit_execve")]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sys_exit_execve(_ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
