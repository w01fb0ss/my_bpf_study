#![no_std]
#![no_main]
mod vmlinux;
use aya_log_ebpf::info;

use aya_bpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_get_current_uid_gid, bpf_probe_read, bpf_probe_read_str, bpf_probe_read_user,
        bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use execsnoop_common::Event;
// use memoffset::offset_of;
use vmlinux::task_struct;

const ARGSIZE: usize = 128;
const TOTAL_MAX_ARGS: isize = 20;

#[map]
static mut EXECS: HashMap<u32, Event> = HashMap::with_max_entries(10240, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(10240, 0);

#[tracepoint(name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> i64 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(ret) => ret as i64,
        Err(ret) => ret,
    }
}

unsafe fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let uid = bpf_get_current_uid_gid() as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let old_event = match EXECS.get(&pid) {
        Some(event) => event,
        None => &Event {
            comm: [0i8; 16],
            pid: 0,
            tgid: 0,
            ppid: 0,
            uid: 0,
            retval: 0,
            args_count: 0,
            args_size: 0,
            args: [0u8; 32],
        },
    };
    let mut event = *old_event;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    let task: *const task_struct = bpf_get_current_task_btf() as *const task_struct;
    let real_parent: *const task_struct = bpf_probe_read(&(*task).real_parent)?;
    let real_parent_tgid = bpf_probe_read(&(*real_parent).tgid as *const i32 as *const u32)?;
    event.ppid = real_parent_tgid;
    event.args_count = 0;
    event.args_size = 0;

    let argv = ctx.read_at::<*const *const u8>(24)?;
    let exe_ptr = bpf_probe_read_user(argv)?;
    let ret = bpf_probe_read_user_str(exe_ptr, &mut event.args)?;
    if ret <= ARGSIZE {
        event.args_size += ret as u32;
    } else {
        event.args[0] = b'\0';
        event.args_size += 1;
    }
    event.args_count += 1;
    // let user_ptr: *const c_int = 0 as _;
    // #pragma unroll
    for i in 1..=TOTAL_MAX_ARGS {
        let mut e_ = [0u8; 32];
        let e_ptr = bpf_probe_read_user(argv.offset(i))?;
        let count = bpf_probe_read_user_str(e_ptr, &mut e_)?;
        if count > ARGSIZE {
            return Ok(0);
        }
        event.args_count += 1;
        event.args_size += count as u32;
    }
    bpf_probe_read_user(argv.offset(TOTAL_MAX_ARGS))?;
    event.args_count += 1;
    EXECS.insert(&pid, &event, 0)?;
    Ok(0)
}

#[tracepoint(name = "sys_exit_execve")]
pub fn sys_exit_execve(ctx: TracePointContext) -> i64 {
    match unsafe { try_sys_exit_execve(ctx) } {
        Ok(ret) => ret as i64,
        Err(ret) => ret,
    }
}

unsafe fn try_sys_exit_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid = bpf_get_current_pid_tgid() as u32;
    // let pid = id as u64;
    let event = match EXECS.get(&pid) {
        Some(event) => event,
        None => return Ok(0),
    };
    let mut new_event = *event;
    new_event.retval = ctx.read_at(16)?;
    new_event.comm = bpf_get_current_comm()?;
    // info!(&ctx, "{}", new_event.pid);
    EVENTS.output(&ctx, &new_event, 0);
    EXECS.remove(&pid)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
