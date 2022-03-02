#![no_std]
#![no_main]
mod vmlinux;

use aya_bpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_get_current_uid_gid, bpf_probe_read, bpf_probe_read_user, bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use execsnoop_common::Event;
// use memoffset::offset_of;
use vmlinux::task_struct;

const ARGSIZE: usize = 128;
const TOTAL_MAX_ARGS: usize = 20;

#[map]
static mut EXECS: HashMap<u64, Event> = HashMap::with_max_entries(10240, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::<Event>::with_max_entries(10240, 0);

#[tracepoint(name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let uid = bpf_get_current_uid_gid();
    let pid = bpf_get_current_pid_tgid();
    let tgid = bpf_get_current_pid_tgid() >> 32;

    let mut event = match EXECS.get_mut(&pid) {
        Some(event) => *event,
        None => Event {
            comm: [0i8; 16],
            pid: 0,
            tgid: 0,
            ppid: 0,
            uid: 0,
            retval: 0,
            args_count: 0,
            args_size: 0,
            args: [0u8; ARGSIZE * TOTAL_MAX_ARGS],
        },
    };

    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    let task: *const task_struct = bpf_get_current_task_btf() as *const task_struct;
    let real_parent: *const task_struct = bpf_probe_read(&(*task).real_parent)?;
    let real_parent_tgid = bpf_probe_read(&(*real_parent).tgid as *const i32 as *const u64)?;
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
        let e_ptr = bpf_probe_read_user(argv.offset(i as isize))?;
        let count = bpf_probe_read_user_str(e_ptr, &mut e_)?;
        if count > ARGSIZE {
            return Ok(0);
        }
        event.args_count += 1;
        event.args_size += count as u32;
    }
    bpf_probe_read_user(argv.offset(TOTAL_MAX_ARGS as isize))?;
    event.args_count += 1;
    EXECS.insert(&pid, &event, 0)?;
    Ok(0)
}

#[tracepoint(name = "sys_exit_execve")]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_execve(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

// TODO: ERROR
// program sys_exit_execve function sys_exit_execve
// Error: the BPF_PROG_LOAD syscall failed. Verifier output: func#0 @0
// func#1 @148
// func#2 @156
// 0: R1=ctx(id=0,off=0,imm=0) R10=fp0
// 0: (bf) r6 = r1
// 1: R1=ctx(id=0,off=0,imm=0) R6_w=ctx(id=0,off=0,imm=0) R10=fp0
// 1: (85) call bpf_get_current_uid_gid#15
// 2: R0_w=invP(id=0) R6_w=ctx(id=0,off=0,imm=0) R10=fp0
// 2: (bf) r7 = r0
// 3: R0_w=invP(id=1) R6_w=ctx(id=0,off=0,imm=0) R7_w=invP(id=1) R10=fp0
// 3: (85) call bpf_get_current_pid_tgid#14
// 4: R0_w=invP(id=0) R6_w=ctx(id=0,off=0,imm=0) R7_w=invP(id=1) R10=fp0
// 4: (7b) *(u64 *)(r10 -2672) = r0
// invalid write to stack R10 off=-2672 size=8
// verification time 62 usec
// stack depth 0+0+0
// processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
unsafe fn try_sys_exit_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let id = bpf_get_current_pid_tgid();
    let pid = id as u64;
    let mut event = match EXECS.get_mut(&pid) {
        Some(event) => *event,
        None => return Ok(0),
    };
    let ret = ctx.read_at::<*const i32>(16)?;
    event.retval = *ret;
    event.comm = bpf_get_current_comm()?;
    EVENTS.output(&ctx, &event, 0);
    EXECS.remove(&pid)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
