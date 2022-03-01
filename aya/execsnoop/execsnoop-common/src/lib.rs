#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub comm: [u8; 16],
    pub pid: i32,
    pub tgid: i32,
    pub ppid: i32,
    pub uid: i32,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    pub args: [u8; 128 * 60],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
