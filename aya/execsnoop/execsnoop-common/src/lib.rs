#![no_std]

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Event {
    pub comm: [i8; 16],
    pub pid: u64,
    pub tgid: u64,
    pub ppid: u64,
    pub uid: u64,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    pub args: [u8; 128 * 20],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
