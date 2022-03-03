#![no_std]

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Event {
    pub comm: [i8; 16],
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub retval: i32,
    pub args_count: i32,
    pub args_size: u32,
    pub args: [u8; 32],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
