use cty::*;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ReadLineEvent {
    pub pid: u64,
    pub uid: u64,
    pub str: [u8; 80],
}
// This is where you should define the types shared by the kernel and user
// space, eg:
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct SomeEvent {
//     pub pid: u64,
//     ...
// }
