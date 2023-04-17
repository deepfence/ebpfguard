#![no_std]

pub const MAX_PATHS: usize = 8;

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct FileOpenAlert {
    pub pid: u64,
    pub binprm_inode: u64,
    pub inode: u64,
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct SetuidAlert {
    pub pid: u64,
    pub binprm_inode: u64,
    pub old_uid: u32,
    pub old_gid: u32,
    pub new_uid: u32,
    pub new_gid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Paths {
    pub all: bool,
    pub len: usize,
    pub paths: [u64; MAX_PATHS],
    pub _padding: [u8; 7],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    use aya::Pod;

    unsafe impl Pod for FileOpenAlert {}
    unsafe impl Pod for SetuidAlert {}
    unsafe impl Pod for Paths {}
}
