#![no_std]

pub const MAX_PATHS: usize = 8;
pub const MAX_IPV4_ADDRS: usize = 8;
pub const MAX_PORTS: usize = 8;

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
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct NetworkAlert {
    pub binprm_inode: u64,
    #[cfg_attr(feature = "user", serde(flatten))]
    pub tuple: NetTuple,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Paths {
    pub all: bool,
    pub len: usize,
    pub paths: [u64; MAX_PATHS],
    pub _padding: [u8; 7],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv4Addrs {
    pub all: bool,
    pub len: usize,
    pub addrs: [u32; MAX_IPV4_ADDRS],
    pub _padding: [u8; 7],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ports {
    pub all: bool,
    pub len: usize,
    pub ports: [u32; MAX_PORTS],
    pub _padding: [u8; 7],
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct NetTuple {
    pub dst_addr: u32,
    pub src_addr: u32,
    pub dst_port: u32,
    pub src_port: u32,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    use aya::Pod;

    unsafe impl Pod for FileOpenAlert {}
    unsafe impl Pod for SetuidAlert {}
    unsafe impl Pod for Paths {}
}
