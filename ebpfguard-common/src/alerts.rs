pub trait Alert {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BprmCheckSecurity {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
}

impl BprmCheckSecurity {
    pub fn new(pid: u32, binprm_inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
        }
    }
}

impl Alert for BprmCheckSecurity {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileOpen {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
    pub inode: u64,
}

impl FileOpen {
    pub fn new(pid: u32, binprm_inode: u64, inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
            inode,
        }
    }
}

impl Alert for FileOpen {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TaskFixSetuid {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
    pub old_uid: u32,
    pub old_gid: u32,
    pub new_uid: u32,
    pub new_gid: u32,
}

impl TaskFixSetuid {
    pub fn new(
        pid: u32,
        binprm_inode: u64,
        old_uid: u32,
        old_gid: u32,
        new_uid: u32,
        new_gid: u32,
    ) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
            old_uid,
            old_gid,
            new_uid,
            new_gid,
        }
    }
}

impl Alert for TaskFixSetuid {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SbMount {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
}

impl SbMount {
    pub fn new(pid: u32, binprm_inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
        }
    }
}

impl Alert for SbMount {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SbRemount {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
}

impl SbRemount {
    pub fn new(pid: u32, binprm_inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
        }
    }
}

impl Alert for SbRemount {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SbUmount {
    pub pid: u32,
    _padding: u32,
    pub binprm_inode: u64,
}

impl SbUmount {
    pub fn new(pid: u32, binprm_inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
        }
    }
}

impl Alert for SbUmount {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketBind {
    pub pid: u32,
    _padding1: u32,
    pub binprm_inode: u64,
    pub port: u16,
    _padding2: [u16; 3],
}

impl SocketBind {
    pub fn new(pid: u32, binprm_inode: u64, port: u16) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            port,
            _padding2: [0; 3],
        }
    }
}

impl Alert for SocketBind {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SocketConnect {
    pub pid: u32,
    _padding1: u32,
    pub binprm_inode: u64,
    pub addr_v4: u32,
    _padding2: u32,
    pub addr_v6: [u8; 16],
    pub port: u16,
}

impl SocketConnect {
    pub fn new_ipv4(pid: u32, binprm_inode: u64, addr_v4: u32, port: u16) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr_v4,
            _padding2: 0,
            addr_v6: [0; 16],
            port,
        }
    }

    pub fn new_ipv6(pid: u32, binprm_inode: u64, addr_v6: [u8; 16], port: u16) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr_v4: 0,
            _padding2: 0,
            addr_v6,
            port,
        }
    }
}

impl Alert for SocketConnect {}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    use aya::Pod;

    unsafe impl Pod for BprmCheckSecurity {}
    unsafe impl Pod for FileOpen {}
    unsafe impl Pod for SbMount {}
    unsafe impl Pod for SocketBind {}
    unsafe impl Pod for SocketConnect {}
    unsafe impl Pod for TaskFixSetuid {}
}
