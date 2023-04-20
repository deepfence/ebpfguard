#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "user")]
use serde::Serialize;

pub const MAX_PATHS: usize = 1;
pub const MAX_PORTS: usize = 1;
pub const MAX_IPV4ADDRS: usize = 1;
pub const MAX_IPV6ADDRS: usize = 1;

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct AlertFileOpen {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding: u32,
    pub binprm_inode: u64,
    pub inode: u64,
}

impl AlertFileOpen {
    pub fn new(pid: u32, binprm_inode: u64, inode: u64) -> Self {
        Self {
            pid,
            _padding: 0,
            binprm_inode,
            inode,
        }
    }
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct AlertSetuid {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding: u32,
    pub binprm_inode: u64,
    pub old_uid: u32,
    pub old_gid: u32,
    pub new_uid: u32,
    pub new_gid: u32,
}

impl AlertSetuid {
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

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct AlertSocketBind {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding1: u32,
    pub binprm_inode: u64,
    pub port: u16,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding2: [u16; 3],
}

impl AlertSocketBind {
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

#[cfg(feature = "user")]
fn serialize_ipv4<S>(addr: &u32, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    Ipv4Addr::from(*addr).serialize(s)
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct AlertSocketConnectV4 {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding1: u32,
    pub binprm_inode: u64,
    #[cfg_attr(feature = "user", serde(serialize_with = "serialize_ipv4"))]
    pub addr: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding2: u32,
}

impl AlertSocketConnectV4 {
    pub fn new(pid: u32, binprm_inode: u64, addr: u32) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr,
            _padding2: 0,
        }
    }
}

#[cfg(feature = "user")]
fn serialize_ipv6<S>(addr: &[u8; 16], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    Ipv6Addr::from(addr.to_owned()).serialize(s)
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone)]
pub struct AlertSocketConnectV6 {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding1: u32,
    pub binprm_inode: u64,
    #[cfg_attr(feature = "user", serde(serialize_with = "serialize_ipv6"))]
    pub addr: [u8; 16],
}

impl AlertSocketConnectV6 {
    pub fn new(pid: u32, binprm_inode: u64, addr: [u8; 16]) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Paths {
    pub all: bool,
    pub _padding: [u8; 7],
    pub len: usize,
    pub paths: [u64; MAX_PATHS],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ports {
    pub all: bool,
    pub _padding1: [u8; 7],
    pub len: usize,
    pub ports: [u16; MAX_PORTS],
    pub _padding2: [u16; 3 * MAX_PORTS],
}

impl Ports {
    pub fn new(all: bool, len: usize, ports: [u16; MAX_PORTS]) -> Self {
        Self {
            all,
            _padding1: [0; 7],
            len,
            ports,
            _padding2: [0; 3 * MAX_PORTS],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv4Addrs {
    pub all: bool,
    pub _padding1: [u8; 7],
    pub len: usize,
    pub addrs: [u32; MAX_IPV4ADDRS],
    pub _padding2: [u32; MAX_IPV4ADDRS],
}

impl Ipv4Addrs {
    pub fn new(len: usize, addrs: [u32; MAX_IPV4ADDRS]) -> Self {
        Self {
            all: false,
            _padding1: [0; 7],
            len,
            addrs,
            _padding2: [0; MAX_IPV4ADDRS],
        }
    }

    pub fn new_all() -> Self {
        Self {
            all: true,
            _padding1: [0; 7],
            len: 0,
            addrs: [0; MAX_IPV4ADDRS],
            _padding2: [0; MAX_IPV4ADDRS],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv6Addrs {
    pub all: bool,
    pub _padding1: [u8; 7],
    pub len: usize,
    pub addrs: [[u8; 16]; MAX_IPV4ADDRS],
}

impl Ipv6Addrs {
    pub fn new(len: usize, addrs: [[u8; 16]; MAX_IPV4ADDRS]) -> Self {
        Self {
            all: false,
            _padding1: [0; 7],
            len,
            addrs,
        }
    }

    pub fn new_all() -> Self {
        Self {
            all: true,
            _padding1: [0; 7],
            len: 0,
            addrs: [[0; 16]; MAX_IPV4ADDRS],
        }
    }
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    use aya::Pod;

    unsafe impl Pod for AlertFileOpen {}
    unsafe impl Pod for AlertSetuid {}
    unsafe impl Pod for Paths {}
    unsafe impl Pod for Ports {}
    unsafe impl Pod for Ipv4Addrs {}
    unsafe impl Pod for Ipv6Addrs {}
}
