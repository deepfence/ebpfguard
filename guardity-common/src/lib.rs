#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "user")]
use serde::Serialize;

pub const MAX_PATHS: usize = 4;
pub const MAX_PORTS: usize = 1;
pub const MAX_IPV4ADDRS: usize = 1;
pub const MAX_IPV6ADDRS: usize = 1;

pub trait Alert {}

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

impl Alert for AlertFileOpen {}

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

impl Alert for AlertSetuid {}

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

impl Alert for AlertSocketBind {}

#[cfg(feature = "user")]
fn serialize_ipv4<S>(addr: &u32, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    Ipv4Addr::from(*addr).serialize(s)
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
pub struct AlertSocketConnect {
    pub pid: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding1: u32,
    pub binprm_inode: u64,
    #[cfg_attr(feature = "user", serde(serialize_with = "serialize_ipv4"))]
    pub addr_v4: u32,
    #[cfg_attr(feature = "user", serde(skip))]
    pub _padding2: u32,
    #[cfg_attr(feature = "user", serde(serialize_with = "serialize_ipv6"))]
    pub addr_v6: [u8; 16],
}

impl AlertSocketConnect {
    pub fn new_ipv4(pid: u32, binprm_inode: u64, addr_v4: u32) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr_v4,
            _padding2: 0,
            addr_v6: [0; 16],
        }
    }

    pub fn new_ipv6(pid: u32, binprm_inode: u64, addr_v6: [u8; 16]) -> Self {
        Self {
            pid,
            _padding1: 0,
            binprm_inode,
            addr_v4: 0,
            _padding2: 0,
            addr_v6,
        }
    }
}

impl Alert for AlertSocketConnect {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Paths {
    // pub all: bool,
    // pub _padding: [u8; 7],
    // pub len: usize,
    pub paths: [u64; MAX_PATHS],
    // pub all: u64,
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

pub trait IpAddrs<T, const U: usize> {
    fn all(&self) -> bool;
    fn addrs(&self) -> [T; U];
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv4Addrs {
    pub addrs: [u32; MAX_IPV4ADDRS],
}

impl Ipv4Addrs {
    pub fn new(addrs: [u32; MAX_IPV4ADDRS]) -> Self {
        Self { addrs }
    }

    pub fn new_all() -> Self {
        Self {
            addrs: [0; MAX_IPV4ADDRS],
        }
    }
}

impl IpAddrs<u32, MAX_IPV4ADDRS> for Ipv4Addrs {
    #[inline(always)]
    fn all(&self) -> bool {
        self.addrs[0] == 0
    }

    #[inline(always)]
    fn addrs(&self) -> [u32; MAX_IPV4ADDRS] {
        self.addrs
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ipv6Addrs {
    pub addrs: [[u8; 16]; MAX_IPV4ADDRS],
}

impl Ipv6Addrs {
    pub fn new(addrs: [[u8; 16]; MAX_IPV4ADDRS]) -> Self {
        Self { addrs }
    }

    pub fn new_all() -> Self {
        Self {
            addrs: [[0; 16]; MAX_IPV4ADDRS],
        }
    }
}

impl IpAddrs<[u8; 16], MAX_IPV6ADDRS> for Ipv6Addrs {
    #[inline(always)]
    fn all(&self) -> bool {
        self.addrs[0] == [0; 16]
    }

    #[inline(always)]
    fn addrs(&self) -> [[u8; 16]; MAX_IPV6ADDRS] {
        self.addrs
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
