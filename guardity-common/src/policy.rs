pub const MAX_PATHS: usize = 4;
pub const MAX_PORTS: usize = 1;
pub const MAX_IPV4ADDRS: usize = 1;
pub const MAX_IPV6ADDRS: usize = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Paths {
    pub paths: [u64; MAX_PATHS],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ports {
    pub all: bool,
    _padding1: [u8; 7],
    pub len: usize,
    pub ports: [u16; MAX_PORTS],
    _padding2: [u16; 3 * MAX_PORTS],
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

    unsafe impl Pod for Paths {}
    unsafe impl Pod for Ports {}
    unsafe impl Pod for Ipv4Addrs {}
    unsafe impl Pod for Ipv6Addrs {}
}
