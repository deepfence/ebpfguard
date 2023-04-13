#![no_std]

pub const MAX_PATHS: usize = 8;

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

    unsafe impl aya::Pod for Paths {}
}
