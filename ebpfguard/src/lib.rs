//! **Ebpfguard** is a library for managing Linux security policies. It is based on
//! [LSM hooks](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html),
//! but without necessity to write any kernel modules or eBPF programs directly.
//! It allows to write policies in Rust (or YAML) in user space.
//!
//! It's based on eBPF and [Aya](https://aya-rs.dev) library, but takes away
//! the need to use them directly.

pub mod alerts;
pub mod error;
pub mod fs;
pub mod hooks;
pub mod manager;
pub mod policy;

pub use manager::PolicyManager;
pub use policy::inode::InodeSubjectMap;
