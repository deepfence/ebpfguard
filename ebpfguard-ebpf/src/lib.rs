#![no_std]
#![no_main]

pub mod binprm;
pub mod bprm_check_security;
pub mod consts;
pub mod file_open;
pub mod maps;
pub mod sb_mount;
pub mod sb_remount;
pub mod sb_umount;
pub mod socket_bind;
pub mod socket_connect;
pub mod task_fix_setuid;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

use aya_bpf::cty::{c_ushort, c_void};
use aya_bpf::{cty::c_int, cty::c_uint, cty::c_ulong};

use vmlinux::cred;
use vmlinux::dentry;
use vmlinux::file;
use vmlinux::inode;
use vmlinux::linux_binprm;
use vmlinux::mm_struct;
use vmlinux::sockaddr;
use vmlinux::sockaddr_in;
use vmlinux::sockaddr_in6;
use vmlinux::task_struct;

#[allow(improper_ctypes)]
extern "C" {
    fn cred_gid_val(target: *const cred) -> c_uint;
    fn cred_uid_val(target: *const cred) -> c_uint;
    fn dentry_i_ino(target: *const dentry) -> c_ulong;
    fn exe_file_inode(target: *const file) -> *const *const inode;
    fn file_dentry(target: *const file) -> *const dentry;
    fn file_inode(target: *const file) -> c_ulong;
    fn inode_i_ino(inode: *const inode) -> *const c_ulong;
    fn linux_binprm_argc(task: *const linux_binprm) -> c_int;
    fn mm_exe_file(target: *const mm_struct) -> *const *const file;
    fn sockaddr_in_sin_addr_s_addr(task: *const sockaddr_in) -> c_uint;
    fn sockaddr_in_sin_port(target: *const sockaddr_in) -> c_ushort;
    fn sockaddr_sa_family(task: *const sockaddr) -> c_ushort;
    fn sockaddr_in6_sin6_addr_in6_u_u6_addr8(
        sockaddr: *const sockaddr_in6,
        array: &[u8; 16],
    ) -> c_void;
    fn task_struct_mm(target: *const task_struct) -> *const *const mm_struct;
}

pub enum Mode {
    Allowlist,
    Denylist,
}

pub enum Action {
    Allow,
    Deny,
}

impl From<Action> for i32 {
    fn from(action: Action) -> Self {
        match action {
            Action::Allow => 0,
            Action::Deny => -1,
        }
    }
}
