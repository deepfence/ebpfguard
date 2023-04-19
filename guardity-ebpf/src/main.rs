#![no_std]
#![no_main]

use core::cmp;

use aya_bpf::{
    cty::c_long,
    macros::{lsm, map},
    maps::{HashMap, PerfEventArray},
    programs::LsmContext,
    BpfContext,
};

pub(crate) mod binprm;
pub(crate) mod maps;
mod socket;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub(crate) mod vmlinux;

use binprm::current_binprm_inode;
use guardity_common::{FileOpenAlert, Paths, SetuidAlert, MAX_PATHS};
use socket::{try_socket_bind, try_socket_connect};
use vmlinux::{cred, file};

const INODE_WILDCARD: u64 = 0;
// const MAX_DIR_DEPTH: usize = 256;
const MAX_DIR_DEPTH: usize = 16;

#[map]
static ALLOWED_FILE_OPEN: HashMap<u64, Paths> = HashMap::pinned(1024, 0);

#[map]
static DENIED_FILE_OPEN: HashMap<u64, Paths> = HashMap::pinned(1024, 0);

#[map]
static ALERT_FILE_OPEN: PerfEventArray<FileOpenAlert> = PerfEventArray::pinned(1024, 0);

#[map]
static ALLOWED_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

#[map]
static DENIED_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

#[map]
static ALERT_SETUID: PerfEventArray<SetuidAlert> = PerfEventArray::pinned(1024, 0);

#[lsm(name = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, c_long> {
    let file: *const file = unsafe { ctx.arg(0) };

    let binprm_inode = current_binprm_inode();
    let inode = unsafe { (*(*(*file).f_path.dentry).d_inode).i_ino };

    if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&INODE_WILDCARD) } {
        if paths.all {
            if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&INODE_WILDCARD) } {
                if paths.all {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                            0,
                        );
                        return Ok(-1);
                    }
                }

                let mut previous_inode = inode;
                let mut parent_dentry = unsafe { (*(*file).f_path.dentry).d_parent };
                for _ in 0..MAX_DIR_DEPTH {
                    if parent_dentry.is_null() {
                        break;
                    }
                    let inode = unsafe { (*(*parent_dentry).d_inode).i_ino };
                    if inode == previous_inode {
                        break;
                    }
                    for i in 0..cmp::min(paths.len, MAX_PATHS) {
                        if paths.paths[i] == inode {
                            ALERT_FILE_OPEN.output(
                                &ctx,
                                &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                                0,
                            );
                            return Ok(-1);
                        }
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }

            if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&binprm_inode) } {
                if paths.all {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                            0,
                        );
                        return Ok(-1);
                    }
                }

                let mut previous_inode = inode;
                let mut parent_dentry = unsafe { (*(*file).f_path.dentry).d_parent };
                for _ in 0..MAX_DIR_DEPTH {
                    if parent_dentry.is_null() {
                        break;
                    }
                    let inode = unsafe { (*(*parent_dentry).d_inode).i_ino };
                    if inode == previous_inode {
                        break;
                    }
                    for i in 0..cmp::min(paths.len, MAX_PATHS) {
                        if paths.paths[i] == inode {
                            ALERT_FILE_OPEN.output(
                                &ctx,
                                &FileOpenAlert::new(ctx.pid(), binprm_inode, inode),
                                0,
                            );
                            return Ok(-1);
                        }
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }
        }
    }

    if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&INODE_WILDCARD) } {
        if paths.all {
            if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&INODE_WILDCARD) } {
                if paths.all {
                    return Ok(0);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        return Ok(0);
                    }
                }

                let mut previous_inode = inode;
                let mut parent_dentry = unsafe { (*(*file).f_path.dentry).d_parent };
                for _ in 0..MAX_DIR_DEPTH {
                    if parent_dentry.is_null() {
                        break;
                    }
                    let inode = unsafe { (*(*parent_dentry).d_inode).i_ino };
                    if inode == previous_inode {
                        break;
                    }
                    for i in 0..cmp::min(paths.len, MAX_PATHS) {
                        if paths.paths[i] == inode {
                            return Ok(0);
                        }
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }

            if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&binprm_inode) } {
                if paths.all {
                    return Ok(0);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        return Ok(0);
                    }
                }

                let mut previous_inode = inode;
                let mut parent_dentry = unsafe { (*(*file).f_path.dentry).d_parent };
                for _ in 0..MAX_DIR_DEPTH {
                    if parent_dentry.is_null() {
                        break;
                    }
                    let inode = unsafe { (*(*parent_dentry).d_inode).i_ino };
                    if inode == previous_inode {
                        break;
                    }
                    for i in 0..cmp::min(paths.len, MAX_PATHS) {
                        if paths.paths[i] == inode {
                            return Ok(0);
                        }
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }
            ALERT_FILE_OPEN.output(&ctx, &FileOpenAlert::new(ctx.pid(), binprm_inode, inode), 0);
            return Ok(-1);
        }
    }

    Ok(0)
}

#[lsm(name = "task_fix_setuid")]
pub fn task_fix_setuid(ctx: LsmContext) -> i32 {
    match try_task_fix_setuid(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_task_fix_setuid(ctx: LsmContext) -> Result<i32, c_long> {
    let new: *const cred = unsafe { ctx.arg(0) };
    let old: *const cred = unsafe { ctx.arg(1) };

    let old_uid = unsafe { (*old).uid.val };
    let old_gid = unsafe { (*old).gid.val };
    let new_uid = unsafe { (*new).uid.val };
    let new_gid = unsafe { (*new).gid.val };

    let binprm_inode = current_binprm_inode();

    if unsafe { ALLOWED_SETUID.get(&INODE_WILDCARD) }.is_some() {
        if unsafe { DENIED_SETUID.get(&binprm_inode).is_some() } {
            ALERT_SETUID.output(
                &ctx,
                &SetuidAlert::new(ctx.pid(), binprm_inode, old_uid, old_gid, new_uid, new_gid),
                0,
            );
            return Ok(-1);
        }
        return Ok(0);
    }

    if unsafe { DENIED_SETUID.get(&INODE_WILDCARD) }.is_some() {
        if unsafe { ALLOWED_SETUID.get(&binprm_inode).is_some() } {
            return Ok(0);
        }
        ALERT_SETUID.output(
            &ctx,
            &SetuidAlert::new(ctx.pid(), binprm_inode, old_uid, old_gid, new_uid, new_gid),
            0,
        );
        return Ok(-1);
    }

    Ok(0)
}

#[lsm(name = "socket_bind")]
pub fn socket_bind(ctx: LsmContext) -> i32 {
    match try_socket_bind(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(name = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    match try_socket_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
