#![no_std]
#![no_main]

use core::cmp;

use aya_bpf::{
    cty::c_long,
    helpers::bpf_get_current_task_btf,
    macros::{lsm, map},
    maps::{HashMap, PerfEventArray},
    programs::LsmContext,
    BpfContext,
};
use aya_log_ebpf::debug;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use guardity_common::{FileOpenAlert, Paths, SetuidAlert, MAX_PATHS};
use vmlinux::{cred, file, sock, task_struct};

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

#[map]
static ALLOWED_PORTS: HashMap<u64, u16> = HashMap::pinned(1024, 0);

#[inline(always)]
fn current_binprm_inode() -> u64 {
    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    unsafe { (*(*(*(*task).mm).__bindgen_anon_1.exe_file).f_inode).i_ino }
}

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
                        &FileOpenAlert {
                            pid: ctx.pid() as u64,
                            binprm_inode,
                            inode,
                        },
                        0,
                    );
                    return Ok(-1);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &FileOpenAlert {
                                pid: ctx.pid() as u64,
                                binprm_inode,
                                inode,
                            },
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
                                &FileOpenAlert {
                                    pid: ctx.pid() as u64,
                                    binprm_inode,
                                    inode,
                                },
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
                        &FileOpenAlert {
                            pid: ctx.pid() as u64,
                            binprm_inode,
                            inode,
                        },
                        0,
                    );
                    return Ok(-1);
                }

                for i in 0..cmp::min(paths.len, MAX_PATHS) {
                    if paths.paths[i] == inode {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &FileOpenAlert {
                                pid: ctx.pid() as u64,
                                binprm_inode,
                                inode,
                            },
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
                                &FileOpenAlert {
                                    pid: ctx.pid() as u64,
                                    binprm_inode,
                                    inode,
                                },
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
            ALERT_FILE_OPEN.output(
                &ctx,
                &FileOpenAlert {
                    pid: ctx.pid() as u64,
                    binprm_inode,
                    inode,
                },
                0,
            );
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
                &SetuidAlert {
                    pid: ctx.pid() as u64,
                    binprm_inode,
                    old_uid,
                    old_gid,
                    new_uid,
                    new_gid,
                },
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
            &SetuidAlert {
                pid: ctx.pid() as u64,
                binprm_inode,
                old_uid,
                old_gid,
                new_uid,
                new_gid,
            },
            0,
        );
        return Ok(-1);
    }

    Ok(0)
}

#[lsm(name = "socket_recvmsg")]
pub fn socket_recvmsg(ctx: LsmContext) -> i32 {
    match try_socket_recvmsg(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_socket_recvmsg(ctx: LsmContext) -> Result<i32, c_long> {
    let sock: *const sock = unsafe { ctx.arg(0) };
    let dport = unsafe {
        (*sock)
            .__sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport
    };

    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    let pid = unsafe { (*task).pid };
    let i_ino = unsafe { (*(*(*(*task).mm).__bindgen_anon_1.exe_file).f_inode).i_ino };
    let comm = ctx.command()?;
    let comm = unsafe { core::str::from_utf8_unchecked(&comm) };

    debug!(
        &ctx,
        "lsm hook socket_recvmsg called: pid: {}, inode: {}, comm: {}, dport: {}",
        pid,
        i_ino,
        comm,
        dport
    );

    if let Some(port) = unsafe { ALLOWED_PORTS.get(&i_ino) } {
        if dport == *port {
            return Ok(0);
        }
        return Ok(1);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
