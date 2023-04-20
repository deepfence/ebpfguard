use core::cmp;

use aya_bpf::{cty::c_long, programs::LsmContext, BpfContext};
use guardity_common::{AlertFileOpen, MAX_PATHS};

use crate::{
    binprm::current_binprm_inode,
    consts::INODE_WILDCARD,
    maps::{ALERT_FILE_OPEN, ALLOWED_FILE_OPEN, DENIED_FILE_OPEN},
    vmlinux::file,
};

const MAX_DIR_DEPTH: usize = 16;

/// Inspects the context of `file_open` LSM hook and decides whether to allow or
/// deny the operation based on the state of the `ALLOWED_FILE_OPEN` and
/// `DENIED_FILE_OPEN` maps.
///
/// If denied, the operation is logged to the `ALERT_FILE_OPEN` map.
///
/// # Example
///
/// ```rust
/// use aya_bpf::{macros::lsm, programs::LsmContext};
/// use guardity_ebpf::file_open;
///
/// #[lsm(name = "my_program")]
/// pub fn my_program(ctx: LsmContext) -> i32 {
///     match file_open::file_open(ctx) {
///         Ok(ret) => ret,
///         Err(_) => 0,
///     }
/// }
/// ```
pub fn file_open(ctx: LsmContext) -> Result<i32, c_long> {
    let file: *const file = unsafe { ctx.arg(0) };

    let binprm_inode = current_binprm_inode();
    let inode = unsafe { (*(*(*file).f_path.dentry).d_inode).i_ino };

    if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&INODE_WILDCARD) } {
        if paths.all {
            if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&INODE_WILDCARD) } {
                if paths.all {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
                }

                let len = cmp::min(paths.len, MAX_PATHS);
                if paths.paths[..len].contains(&inode) {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
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
                    let len = cmp::min(paths.len, MAX_PATHS);
                    if paths.paths[..len].contains(&inode) {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                            0,
                        );
                        return Ok(-1);
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }

            if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&binprm_inode) } {
                if paths.all {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
                }

                let len = cmp::min(paths.len, MAX_PATHS);
                if paths.paths[..len].contains(&inode) {
                    ALERT_FILE_OPEN.output(
                        &ctx,
                        &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                        0,
                    );
                    return Ok(-1);
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
                    let len = cmp::min(paths.len, MAX_PATHS);
                    if paths.paths[..len].contains(&inode) {
                        ALERT_FILE_OPEN.output(
                            &ctx,
                            &AlertFileOpen::new(ctx.pid(), binprm_inode, inode),
                            0,
                        );
                        return Ok(-1);
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

                let len = cmp::min(paths.len, MAX_PATHS);
                if paths.paths[..len].contains(&inode) {
                    return Ok(0);
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
                    let len = cmp::min(paths.len, MAX_PATHS);
                    if paths.paths[..len].contains(&inode) {
                        return Ok(0);
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }

            if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&binprm_inode) } {
                if paths.all {
                    return Ok(0);
                }

                let len = cmp::min(paths.len, MAX_PATHS);
                if paths.paths[..len].contains(&inode) {
                    return Ok(0);
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
                    let len = cmp::min(paths.len, MAX_PATHS);
                    if paths.paths[..len].contains(&inode) {
                        return Ok(0);
                    }
                    previous_inode = inode;
                    parent_dentry = unsafe { (*parent_dentry).d_parent };
                }
            }
            ALERT_FILE_OPEN.output(&ctx, &AlertFileOpen::new(ctx.pid(), binprm_inode, inode), 0);
            return Ok(-1);
        }
    }

    Ok(0)
}
