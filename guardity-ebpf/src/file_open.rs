use aya_bpf::{maps::HashMap, programs::LsmContext, BpfContext};
use guardity_common::{AlertFileOpen, Paths, MAX_PATHS};

use crate::{
    binprm::current_binprm_inode,
    consts::INODE_WILDCARD,
    maps::{ALERT_FILE_OPEN, ALLOWED_FILE_OPEN, DENIED_FILE_OPEN},
    vmlinux::file,
    Action, Mode,
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
///     file_open::file_open(ctx).into()
/// }
/// ```
pub fn file_open(ctx: LsmContext) -> Action {
    let file: *const file = unsafe { ctx.arg(0) };

    let binprm_inode = current_binprm_inode();
    let inode = unsafe { (*(*(*file).f_path.dentry).d_inode).i_ino };

    if let Some(paths) = unsafe { ALLOWED_FILE_OPEN.get(&INODE_WILDCARD) } {
        if paths.paths[0] == 0 {
            return check_conditions_and_alert(
                &ctx,
                &DENIED_FILE_OPEN,
                file,
                inode,
                binprm_inode,
                Mode::Denylist,
            );
        }
    }

    if let Some(paths) = unsafe { DENIED_FILE_OPEN.get(&INODE_WILDCARD) } {
        if paths.paths[0] == 0 {
            return check_conditions_and_alert(
                &ctx,
                &ALLOWED_FILE_OPEN,
                file,
                inode,
                binprm_inode,
                Mode::Allowlist,
            );
        }
    }

    Action::Allow
}

#[inline(always)]
fn check_conditions_and_alert(
    ctx: &LsmContext,
    map: &HashMap<u64, Paths>,
    file: *const file,
    inode: u64,
    binprm_inode: u64,
    mode: Mode,
) -> Action {
    match check_conditions(map, file, inode, binprm_inode, mode) {
        Action::Allow => Action::Allow,
        Action::Deny => {
            ALERT_FILE_OPEN.output(ctx, &AlertFileOpen::new(ctx.pid(), binprm_inode, inode), 0);
            Action::Deny
        }
    }
}

#[inline(always)]
fn check_conditions(
    map: &HashMap<u64, Paths>,
    file: *const file,
    inode: u64,
    binprm_inode: u64,
    mode: Mode,
) -> Action {
    if let Some(paths) = unsafe { map.get(&INODE_WILDCARD) } {
        if let Some(action) = check_paths(&paths.paths, file, inode, &mode) {
            return action;
        }
    }

    if let Some(paths) = unsafe { map.get(&binprm_inode) } {
        if let Some(action) = check_paths(&paths.paths, file, inode, &mode) {
            return action;
        }
    }

    match mode {
        Mode::Allowlist => Action::Deny,
        Mode::Denylist => Action::Allow,
    }
}

#[inline(always)]
fn check_paths(
    paths: &[u64; MAX_PATHS],
    file: *const file,
    inode: u64,
    mode: &Mode,
) -> Option<Action> {
    if paths[0] == 0 {
        return Some(match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        });
    }

    if paths[..MAX_PATHS - 1].contains(&inode) {
        return Some(match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        });
    }

    check_parents(paths, file, inode, mode)
}

#[inline(always)]
fn check_parents(
    paths: &[u64; MAX_PATHS],
    file: *const file,
    mut previous_inode: u64,
    mode: &Mode,
) -> Option<Action> {
    let mut parent_dentry = unsafe { (*(*file).f_path.dentry).d_parent };
    for _ in 0..MAX_DIR_DEPTH {
        if parent_dentry.is_null() {
            break;
        }
        let inode = unsafe { (*(*parent_dentry).d_inode).i_ino };
        if inode == previous_inode {
            break;
        }
        if paths[..MAX_PATHS - 1].contains(&inode) {
            return Some(match mode {
                Mode::Allowlist => Action::Allow,
                Mode::Denylist => Action::Deny,
            });
        }
        previous_inode = inode;
        parent_dentry = unsafe { (*parent_dentry).d_parent };
    }

    None
}
