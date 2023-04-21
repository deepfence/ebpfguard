use aya_bpf::{cty::c_long, programs::LsmContext, BpfContext};
use guardity_common::alerts;

use crate::{
    binprm::current_binprm_inode,
    consts::INODE_WILDCARD,
    maps::{ALERT_SETUID, ALLOWED_SETUID, DENIED_SETUID},
    vmlinux::cred,
};

/// Inspects the context of `task_fix_setuid` LSM hook and decides whether to
/// allow or deny the operation based on the state of the `ALLOWED_SETUID`
/// and `DENIED_SETUID` maps.
///
/// If denied, the operation is logged to the `ALERT_SETUID` map.
///
/// # Example
///
/// ```rust
/// use aya_bpf::{macros::lsm, programs::LsmContext};
/// use guardity_ebpf::setuid;
///
/// #[lsm(name = "my_program")]
/// pub fn my_program(ctx: LsmContext) -> i32 {
///    match setuid::setuid(ctx) {
///       Ok(ret) => ret,
///       Err(_) => 0,
/// }
/// ```
pub fn task_fix_setuid(ctx: LsmContext) -> Result<i32, c_long> {
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
                &alerts::TaskFixSetuid::new(
                    ctx.pid(),
                    binprm_inode,
                    old_uid,
                    old_gid,
                    new_uid,
                    new_gid,
                ),
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
            &alerts::TaskFixSetuid::new(
                ctx.pid(),
                binprm_inode,
                old_uid,
                old_gid,
                new_uid,
                new_gid,
            ),
            0,
        );
        return Ok(-1);
    }

    Ok(0)
}
