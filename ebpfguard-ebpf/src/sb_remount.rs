use aya_bpf::{cty::c_long, maps::HashMap, programs::LsmContext, BpfContext};
use ebpfguard_common::{alerts, consts::INODE_WILDCARD};

use crate::{
    binprm::current_binprm_inode,
    maps::{ALERT_SB_REMOUNT, ALLOWED_SB_REMOUNT, DENIED_SB_REMOUNT},
    Action, Mode,
};

/// Inspects the context of `sb_remount` LSM hook and decides whether to allow or
/// deny the operation based on the state of the `ALLOWED_SB_REMOUNT` and
/// `DENIED_SB_REMOUNT` maps.
///
/// If denied, the operation is logged to the `ALERT_SB_REMOUNT` map.
///
/// # Example
///
/// ```rust
/// use aya_bpf::{macros::lsm, programs::LsmContext};
///
/// #[lsm(name = "my_program")]
/// pub fn my_program(ctx: LsmContext) -> i32 {
///     sb_umount(ctx).into()
/// }
/// ```
pub fn sb_remount(ctx: LsmContext) -> Result<Action, c_long> {
    let binprm_inode = current_binprm_inode()?;

    if unsafe { ALLOWED_SB_REMOUNT.get(&INODE_WILDCARD).is_some() } {
        return Ok(check_conditions_and_alert(
            &ctx,
            &DENIED_SB_REMOUNT,
            binprm_inode,
            Mode::Denylist,
        ));
    }

    if unsafe { DENIED_SB_REMOUNT.get(&INODE_WILDCARD).is_some() } {
        return Ok(check_conditions_and_alert(
            &ctx,
            &ALLOWED_SB_REMOUNT,
            binprm_inode,
            Mode::Allowlist,
        ));
    }

    Ok(Action::Allow)
}

#[inline(always)]
fn check_conditions_and_alert(
    ctx: &LsmContext,
    map: &HashMap<u64, u8>,
    binprm_inode: u64,
    mode: Mode,
) -> Action {
    match check_conditions(map, binprm_inode, mode) {
        Action::Deny => {
            ALERT_SB_REMOUNT.output(ctx, &alerts::SbRemount::new(ctx.pid(), binprm_inode), 0);
            Action::Deny
        }
        action => action,
    }
}

#[inline(always)]
fn check_conditions(map: &HashMap<u64, u8>, binprm_inode: u64, mode: Mode) -> Action {
    if unsafe { map.get(&INODE_WILDCARD).is_some() } {
        return match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        };
    }

    if unsafe { map.get(&binprm_inode).is_some() } {
        return match mode {
            Mode::Allowlist => Action::Allow,
            Mode::Denylist => Action::Deny,
        };
    }

    match mode {
        Mode::Allowlist => Action::Deny,
        Mode::Denylist => Action::Allow,
    }
}
