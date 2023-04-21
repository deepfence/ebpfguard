use aya_bpf::{cty::c_long, programs::LsmContext, BpfContext};
use guardity_common::alerts;

use crate::{binprm::current_binprm_inode, maps::ALERT_BPRM_CHECK_SECURITY, vmlinux::linux_binprm};

pub fn bprm_check_security(ctx: LsmContext) -> Result<i32, c_long> {
    let new_binprm: *const linux_binprm = unsafe { ctx.arg(0) };
    let argc = unsafe { (*new_binprm).argc };

    let old_binprm_inode = current_binprm_inode();

    if argc < 1 {
        ALERT_BPRM_CHECK_SECURITY.output(
            &ctx,
            &alerts::BprmCheckSecurity::new(ctx.pid() as u32, old_binprm_inode),
            0,
        );
        return Ok(-1);
    }

    Ok(0)
}
