use aya_bpf::{cty::c_long, programs::LsmContext};

use crate::vmlinux::linux_binprm;

pub fn bprm_check_security(ctx: LsmContext) -> Result<i32, c_long> {
    let binprm: *const linux_binprm = unsafe { ctx.arg(0) };
    let argc = unsafe { (*binprm).argc };

    if argc < 1 {
        return Ok(-1);
    }

    Ok(0)
}
