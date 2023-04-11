#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_long,
    helpers::bpf_get_current_task_btf,
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
    BpfContext,
};
use aya_log_ebpf::{debug, info};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{sock, task_struct};

const INODE_WILDCARD: u64 = 0;

#[map]
static ALLOWED_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

#[map]
static DENIED_SETUID: HashMap<u64, u8> = HashMap::pinned(1024, 0);

#[map]
static ALLOWED_PORTS: HashMap<u64, u16> = HashMap::pinned(1024, 0);

#[inline(always)]
fn current_binprm_inode() -> u64 {
    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    unsafe { (*(*(*(*task).mm).__bindgen_anon_1.exe_file).f_inode).i_ino }
}

#[lsm(name = "task_fix_setuid")]
pub fn task_fix_setuid(ctx: LsmContext) -> i32 {
    match try_task_fix_setuid(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_task_fix_setuid(ctx: LsmContext) -> Result<i32, c_long> {
    let inode = current_binprm_inode();

    let comm = ctx.command()?;
    let comm = unsafe { core::str::from_utf8_unchecked(&comm) };

    debug!(
        &ctx,
        "lsm hook task_fix_setuid called: inode: {}, comm: {}", inode, comm
    );

    if unsafe { ALLOWED_SETUID.get(&INODE_WILDCARD) }.is_some() {
        if unsafe { DENIED_SETUID.get(&inode).is_some() } {
            return Ok(-1);
        }
        return Ok(0);
    }

    if unsafe { DENIED_SETUID.get(&INODE_WILDCARD) }.is_some() {
        if unsafe { ALLOWED_SETUID.get(&inode).is_some() } {
            return Ok(0);
        }
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
