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
use aya_log_ebpf::debug;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{sock, task_struct};

#[map]
static ALLOWED_PORTS: HashMap<u64, u16> = HashMap::with_max_entries(1024, 0);

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
