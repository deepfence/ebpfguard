#![no_std]
#![no_main]

use aya_bpf::{macros::lsm, programs::LsmContext};

use ebpfguard_ebpf::{
    bprm_check_security::bprm_check_security, file_open::file_open, sb_mount::sb_mount,
    sb_remount::sb_remount, sb_umount::sb_umount, socket_bind::socket_bind,
    socket_connect::socket_connect, task_fix_setuid::task_fix_setuid,
};

#[lsm(name = "bprm_check_security")]
pub fn prog_bprm_check_security(ctx: LsmContext) -> i32 {
    match bprm_check_security(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(name = "file_open")]
pub fn prog_file_open(ctx: LsmContext) -> i32 {
    file_open(ctx).into()
}

#[lsm(name = "task_fix_setuid")]
pub fn prog_task_fix_setuid(ctx: LsmContext) -> i32 {
    match task_fix_setuid(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(name = "sb_mount")]
pub fn prog_sb_mount(ctx: LsmContext) -> i32 {
    sb_mount(ctx).into()
}

#[lsm(name = "sb_remount")]
pub fn prog_sb_remount(ctx: LsmContext) -> i32 {
    sb_remount(ctx).into()
}

#[lsm(name = "sb_umount")]
pub fn prog_sb_umount(ctx: LsmContext) -> i32 {
    sb_umount(ctx).into()
}

#[lsm(name = "socket_bind")]
pub fn prog_socket_bind(ctx: LsmContext) -> i32 {
    socket_bind(ctx).into()
}

#[lsm(name = "socket_connect")]
pub fn prog_socket_connect(ctx: LsmContext) -> i32 {
    match socket_connect(ctx) {
        Ok(ret) => ret.into(),
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
