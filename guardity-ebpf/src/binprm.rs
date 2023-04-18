use aya_bpf::helpers::bpf_get_current_task_btf;

use crate::vmlinux::task_struct;

#[inline(always)]
pub(crate) fn current_binprm_inode() -> u64 {
    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    unsafe { (*(*(*(*task).mm).__bindgen_anon_1.exe_file).f_inode).i_ino }
}
