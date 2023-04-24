use aya_bpf::helpers::bpf_get_current_task_btf;

use crate::vmlinux::task_struct;

/// Returns the inode of the current binary.
///
/// # Examples
///
/// ```rust
/// use ebpfguard_ebpf::binprm::current_binprm_inode;
///
/// let inode = current_binprm_inode();
/// ```
#[inline(always)]
pub(crate) fn current_binprm_inode() -> u64 {
    let task = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    unsafe { (*(*(*(*task).mm).__bindgen_anon_1.exe_file).f_inode).i_ino }
}
