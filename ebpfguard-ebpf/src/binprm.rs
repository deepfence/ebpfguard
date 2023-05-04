use aya_bpf::{
    cty::c_long,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
};

use crate::vmlinux::task_struct;

/// Returns the inode of the current binary.
///
/// # Examples
///
/// ```rust
/// use ebpfguard_ebpf::binprm::current_binprm_inode;
///
/// # fn main() -> Result<(), c_long> {
/// let inode = current_binprm_inode()?;
/// # Ok(())
/// # }
/// ```
#[inline(always)]
pub(crate) fn current_binprm_inode() -> Result<u64, c_long> {
    let binprm_inode = unsafe {
        let task = bpf_get_current_task() as *mut task_struct;
        let mm = bpf_probe_read_kernel(&(*task).mm)?;
        let file = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.exe_file)?;
        let f_inode = bpf_probe_read_kernel(&(*file).f_inode)?;
        bpf_probe_read_kernel(&(*f_inode).i_ino)?
    };
    Ok(binprm_inode)
}
