use aya_bpf::{
    cty::c_long,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
};

use crate::{exe_file_inode, inode_i_ino, mm_exe_file, task_struct_mm, vmlinux::task_struct};

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
        let mm = bpf_probe_read_kernel(task_struct_mm(task))?;
        let file = bpf_probe_read_kernel(mm_exe_file(mm))?;
        let f_inode = bpf_probe_read_kernel(exe_file_inode(file))?;
        bpf_probe_read_kernel(inode_i_ino(f_inode))?
    };
    Ok(binprm_inode)
}
