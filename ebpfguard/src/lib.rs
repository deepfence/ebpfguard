//! **Ebpfguard** is a library for managing Linux security policies. It is based on
//! [LSM hooks](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html),
//! but without necessity to write any kernel modules or eBPF programs directly.
//! It allows to write policies in Rust (or YAML) in user space.
//!
//! It's based on eBPF and [Aya](https://aya-rs.dev) library, but takes away
//! the need to use them directly.
//!
//! # Prerequisites
//!
//! First, you need to have a Linux kernel:
//! * with BTF support
//! * with BPF LSM support (kernels >= 5.7)
//!
//! You can check if your kernel has BTF support by checking whether file
//! `/sys/kernel/btf/vmlinux` exists. You can also check the kernel configuration:
//!
//! ```bash
//! $ zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
//! CONFIG_DEBUG_INFO_BTF=y
//! ```
//!
//! Next, you need to check if your kernel has BPF LSM support:
//!
//! ```bash
//! $ cat /sys/kernel/security/lsm
//! lockdown,capability,selinux,bpf
//! ```
//!
//! If the output doesn't contain `bpf`, you need to enable BPF LSM by adding
//! `lsm=[...],bpf` to your kernel config parameters. That can be achieved by
//! executing the [following script](https://raw.githubusercontent.com/vadorovsky/enable-bpf-lsm/main/enable-bpf-lsm.py).
//!
//! Then you need the Rust stable and nightly toolchains installed on your system,
//! as well as bpf-linker. You can install these by following these
//! [instructions](https://aya-rs.dev/book/start/development/).
//!
//! # LSM hooks
//!
//! LSM hooks supported by Ebpfguard are:
//!
//! * [`bprm_check_security`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L62)
//! * [`file_open`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L620)
//! * [`sb_mount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L128)
//! * [`sb_remount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L147)
//! * [`sb_umount`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L159)
//! * [`socket_bind`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L904)
//! * [`socket_connect`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L912)
//! * [`task_fix_setuid`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L709)
//!
//! # Examples
//!
//! ## Defining single policies
//!
//! ### `file_open`
//!
//! The [file_open](https://github.com/deepfence/ebpfguard/tree/main/examples/file_open)
//! example shows how to define a policy for `file_open` LSM hook as Rust code.
//! It denies the given binary (or all processes, if none defined) from opening
//! the given directory.
//!
//! To try it out, let's create a directory and a file inside it:
//!
//! ```bash
//! $ mkdir /tmp/test
//! $ echo "foo" > /tmp/test/test
//! ```
//!
//! Then run our example policy program with:
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example file_open -- --path-to-deny /tmp/test
//! ```
//!
//! When trying to access that directory and file, you should see that these
//! operations are denied:
//!
//! ```bash
//! $ ls /tmp/test/
//! ls: cannot open directory '/tmp/test/': Operation not permitted
//! $ cat /tmp/test/test
//! cat: /tmp/test/test: Operation not permitted
//! ```
//!
//! The policy application should show logs like:
//!
//! ```bash
//! [2023-04-22T20:51:01Z INFO  file_open] file_open: pid=3001 subject=980333 path=9632
//! [2023-04-22T20:51:03Z INFO  file_open] file_open: pid=3010 subject=980298 path=9633
//! ```
//! ### mount
//!
//! The [mount](https://github.com/deepfence/ebpfguard/tree/main/examples/file_open)
//! example shows how to define a policy for `sb_mount`, `sb_remount` and
//! `sb_umount` LSM hooks as Rust code. It denies the mount operations for all
//! processes except for the optionally given one.
//!
//! To try it out, let's create two directories:
//!
//! ```bash
//! $ mkdir /tmp/test1
//! $ mkdir /tmp/test2
//! ```
//!
//! Then run our example policy program, first without providing any binary to
//! allow mount for (so it's denied for all processes):
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example mount
//! ```
//!
//! Let's try to bind mount the first directory to the second one. It should
//! fail with the following error:
//!
//! ```bash
//! sudo mount --bind /tmp/test1 /tmp/test2
//! mount: /tmp/test2: permission denied.
//!        dmesg(1) may have more information after failed mount system call.
//! ```
//!
//! And the policy program should show a log like:
//!
//! ```bash
//! [2023-04-23T21:02:58Z INFO  mount] sb_mount: pid=17363 subject=678150
//! ```
//!
//! Now let's try to allow mount operations for the mount binary:
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example mount -- --allow /usr/bin/mount
//! ```
//!
//! And try to bind mount the first directory to the second one again. It should
//! succeed this time:
//!
//! ```bash
//! $ sudo mount --bind /tmp/test1 /tmp/test2
//! $ mount | grep test
//! tmpfs on /tmp/test2 type tmpfs (rw,nosuid,nodev,seclabel,nr_inodes=1048576,inode64)
//! ```
//!
//! ### `task_fix_setuid`
//!
//! The [task_fix_setuid](https://github.com/deepfence/ebpfguard/tree/main/examples/task_fix_setuid)
//! example shows how to define a policy for `task_fix_setuid` LSM hook as Rust
//! code. It denies the `setuid` operation for all processes except for the
//! optionally given one.
//!
//! To try it out, run our example policy program, first without providing any
//! binary to allow `setuid` for (so it's denied for all processes):
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example task_fix_setuid
//! ```
//!
//! Then try to use `sudo`. It should fail with the following error:
//!
//! ```bash
//! sudo -i
//! sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
//! sudo: error initializing audit plugin sudoers_audit
//! ```
//!
//! And the policy program should show log like:
//!
//! ```bash
//! [2023-04-23T15:15:00Z INFO  task_fix_setuid] file_open: pid=25604 subject=674642 old_uid=1000 old_gid=1000 new_uid=0 new_gid=1000
//! ```
//!
//! Now, let's try to allow `setuid` for a specific binary. Let's use `sudo`:
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example task_fix_setuid -- --allow /usr/bin/sudo
//! ```
//!
//! Then try to use `sudo` again. It should work this time:
//!
//! ```bash
//! $ sudo -i
//! # whoami
//! root
//! ```
//!
//! ## Daemon with CLI and YAML engine
//!
//! Run the daemon with:
//!
//! ```bash
//! $ RUST_LOG=info cargo xtask run --example daemon
//! ```
//!
//! Then manage the policies using the CLI:
//!
//! ```bash
//! $ cargo xtask run --example cli -- --help
//! ```
//!
//! You can apply policies from the
//! [example YAML file](https://github.com/deepfence/ebpfguard/blob/main/examples/cli/policy.yaml):
//!
//! ```bash
//! $ cargo xtask run --example cli -- policy add --path examples/cli/policy.yaml
//! ```

use std::path::Path;

use aya::{
    include_bytes_aligned,
    programs::{lsm::LsmLink, Lsm},
    Bpf, BpfLoader, Btf,
};

pub mod alerts;
pub mod error;
pub mod fs;
pub mod hooks;
pub mod policy;

use error::EbpfguardError;
use hooks::{
    bprm_check_security::BprmCheckSecurity, file_open::FileOpen, sb_mount::SbMount,
    sb_remount::SbRemount, sb_umount::SbUmount, socket_bind::SocketBind,
    socket_connect::SocketConnect, task_fix_setuid::TaskFixSetuid, All,
};
use policy::inode::InodeSubjectMap;

pub struct PolicyManager {
    bpf: Bpf,
}

impl PolicyManager {
    /// Default path for storage of eBPFGuard maps
    pub const DEFAULT_BPFFS_MAPS_PATH: &str = "/sys/fs/bpf/ebpfguard_default";

    /// Creates a new policy manager with default maps path.
    ///
    /// Assumes mounted bpf filesystem under /sys/fs/bpf.
    /// # Example
    /// ```no_run
    /// use ebpfguard::PolicyManager;
    ///
    /// let mut policy_manager = PolicyManager::with_default_path().unwrap();
    /// ```
    pub fn with_default_path() -> Result<Self, EbpfguardError> {
        std::fs::create_dir_all(Self::DEFAULT_BPFFS_MAPS_PATH)?;
        Self::new(Self::DEFAULT_BPFFS_MAPS_PATH)
    }

    /// Creates a new policy manager.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpfguard::PolicyManager;
    /// use std::path::Path;
    ///
    /// let mut policy_manager = PolicyManager::new(Path::new("/sys/fs/bpf/mypolicies")).unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(bpf_path: P) -> Result<Self, EbpfguardError> {
        let bpf_lsm_enabled = std::fs::read_to_string("/sys/kernel/security/lsm")?
            .split(',')
            .any(|x| x.to_lowercase() == "bpf");
        if !bpf_lsm_enabled {
            return Err(EbpfguardError::BpfLsmModuleDisabled);
        }

        #[cfg(debug_assertions)]
        let bpf = BpfLoader::new()
            .map_pin_path(&bpf_path)
            .load(include_bytes_aligned!(
                "../../ebpfguard-ebpf/ebpfguard.debug.obj"
            ))?;
        #[cfg(not(debug_assertions))]
        let bpf = BpfLoader::new()
            .map_pin_path(&bpf_path)
            .load(include_bytes_aligned!(
                "../../ebpfguard-ebpf/ebpfguard.release.obj"
            ))?;

        Ok(Self { bpf })
    }

    /// Attaches and returns a handle to all LSM hooks.
    pub fn attach_all(&mut self) -> Result<All, EbpfguardError> {
        let bprm_check_security = self.attach_bprm_check_security()?;
        let file_open = self.attach_file_open()?;
        let sb_mount = self.attach_sb_mount()?;
        let sb_remount = self.attach_sb_remount()?;
        let sb_umount = self.attach_sb_umount()?;
        let socket_bind = self.attach_socket_bind()?;
        let socket_connect = self.attach_socket_connect()?;
        let task_fix_setuid = self.attach_task_fix_setuid()?;

        Ok(All {
            bprm_check_security,
            file_open,
            sb_mount,
            sb_remount,
            sb_umount,
            socket_bind,
            socket_connect,
            task_fix_setuid,
        })
    }

    pub fn manage_all(&mut self) -> Result<All, EbpfguardError> {
        let bprm_check_security = self.manage_bprm_check_security()?;
        let file_open = self.manage_file_open()?;
        let sb_mount = self.manage_sb_mount()?;
        let sb_remount = self.manage_sb_remount()?;
        let sb_umount = self.manage_sb_umount()?;
        let socket_bind = self.manage_socket_bind()?;
        let socket_connect = self.manage_socket_connect()?;
        let task_fix_setuid = self.manage_task_fix_setuid()?;

        Ok(All {
            bprm_check_security,
            file_open,
            sb_mount,
            sb_remount,
            sb_umount,
            socket_bind,
            socket_connect,
            task_fix_setuid,
        })
    }

    pub fn attach_bprm_check_security(&mut self) -> Result<BprmCheckSecurity, EbpfguardError> {
        let mut bprm_check_security = self.manage_bprm_check_security()?;
        let program_link = self.attach_program("bprm_check_security")?;
        bprm_check_security.program_link = Some(program_link);

        Ok(bprm_check_security)
    }

    pub fn manage_bprm_check_security(&mut self) -> Result<BprmCheckSecurity, EbpfguardError> {
        let perf_array = self
            .bpf
            .take_map("ALERT_BPRM_CHECK_SECURITY")
            .unwrap()
            .try_into()?;

        Ok(BprmCheckSecurity {
            program_link: None,
            perf_array,
        })
    }

    pub fn attach_file_open(&mut self) -> Result<FileOpen, EbpfguardError> {
        let mut file_open = self.manage_file_open()?;
        let program_link = self.attach_program("file_open")?;
        file_open.program_link = Some(program_link);

        Ok(file_open)
    }

    pub fn manage_file_open(&mut self) -> Result<FileOpen, EbpfguardError> {
        let allowed_map = self.bpf.take_map("ALLOWED_FILE_OPEN").unwrap().try_into()?;
        let denied_map = self.bpf.take_map("DENIED_FILE_OPEN").unwrap().try_into()?;
        let perf_array = self.bpf.take_map("ALERT_FILE_OPEN").unwrap().try_into()?;

        Ok(FileOpen {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_task_fix_setuid(&mut self) -> Result<TaskFixSetuid, EbpfguardError> {
        let mut task_fix_setuid = self.manage_task_fix_setuid()?;
        let program_link = self.attach_program("task_fix_setuid")?;
        task_fix_setuid.program_link = Some(program_link);

        Ok(task_fix_setuid)
    }

    pub fn manage_task_fix_setuid(&mut self) -> Result<TaskFixSetuid, EbpfguardError> {
        let allowed_map = self
            .bpf
            .take_map("ALLOWED_TASK_FIX_SETUID")
            .unwrap()
            .try_into()?;
        let denied_map = self
            .bpf
            .take_map("DENIED_TASK_FIX_SETUID")
            .unwrap()
            .try_into()?;
        let perf_array = self
            .bpf
            .take_map("ALERT_TASK_FIX_SETUID")
            .unwrap()
            .try_into()?;

        Ok(TaskFixSetuid {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_sb_mount(&mut self) -> Result<SbMount, EbpfguardError> {
        let mut sb_mount = self.manage_sb_mount()?;
        let program_link = self.attach_program("sb_mount")?;
        sb_mount.program_link = Some(program_link);

        Ok(sb_mount)
    }

    pub fn manage_sb_mount(&mut self) -> Result<SbMount, EbpfguardError> {
        let allowed_map = self.bpf.take_map("ALLOWED_SB_MOUNT").unwrap().try_into()?;
        let denied_map = self.bpf.take_map("DENIED_SB_MOUNT").unwrap().try_into()?;
        let perf_array = self.bpf.take_map("ALERT_SB_MOUNT").unwrap().try_into()?;

        Ok(SbMount {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_sb_remount(&mut self) -> Result<SbRemount, EbpfguardError> {
        let mut sb_remount = self.manage_sb_remount()?;
        let program_link = self.attach_program("sb_remount")?;
        sb_remount.program_link = Some(program_link);

        Ok(sb_remount)
    }

    pub fn manage_sb_remount(&mut self) -> Result<SbRemount, EbpfguardError> {
        let allowed_map = self
            .bpf
            .take_map("ALLOWED_SB_REMOUNT")
            .unwrap()
            .try_into()?;
        let denied_map = self.bpf.take_map("DENIED_SB_REMOUNT").unwrap().try_into()?;
        let perf_array = self.bpf.take_map("ALERT_SB_REMOUNT").unwrap().try_into()?;

        Ok(SbRemount {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_sb_umount(&mut self) -> Result<SbUmount, EbpfguardError> {
        let mut sb_umount = self.manage_sb_umount()?;
        let program_link = self.attach_program("sb_umount")?;
        sb_umount.program_link = Some(program_link);

        Ok(sb_umount)
    }

    pub fn manage_sb_umount(&mut self) -> Result<SbUmount, EbpfguardError> {
        let allowed_map = self.bpf.take_map("ALLOWED_SB_UMOUNT").unwrap().try_into()?;
        let denied_map = self.bpf.take_map("DENIED_SB_UMOUNT").unwrap().try_into()?;
        let perf_array = self.bpf.take_map("ALERT_SB_UMOUNT").unwrap().try_into()?;

        Ok(SbUmount {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_socket_bind(&mut self) -> Result<SocketBind, EbpfguardError> {
        let mut socket_bind = self.manage_socket_bind()?;
        let program_link = self.attach_program("socket_bind")?;
        socket_bind.program_link = Some(program_link);

        Ok(socket_bind)
    }

    pub fn manage_socket_bind(&mut self) -> Result<SocketBind, EbpfguardError> {
        let allowed_map = self
            .bpf
            .take_map("ALLOWED_SOCKET_BIND")
            .unwrap()
            .try_into()?;
        let denied_map = self
            .bpf
            .take_map("DENIED_SOCKET_BIND")
            .unwrap()
            .try_into()?;
        let perf_array = self.bpf.take_map("ALERT_SOCKET_BIND").unwrap().try_into()?;

        Ok(SocketBind {
            program_link: None,
            allowed_map,
            denied_map,
            perf_array,
        })
    }

    pub fn attach_socket_connect(&mut self) -> Result<SocketConnect, EbpfguardError> {
        let mut socket_connect = self.manage_socket_connect()?;
        let program_link = self.attach_program("socket_connect")?;
        socket_connect.program_link = Some(program_link);

        Ok(socket_connect)
    }

    pub fn manage_socket_connect(&mut self) -> Result<SocketConnect, EbpfguardError> {
        let allowed_map_v4 = self
            .bpf
            .take_map("ALLOWED_SOCKET_CONNECT_V4")
            .unwrap()
            .try_into()?;
        let denied_map_v4 = self
            .bpf
            .take_map("DENIED_SOCKET_CONNECT_V4")
            .unwrap()
            .try_into()?;
        let allowed_map_v6 = self
            .bpf
            .take_map("ALLOWED_SOCKET_CONNECT_V6")
            .unwrap()
            .try_into()?;
        let denied_map_v6 = self
            .bpf
            .take_map("DENIED_SOCKET_CONNECT_V6")
            .unwrap()
            .try_into()?;
        let perf_array = self
            .bpf
            .take_map("ALERT_SOCKET_CONNECT")
            .unwrap()
            .try_into()?;

        Ok(SocketConnect {
            program_link: None,
            allowed_map_v4,
            denied_map_v4,
            allowed_map_v6,
            denied_map_v6,
            perf_array,
        })
    }

    fn attach_program(&mut self, name: &str) -> Result<LsmLink, EbpfguardError> {
        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = self.bpf.program_mut(name).unwrap().try_into()?;
        program.load(name, &btf)?;
        let link_id = program.attach()?;
        let link = program.take_link(link_id)?;

        Ok(link)
    }
}
