//! **Guardity** is a library for managing Linux security policies. It is based on
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
//! LSM hooks supported by Guardity are:
//!
//! * [`bprm_check_security`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L62)
//! * [`file_open`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L620)
//! * [`task_fix_setuid`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L709)
//! * [`socket_bind`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L904)
//! * [`socket_connect`](https://elixir.bootlin.com/linux/v6.2.12/source/include/linux/lsm_hooks.h#L912)
//!
//! # Examples
//!
//! ## Defining single policies
//!
//! The [file_open](https://github.com/deepfence/guardity/tree/main/examples/file_open)
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
//! [example YAML file](https://github.com/deepfence/guardity/blob/main/examples/cli/policy.yaml):
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
use hooks::{All, BprmCheckSecurity, FileOpen, SocketBind, SocketConnect, TaskFixSetuid};
use policy::inode::InodeSubjectMap;

pub mod alerts;
pub mod error;
pub mod fs;
pub mod hooks;
pub mod policy;

pub struct PolicyManager {
    bpf: Bpf,
}

impl PolicyManager {
    /// Creates a new policy manager.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use guardity::PolicyManager;
    /// use std::path::Path;
    ///
    /// let mut policy_manager = PolicyManager::new(Path::new("/sys/fs/bpf/mypolicies")).unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(bpf_path: P) -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let bpf = BpfLoader::new()
            .map_pin_path(&bpf_path)
            .load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/debug/guardity"
            ))?;
        #[cfg(not(debug_assertions))]
        let bpf = BpfLoader::new()
            .map_pin_path(&bpf_path)
            .load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/release/guardity"
            ))?;

        Ok(Self { bpf })
    }

    /// Attaches and returns a handle to all LSM hooks.
    pub fn attach_all(&mut self) -> anyhow::Result<All> {
        let bprm_check_security = self.attach_bprm_check_security()?;
        let file_open = self.attach_file_open()?;
        let task_fix_setuid = self.attach_task_fix_setuid()?;
        let socket_bind = self.attach_socket_bind()?;
        let socket_connect = self.attach_socket_connect()?;

        Ok(All {
            bprm_check_security,
            file_open,
            task_fix_setuid,
            socket_bind,
            socket_connect,
        })
    }

    pub fn manage_all(&mut self) -> anyhow::Result<All> {
        let bprm_check_security = self.manage_bprm_check_security()?;
        let file_open = self.manage_file_open()?;
        let task_fix_setuid = self.manage_task_fix_setuid()?;
        let socket_bind = self.manage_socket_bind()?;
        let socket_connect = self.manage_socket_connect()?;

        Ok(All {
            bprm_check_security,
            file_open,
            task_fix_setuid,
            socket_bind,
            socket_connect,
        })
    }

    pub fn attach_bprm_check_security(&mut self) -> anyhow::Result<BprmCheckSecurity> {
        let mut bprm_check_security = self.manage_bprm_check_security()?;
        let program_link = self.attach_program("bprm_check_security")?;
        bprm_check_security.program_link = Some(program_link);

        Ok(bprm_check_security)
    }

    pub fn manage_bprm_check_security(&mut self) -> anyhow::Result<BprmCheckSecurity> {
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

    pub fn attach_file_open(&mut self) -> anyhow::Result<FileOpen> {
        let mut file_open = self.manage_file_open()?;
        let program_link = self.attach_program("file_open")?;
        file_open.program_link = Some(program_link);

        Ok(file_open)
    }

    pub fn manage_file_open(&mut self) -> anyhow::Result<FileOpen> {
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

    pub fn attach_task_fix_setuid(&mut self) -> anyhow::Result<TaskFixSetuid> {
        let mut task_fix_setuid = self.manage_task_fix_setuid()?;
        let program_link = self.attach_program("task_fix_setuid")?;
        task_fix_setuid.program_link = Some(program_link);

        Ok(task_fix_setuid)
    }

    pub fn manage_task_fix_setuid(&mut self) -> anyhow::Result<TaskFixSetuid> {
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

    pub fn attach_socket_bind(&mut self) -> anyhow::Result<SocketBind> {
        let mut socket_bind = self.manage_socket_bind()?;
        let program_link = self.attach_program("socket_bind")?;
        socket_bind.program_link = Some(program_link);

        Ok(socket_bind)
    }

    pub fn manage_socket_bind(&mut self) -> anyhow::Result<SocketBind> {
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

    pub fn attach_socket_connect(&mut self) -> anyhow::Result<SocketConnect> {
        let mut socket_connect = self.manage_socket_connect()?;
        let program_link = self.attach_program("socket_connect")?;
        socket_connect.program_link = Some(program_link);

        Ok(socket_connect)
    }

    pub fn manage_socket_connect(&mut self) -> anyhow::Result<SocketConnect> {
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

    fn attach_program(&mut self, name: &str) -> anyhow::Result<LsmLink> {
        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = self.bpf.program_mut(name).unwrap().try_into()?;
        program.load(name, &btf)?;
        let link_id = program.attach()?;
        let link = program.take_link(link_id)?;

        Ok(link)
    }
}
