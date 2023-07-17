use std::path::Path;

use aya::{
    include_bytes_aligned,
    programs::{lsm::LsmLink, Lsm},
    Bpf, BpfLoader, Btf,
};

use crate::{
    error::EbpfguardError,
    hooks::{
        bprm_check_security::BprmCheckSecurity, file_open::FileOpen, sb_mount::SbMount,
        sb_remount::SbRemount, sb_umount::SbUmount, socket_bind::SocketBind,
        socket_connect::SocketConnect, task_fix_setuid::TaskFixSetuid, All,
    },
};

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
