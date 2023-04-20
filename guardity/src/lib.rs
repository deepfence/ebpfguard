use std::path::Path;

use aya::{
    include_bytes_aligned,
    programs::{lsm::LsmLink, Lsm},
    Bpf, BpfLoader, Btf,
};

pub mod fs;
pub mod policy;

pub struct PolicyManager {
    pub bpf: Bpf,
    pub bprm_check_security: Option<Hook>,
    pub file_open: Option<Hook>,
    pub setuid: Option<Hook>,
    pub socket_bind: Option<Hook>,
    pub socket_connect: Option<Hook>,
}

pub type Foo = Option<u32>;

impl PolicyManager {
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

        Ok(Self {
            bpf,
            bprm_check_security: None,
            file_open: None,
            setuid: None,
            socket_bind: None,
            socket_connect: None,
        })
    }

    pub fn attach_bprm_check_security(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "bprm_check_security")?;
        let bprm_check_security = Hook::new(link)?;
        self.bprm_check_security = Some(bprm_check_security);

        Ok(())
    }

    pub fn attach_file_open(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "file_open")?;
        let file_open = Hook::new(link)?;
        self.file_open = Some(file_open);

        Ok(())
    }

    pub fn file_open(&mut self) -> anyhow::Result<&mut Hook> {
        match self.file_open {
            Some(ref mut file_open) => Ok(file_open),
            None => Err(anyhow::anyhow!("file_open is not attached")),
        }
    }

    pub fn attach_task_fix_setuid(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "task_fix_setuid")?;
        let setuid = Hook::new(link)?;
        self.setuid = Some(setuid);

        Ok(())
    }

    pub fn setuid(&mut self) -> anyhow::Result<&mut Hook> {
        match self.setuid {
            Some(ref mut setuid) => Ok(setuid),
            None => Err(anyhow::anyhow!("setuid is not attached")),
        }
    }

    pub fn attach_socket_bind(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "socket_bind")?;
        let socket_bind = Hook::new(link)?;
        self.socket_bind = Some(socket_bind);

        Ok(())
    }

    pub fn socket_bind(&mut self) -> anyhow::Result<&mut Hook> {
        match self.socket_bind {
            Some(ref mut socket_bind) => Ok(socket_bind),
            None => Err(anyhow::anyhow!("socket_bind is not attached")),
        }
    }

    pub fn attach_socket_connect(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "socket_connect")?;
        let socket_connect = Hook::new(link)?;
        self.socket_connect = Some(socket_connect);

        Ok(())
    }

    pub fn socket_connect(&mut self) -> anyhow::Result<&mut Hook> {
        match self.socket_connect {
            Some(ref mut socket_connect) => Ok(socket_connect),
            None => Err(anyhow::anyhow!("socket_connect is not attached")),
        }
    }
}

fn attach_program(bpf: &mut Bpf, name: &str) -> anyhow::Result<LsmLink> {
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut(name).unwrap().try_into()?;
    program.load(name, &btf)?;
    let link_id = program.attach()?;
    let link = program.take_link(link_id)?;

    Ok(link)
}

pub struct Hook {
    #[allow(dead_code)]
    program_link: LsmLink,
}

impl Hook {
    pub fn new(program_link: LsmLink) -> anyhow::Result<Self> {
        Ok(Self { program_link })
    }
}
