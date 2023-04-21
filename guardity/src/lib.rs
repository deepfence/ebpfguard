use std::{fmt::Debug, marker::PhantomData, path::Path};

use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, MapData},
    programs::{lsm::LsmLink, Lsm},
    util::online_cpus,
    Bpf, BpfLoader, Btf,
};
use bytes::BytesMut;
use guardity_common::{
    Alert, AlertBprmCheckSecurity, AlertFileOpen, AlertSetuid, AlertSocketBind, AlertSocketConnect,
};
use tokio::{
    sync::mpsc::{self, Receiver},
    task,
};

pub mod fs;
pub mod policy;

pub struct PolicyManager {
    bpf: Bpf,
    bprm_check_security: Option<BprmCheckSecurityHook>,
    file_open: Option<FileOpenHook>,
    task_fix_setuid: Option<TaskFixSetuidHook>,
    socket_bind: Option<SocketBindHook>,
    socket_connect: Option<SocketConnectHook>,
}

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
            task_fix_setuid: None,
            socket_bind: None,
            socket_connect: None,
        })
    }

    pub fn attach_bprm_check_security(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "bprm_check_security")?;
        let perf_array = perf_array(&mut self.bpf, "ALERT_BPRM_CHECK_SECURITY")?;
        let bprm_check_security = Hook::new(link, perf_array)?;
        self.bprm_check_security = Some(bprm_check_security);

        Ok(())
    }

    pub fn bprm_check_security(&mut self) -> anyhow::Result<&mut BprmCheckSecurityHook> {
        match self.bprm_check_security {
            Some(ref mut bprm_check_security) => Ok(bprm_check_security),
            None => Err(anyhow::anyhow!("bprm_check_security is not attached")),
        }
    }

    pub fn attach_file_open(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "file_open")?;
        let perf_array = perf_array(&mut self.bpf, "ALERT_FILE_OPEN")?;
        let file_open = Hook::new(link, perf_array)?;
        self.file_open = Some(file_open);

        Ok(())
    }

    pub fn file_open(&mut self) -> anyhow::Result<&mut FileOpenHook> {
        match self.file_open {
            Some(ref mut file_open) => Ok(file_open),
            None => Err(anyhow::anyhow!("file_open is not attached")),
        }
    }

    pub fn attach_task_fix_setuid(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "task_fix_setuid")?;
        let perf_array = perf_array(&mut self.bpf, "ALERT_SETUID")?;
        let setuid = Hook::new(link, perf_array)?;
        self.task_fix_setuid = Some(setuid);

        Ok(())
    }

    pub fn task_fix_setuid(&mut self) -> anyhow::Result<&mut TaskFixSetuidHook> {
        match self.task_fix_setuid {
            Some(ref mut setuid) => Ok(setuid),
            None => Err(anyhow::anyhow!("setuid is not attached")),
        }
    }

    pub fn attach_socket_bind(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "socket_bind")?;
        let perf_array = perf_array(&mut self.bpf, "ALERT_SOCKET_BIND")?;
        let socket_bind = Hook::new(link, perf_array)?;
        self.socket_bind = Some(socket_bind);

        Ok(())
    }

    pub fn socket_bind(&mut self) -> anyhow::Result<&mut SocketBindHook> {
        match self.socket_bind {
            Some(ref mut socket_bind) => Ok(socket_bind),
            None => Err(anyhow::anyhow!("socket_bind is not attached")),
        }
    }

    pub fn attach_socket_connect(&mut self) -> anyhow::Result<()> {
        let link = attach_program(&mut self.bpf, "socket_connect")?;
        let perf_array = perf_array(&mut self.bpf, "ALERT_SOCKET_CONNECT")?;
        let socket_connect = Hook::new(link, perf_array)?;
        self.socket_connect = Some(socket_connect);

        Ok(())
    }

    pub fn socket_connect(&mut self) -> anyhow::Result<&mut SocketConnectHook> {
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

fn perf_array(bpf: &mut Bpf, name: &str) -> anyhow::Result<AsyncPerfEventArray<MapData>> {
    let perf_array = bpf.take_map(name).unwrap().try_into()?;
    Ok(perf_array)
}

pub struct Hook<T>
where
    T: Alert,
{
    #[allow(dead_code)]
    program_link: LsmLink,
    perf_array: AsyncPerfEventArray<MapData>,
    phantom: PhantomData<T>,
}

impl<T> Hook<T>
where
    T: Alert + Debug + Send + 'static,
{
    fn new(
        program_link: LsmLink,
        perf_array: AsyncPerfEventArray<MapData>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            program_link,
            perf_array,
            phantom: PhantomData,
        })
    }

    pub async fn alerts(&mut self) -> anyhow::Result<Receiver<T>> {
        let (tx, rx) = mpsc::channel(32);

        let cpus = online_cpus()?;
        for cpu_id in cpus {
            let tx = tx.clone();
            let mut buf = self.perf_array.open(cpu_id, None)?;

            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let alert = {
                            let ptr = buf.as_ptr() as *const T;
                            unsafe { ptr.read_unaligned() }
                        };
                        tx.send(alert).await.unwrap();
                    }
                }
            });
        }

        Ok(rx)
    }
}

pub type BprmCheckSecurityHook = Hook<AlertBprmCheckSecurity>;
pub type FileOpenHook = Hook<AlertFileOpen>;
pub type TaskFixSetuidHook = Hook<AlertSetuid>;
pub type SocketBindHook = Hook<AlertSocketBind>;
pub type SocketConnectHook = Hook<AlertSocketConnect>;
