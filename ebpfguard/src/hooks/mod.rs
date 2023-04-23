use std::fmt::Debug;

use aya::{
    maps::{AsyncPerfEventArray, MapData},
    util::online_cpus,
};
use bytes::BytesMut;
use ebpfguard_common::alerts as ebpf_alerts;
use once_cell::sync::Lazy;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    task,
};

use crate::{alerts, error::EbpfguardError, policy, InodeSubjectMap};

pub mod bprm_check_security;
pub mod file_open;
pub mod sb_mount;
pub mod sb_remount;
pub mod sb_umount;
pub mod socket_bind;
pub mod socket_connect;
pub mod task_fix_setuid;

use bprm_check_security::BprmCheckSecurity;
use file_open::FileOpen;
use sb_mount::SbMount;
use socket_bind::SocketBind;
use socket_connect::SocketConnect;
use task_fix_setuid::TaskFixSetuid;

static INODE_SUBJECT_MAP: Lazy<Mutex<InodeSubjectMap>> =
    Lazy::new(|| Mutex::new(InodeSubjectMap::default()));

pub struct All {
    pub bprm_check_security: BprmCheckSecurity,
    pub file_open: FileOpen,
    pub sb_mount: SbMount,
    pub sb_remount: sb_remount::SbRemount,
    pub sb_umount: sb_umount::SbUmount,
    pub socket_bind: SocketBind,
    pub socket_connect: SocketConnect,
    pub task_fix_setuid: TaskFixSetuid,
}

impl All {
    pub async fn add_policy(&mut self, policy: policy::Policy) -> Result<(), EbpfguardError> {
        match policy {
            policy::Policy::FileOpen(policy) => self.file_open.add_policy(policy).await?,
            policy::Policy::SbMount(policy) => self.sb_mount.add_policy(policy).await?,
            policy::Policy::SbRemount(policy) => self.sb_remount.add_policy(policy).await?,
            policy::Policy::SbUmount(policy) => self.sb_umount.add_policy(policy).await?,
            policy::Policy::SocketBind(policy) => self.socket_bind.add_policy(policy).await?,
            policy::Policy::SocketConnect(policy) => self.socket_connect.add_policy(policy).await?,
            policy::Policy::TaskFixSetuid(policy) => {
                self.task_fix_setuid.add_policy(policy).await?
            }
        }

        Ok(())
    }
}

pub async fn perf_array_alerts<E, U>(
    perf_array: &mut AsyncPerfEventArray<MapData>,
) -> Result<Receiver<U>, EbpfguardError>
where
    E: ebpf_alerts::Alert,
    U: alerts::Alert + Debug + Send + From<E> + 'static,
{
    let (tx, rx) = mpsc::channel(32);

    let cpus = online_cpus()?;
    for cpu_id in cpus {
        let tx = tx.clone();
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let alert: U = {
                        let ptr = buf.as_ptr() as *const E;
                        let alert = unsafe { ptr.read_unaligned() };
                        alert.into()
                    };
                    tx.send(alert).await.unwrap();
                }
            }
        });
    }

    Ok(rx)
}
