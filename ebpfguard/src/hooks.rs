use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::lsm::LsmLink,
    util::online_cpus,
};
use bytes::BytesMut;
use ebpfguard_common::{
    alerts as ebpf_alerts,
    policy::{self as ebpf_policy, IpAddrs},
};
use once_cell::sync::Lazy;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    task,
};

use crate::{alerts, error::EbpfguardError, policy, InodeSubjectMap};

static INODE_SUBJECT_MAP: Lazy<Mutex<InodeSubjectMap>> =
    Lazy::new(|| Mutex::new(InodeSubjectMap::default()));

pub struct All {
    pub bprm_check_security: BprmCheckSecurity,
    pub file_open: FileOpen,
    pub task_fix_setuid: TaskFixSetuid,
    pub socket_bind: SocketBind,
    pub socket_connect: SocketConnect,
}

impl All {
    pub async fn add_policy(&mut self, policy: policy::Policy) -> Result<(), EbpfguardError> {
        match policy {
            policy::Policy::FileOpen(policy) => self.file_open.add_policy(policy).await?,
            policy::Policy::TaskFixSetuid(policy) => {
                self.task_fix_setuid.add_policy(policy).await?
            }
            policy::Policy::SocketBind(policy) => self.socket_bind.add_policy(policy).await?,
            policy::Policy::SocketConnect(policy) => self.socket_connect.add_policy(policy).await?,
        }

        Ok(())
    }
}

pub struct BprmCheckSecurity {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl BprmCheckSecurity {
    pub async fn alerts(&mut self) -> Result<Receiver<alerts::BprmCheckSecurity>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::BprmCheckSecurity, alerts::BprmCheckSecurity>(
            &mut self.perf_array,
        )
        .await
    }
}

pub struct FileOpen {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map: HashMap<MapData, u64, ebpf_policy::Paths>,
    pub(crate) denied_map: HashMap<MapData, u64, ebpf_policy::Paths>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl FileOpen {
    pub async fn add_policy(&mut self, policy: policy::FileOpen) -> Result<(), EbpfguardError> {
        let bin_inode = {
            let mut map = INODE_SUBJECT_MAP.lock().await;
            map.resolve_path(policy.subject)?
        };

        let allow: ebpf_policy::Paths = policy.allow.into();
        let deny: ebpf_policy::Paths = policy.deny.into();

        self.allowed_map.insert(bin_inode, allow, 0)?;
        self.denied_map.insert(bin_inode, deny, 0)?;

        Ok(())
    }

    pub async fn list_policies(&self) -> Result<Vec<policy::FileOpen>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map.iter() {
            let (bin_inode, allow) = res?;
            let deny = self.denied_map.get(&bin_inode, 0)?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            policies.push(policy::FileOpen {
                subject,
                allow: allow.into(),
                deny: deny.into(),
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::FileOpen>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::FileOpen, alerts::FileOpen>(&mut self.perf_array).await
    }
}

pub struct TaskFixSetuid {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map: HashMap<MapData, u64, u8>,
    pub(crate) denied_map: HashMap<MapData, u64, u8>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl TaskFixSetuid {
    pub async fn add_policy(
        &mut self,
        policy: policy::TaskFixSetuid,
    ) -> Result<(), EbpfguardError> {
        let bin_inode = {
            let mut map = INODE_SUBJECT_MAP.lock().await;
            map.resolve_path(policy.subject)?
        };

        if policy.allow {
            self.allowed_map.insert(bin_inode, 0, 0)?;
        } else {
            self.denied_map.insert(bin_inode, 0, 0)?;
        }

        Ok(())
    }

    pub async fn list_policies(&self) -> Result<Vec<policy::TaskFixSetuid>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map.iter() {
            let (bin_inode, _) = res?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            policies.push(policy::TaskFixSetuid {
                subject,
                allow: true,
            });
        }

        for res in self.denied_map.iter() {
            let (bin_inode, _) = res?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            policies.push(policy::TaskFixSetuid {
                subject,
                allow: false,
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::TaskFixSetuid>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::TaskFixSetuid, alerts::TaskFixSetuid>(&mut self.perf_array)
            .await
    }
}

pub struct SocketBind {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map: HashMap<MapData, u64, ebpf_policy::Ports>,
    pub(crate) denied_map: HashMap<MapData, u64, ebpf_policy::Ports>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl SocketBind {
    pub async fn add_policy(&mut self, policy: policy::SocketBind) -> Result<(), EbpfguardError> {
        let bin_inode = {
            let mut map = INODE_SUBJECT_MAP.lock().await;
            map.resolve_path(policy.subject)?
        };

        let allow: ebpf_policy::Ports = policy.allow.into();
        let deny: ebpf_policy::Ports = policy.deny.into();

        self.allowed_map.insert(bin_inode, allow, 0)?;
        self.denied_map.insert(bin_inode, deny, 0)?;

        Ok(())
    }

    pub async fn list_policies(&self) -> Result<Vec<policy::SocketBind>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map.iter() {
            let (bin_inode, allow) = res?;
            let deny = self.denied_map.get(&bin_inode, 0)?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            policies.push(policy::SocketBind {
                subject,
                allow: allow.into(),
                deny: deny.into(),
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::SocketBind>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::SocketBind, alerts::SocketBind>(&mut self.perf_array).await
    }
}

pub struct SocketConnect {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map_v4: HashMap<MapData, u64, ebpf_policy::Ipv4Addrs>,
    pub(crate) denied_map_v4: HashMap<MapData, u64, ebpf_policy::Ipv4Addrs>,
    pub(crate) allowed_map_v6: HashMap<MapData, u64, ebpf_policy::Ipv6Addrs>,
    pub(crate) denied_map_v6: HashMap<MapData, u64, ebpf_policy::Ipv6Addrs>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl SocketConnect {
    pub async fn add_policy(
        &mut self,
        policy: policy::SocketConnect,
    ) -> Result<(), EbpfguardError> {
        let bin_inode = {
            let mut map = INODE_SUBJECT_MAP.lock().await;
            map.resolve_path(policy.subject)?
        };

        let (allow_v4, allow_v6) = policy.allow.into_ebpf();
        let (deny_v4, deny_v6) = policy.deny.into_ebpf();

        self.allowed_map_v4.insert(bin_inode, allow_v4, 0)?;
        self.denied_map_v4.insert(bin_inode, deny_v4, 0)?;
        self.allowed_map_v6.insert(bin_inode, allow_v6, 0)?;
        self.denied_map_v6.insert(bin_inode, deny_v6, 0)?;

        Ok(())
    }

    pub async fn list_policies(&self) -> Result<Vec<policy::SocketConnect>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map_v4.iter() {
            let (bin_inode, allow_v4) = res?;
            let deny_v4 = self.denied_map_v4.get(&bin_inode, 0)?;
            let allow_v6 = self.allowed_map_v6.get(&bin_inode, 0)?;
            let deny_v6 = self.denied_map_v6.get(&bin_inode, 0)?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            let allow = if allow_v4.all() && allow_v6.all() {
                policy::Addresses::All
            } else {
                let mut addrs = Vec::new();
                for addr in allow_v4.addrs.iter() {
                    if *addr == 0 {
                        break;
                    }
                    addrs.push(IpAddr::V4(Ipv4Addr::from(addr.to_owned())));
                }
                for addr in allow_v6.addrs.iter() {
                    if *addr == [0u8; 16] {
                        break;
                    }
                    addrs.push(IpAddr::V6(Ipv6Addr::from(addr.to_owned())));
                }
                policy::Addresses::Addresses(addrs)
            };
            let deny = if deny_v4.all() && deny_v6.all() {
                policy::Addresses::All
            } else {
                let mut addrs = Vec::new();
                for addr in deny_v4.addrs.iter() {
                    if *addr == 0 {
                        break;
                    }
                    addrs.push(IpAddr::V4(Ipv4Addr::from(addr.to_owned())));
                }
                for addr in deny_v6.addrs.iter() {
                    if *addr == [0u8; 16] {
                        break;
                    }
                    addrs.push(IpAddr::V6(Ipv6Addr::from(addr.to_owned())));
                }
                policy::Addresses::Addresses(addrs)
            };

            policies.push(policy::SocketConnect {
                subject,
                allow,
                deny,
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::SocketConnect>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::SocketConnect, alerts::SocketConnect>(&mut self.perf_array)
            .await
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
