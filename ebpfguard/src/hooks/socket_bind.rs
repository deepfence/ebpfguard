use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::lsm::LsmLink,
};
use ebpfguard_common::{alerts as ebpf_alerts, policy as ebpf_policy};

use tokio::sync::mpsc::Receiver;

use crate::{alerts, error::EbpfguardError, policy};

use super::{perf_array_alerts, INODE_SUBJECT_MAP};

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
