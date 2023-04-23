use aya::{
    maps::{AsyncPerfEventArray, HashMap, MapData},
    programs::lsm::LsmLink,
};
use ebpfguard_common::alerts as ebpf_alerts;
use tokio::sync::mpsc::Receiver;

use crate::{alerts, error::EbpfguardError, policy};

use super::{perf_array_alerts, INODE_SUBJECT_MAP};

pub struct SbMount {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) allowed_map: HashMap<MapData, u64, u8>,
    pub(crate) denied_map: HashMap<MapData, u64, u8>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl SbMount {
    pub async fn add_policy(&mut self, policy: policy::SbMount) -> Result<(), EbpfguardError> {
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

    pub async fn list_policies(&self) -> Result<Vec<policy::SbMount>, EbpfguardError> {
        let mut policies = Vec::new();

        for res in self.allowed_map.iter() {
            let (bin_inode, _) = res?;

            let subject = {
                let map = INODE_SUBJECT_MAP.lock().await;
                map.resolve_inode(bin_inode)
            };

            policies.push(policy::SbMount {
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

            policies.push(policy::SbMount {
                subject,
                allow: false,
            });
        }

        Ok(policies)
    }

    pub async fn alerts(&mut self) -> Result<Receiver<alerts::SbMount>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::SbMount, alerts::SbMount>(&mut self.perf_array).await
    }
}
